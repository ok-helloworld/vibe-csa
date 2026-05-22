#!/usr/bin/env python3
"""Prepare browser-captured credentials for vibe-csa dynamic verification.

This is a thin, standard wrapper around extract_credentials.py. It never sends
the username/password itself; it passes them as terminal hints so the user can
manually enter them in the browser opened by extract_credentials.py.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import urllib.parse
from pathlib import Path

try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


DEFAULT_OUTPUT = Path("workDir") / "sessions" / "creds.json"


def build_login_url(target: str, login_path: str) -> str:
    base = target.rstrip("/") + "/"
    path = login_path.lstrip("/")
    return urllib.parse.urljoin(base, path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture browser login credentials for vibe-csa dynamic verification",
    )
    parser.add_argument("--target", help="Target base URL, used with --login-path")
    parser.add_argument("--login-url", help="Exact login page URL")
    parser.add_argument("--login-path", default="admin/login",
                        help="Login path relative to --target when --login-url is omitted")
    parser.add_argument("--username", help="Username hint printed for manual browser login")
    parser.add_argument("--password", help="Password hint printed for manual browser login")
    parser.add_argument("--role", default="user", help="Role label stored in creds.json")
    parser.add_argument("--verify-url", help="URL used by extract_credentials.py to verify session reuse")
    parser.add_argument("--output", "-o", default=str(DEFAULT_OUTPUT), help="Credential JSON output path")
    parser.add_argument("--timeout", type=int, default=180, help="Login wait timeout in seconds")
    parser.add_argument("--cdp-port", type=int, help="Attach to an existing Chrome/Edge CDP port")
    parser.add_argument("--manual-confirm", action="store_true",
                        help="Do not extract on login form submission; wait for Enter or strong success signals")
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    script = Path(__file__).resolve().parent / "extract_credentials.py"
    cmd = [sys.executable, str(script), "--output", str(output)]

    if args.cdp_port:
        cmd.extend(["--cdp-port", str(args.cdp_port)])
    else:
        login_url = args.login_url
        if not login_url:
            if not args.target:
                parser.error("--target or --login-url is required unless --cdp-port is used")
            login_url = build_login_url(args.target, args.login_path)
        cmd.extend(["--url", login_url, "--timeout", str(args.timeout), "--role-label", args.role])

    if args.username:
        cmd.extend(["--hint-username", args.username])
    if args.password:
        cmd.extend(["--hint-password", args.password])
    if args.verify_url:
        cmd.extend(["--verify-url", args.verify_url])
    if args.manual_confirm:
        cmd.append("--manual-confirm")

    print("[auth] launching browser credential capture")
    print(f"[auth] output: {output}")
    raise SystemExit(subprocess.call(cmd))


if __name__ == "__main__":
    main()
