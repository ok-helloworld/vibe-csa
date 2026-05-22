#!/usr/bin/env python3
"""
Vibe CSA — 交互式浏览器登录凭证捕获 v2.1

设计原则:
  - 无任何交互式 input() 提示，完全由 CLI 参数驱动（模型可通过 Bash 工具调用）
  - 双重触发：自动检测登录信号 OR 用户在终端按 Enter
  - 自动提取 Cookie / localStorage / JWT / sessionStorage
  - 会话固定检测

用法:
  # 基础：打开浏览器，用户手动登录，自动提取
  python extract_credentials.py --url https://target.com/login --output workDir/sessions/creds.json

  # 带凭证提示：在终端打印账号密码，用户看着在浏览器里输
  python extract_credentials.py --url https://target.com/login \\
    --hint-username admin --hint-password admin123 \\
    --output workDir/sessions/creds.json

  # 连接已有 Chrome（CDP 模式）
  python extract_credentials.py --cdp-port 9222 --output workDir/sessions/creds.json
"""

import argparse
import base64
import json
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Windows GBK 终端中文乱码修复
if sys.stdout.encoding and sys.stdout.encoding.lower() in ('gbk', 'cp936', 'cp950'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("错误: playwright 未安装。请运行: pip install playwright && playwright install chromium")
    sys.exit(1)


# ── JWT 工具 ──────────────────────────────────────────────────
def decode_jwt(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None


def looks_like_jwt(value: str) -> bool:
    return bool(re.match(r'^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$', value))


# ── 登录信号检测 ──────────────────────────────────────────────
def get_login_signals(page, initial_url: str, had_password_field: bool = True) -> list:
    """
    检测登录后 DOM 变化信号（不含 URL 跳转，URL 单独作为立即触发处理）。
    返回信号列表，调用方要求 ≥2 个才视为已登录。

    设计原则：只选择登录后才会出现的元素，排除登录表单本身也有的元素。
    """
    signals = []

    # DOM 元素：仅选择登录后才出现的元素，排除 username/email input 等登录表单常见类名
    try:
        dom_signals = page.evaluate("""(hadPasswordField) => {
            const result = [];
            const indicators = [
                // 退出/注销链接（登录后才有）
                ['a[href*="logout"]',            '退出链接'],
                ['a[href*="signout"]',           '退出链接'],
                ['a[href*="sign-out"]',          '退出链接'],
                ['button[id*="logout"]',         '退出按钮'],
                ['[data-action*="logout"]',      '退出操作'],
                // 用户头像/菜单（登录后才有，排除 class*=username 因为登录表单也用）
                ['[class*="user-avatar"]',       '用户头像'],
                ['[class*="user-menu"]',         '用户菜单'],
                ['[class*="user-dropdown"]',     '用户下拉'],
                ['[class*="navbar-user"]',       '导航用户区'],
                ['[id*="userDropdown"]',         '用户下拉菜单'],
                // 仪表盘/后台主体（登录后才有）
                ['[class*="dashboard-body"]',    '仪表盘主体'],
                ['[id*="dashboard"]',            '仪表盘'],
                // 侧边栏（多数 CMS 后台登录后才渲染）
                ['[class*="sidebar-nav"]',       '侧边栏导航'],
                ['[id*="sidebar"]',              '侧边栏'],
                // data-testid 用户标识
                ['[data-testid*="user-info"]',   '用户信息区'],
            ];
            for (const [sel, label] of indicators) {
                try {
                    const el = document.querySelector(sel);
                    if (el && el.offsetParent !== null) {
                        result.push('DOM:' + label);
                    }
                } catch(e) {}
            }
            // 密码框消失：仅当登录页原本有密码框时才算信号，防止页面未渲染时误判
            if (hadPasswordField) {
                const pwdInput = document.querySelector('input[type="password"]');
                if (!pwdInput || pwdInput.offsetParent === null) {
                    result.push('DOM:密码框已消失');
                }
            }
            return result;
        }""", had_password_field)
        signals.extend([("DOM", s) for s in dom_signals])
    except Exception:
        pass

    # 4. Token / Cookie 关键字出现
    try:
        has_token = page.evaluate("""() => {
            if (/token|session|auth|jwt/i.test(document.cookie)) return 'cookie';
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    if (/token|auth|jwt|session|access/i.test(k) && localStorage.getItem(k))
                        return 'localStorage:' + k;
                }
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i);
                    if (/token|auth|jwt|session|access/i.test(k) && sessionStorage.getItem(k))
                        return 'sessionStorage:' + k;
                }
            } catch(e) {}
            return null;
        }""")
        if has_token:
            signals.append(("Token出现", has_token))
    except Exception:
        pass

    return signals


# ── 凭证提取 ──────────────────────────────────────────────────
def extract_credentials_from_page(page, cookies_before=None,
                                   verify_url=None, role_label=None) -> dict:
    credentials = {
        "role_label": role_label or "user",
        "cookies": [],
        "cookies_before": cookies_before or [],
        "tokens": [],
        "storage": {"localStorage": {}, "sessionStorage": {}},
        "jwt_analysis": [],
        "auth_cookie_string": "",
        "auth_headers": [],
        "session_fixation": None,
        "login_url": page.url,
        "capture_time": datetime.now(timezone.utc).isoformat(),
        "warnings": [],
    }

    # Cookie
    try:
        for c in page.context.cookies():
            credentials["cookies"].append({
                "name": c["name"], "value": c["value"],
                "domain": c.get("domain", ""), "path": c.get("path", "/"),
                "secure": c.get("secure", False), "httpOnly": c.get("httpOnly", False),
                "sameSite": c.get("sameSite", "None"),
            })
    except Exception as e:
        credentials["warnings"].append(f"Cookie 提取失败: {e}")

    # localStorage / sessionStorage
    try:
        storage_data = page.evaluate("""() => {
            const result = { localStorage: {}, sessionStorage: {} };
            try { for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                result.localStorage[k] = localStorage.getItem(k);
            }} catch(e) {}
            try { for (let i = 0; i < sessionStorage.length; i++) {
                const k = sessionStorage.key(i);
                result.sessionStorage[k] = sessionStorage.getItem(k);
            }} catch(e) {}
            return result;
        }""")
        credentials["storage"] = storage_data
    except Exception:
        pass

    # Token 识别
    token_keywords = [
        "token", "access_token", "refresh_token", "id_token", "jwt",
        "authorization", "bearer", "api_key", "apikey", "x-auth-token",
        "session", "session_id", "sid", "auth", "credential", "access",
    ]
    for stype in ["localStorage", "sessionStorage"]:
        for key, value in (credentials["storage"].get(stype) or {}).items():
            if any(p in key.lower() for p in token_keywords) and value:
                credentials["tokens"].append({"type": stype, "key": key, "value": value})
    for c in credentials["cookies"]:
        if any(p in c["name"].lower() for p in token_keywords):
            credentials["tokens"].append({"type": "cookie", "key": c["name"], "value": c["value"]})

    # Cookie 字符串
    credentials["auth_cookie_string"] = "; ".join(
        f'{c["name"]}={c["value"]}' for c in credentials["cookies"]
    )

    # 认证头（优先 Bearer JWT）
    bearer_token = next(
        (t["value"] for t in credentials["tokens"] if looks_like_jwt(t["value"])), None
    ) or next(
        (t["value"] for t in credentials["tokens"]
         if t["key"].lower() in ("token", "access_token", "bearer", "authorization")),
        None
    )
    if bearer_token:
        credentials["auth_headers"].append({
            "type": "header", "name": "Authorization", "value": f"Bearer {bearer_token}",
        })
    if credentials["auth_cookie_string"]:
        credentials["auth_headers"].append({
            "type": "header", "name": "Cookie", "value": credentials["auth_cookie_string"],
        })

    # 告警
    if not credentials["auth_cookie_string"] and not credentials["tokens"]:
        credentials["warnings"].append("未捕获到任何 Cookie 或 Token — 登录可能未成功")

    # JWT 解码
    seen = set()
    for t in credentials["tokens"]:
        if t["value"] in seen or not looks_like_jwt(t["value"]):
            continue
        seen.add(t["value"])
        decoded = decode_jwt(t["value"])
        if decoded:
            analysis = {"source_key": t["key"], "source_type": t["type"], "payload": decoded}
            exp_ts = decoded.get("exp")
            if exp_ts:
                try:
                    analysis["expires_at"] = datetime.fromtimestamp(
                        int(exp_ts), tz=timezone.utc
                    ).isoformat()
                    secs = int(exp_ts) - int(time.time())
                    analysis["expires_in_seconds"] = secs
                    if secs < 3600:
                        analysis["warning"] = f"Token {secs // 60} 分钟后过期"
                except Exception:
                    pass
            credentials["jwt_analysis"].append(analysis)

    # 会话固定
    if cookies_before:
        for cb in cookies_before:
            for ca in credentials["cookies"]:
                if cb["name"] == ca["name"] and cb["value"] == ca["value"]:
                    credentials["session_fixation"] = {
                        "detected": True,
                        "cookie_name": cb["name"],
                        "detail": f"登录前后 {cb['name']} 值未重新生成，存在会话固定风险",
                    }
                    credentials["warnings"].append(
                        f"会话固定风险: {cb['name']} 登录前后值相同"
                    )
                    break

    # 验证
    if verify_url:
        try:
            resp = page.goto(verify_url, wait_until="domcontentloaded", timeout=10000)
            credentials["verification"] = {
                "url": verify_url,
                "status": resp.status if resp else None,
                "success": (resp.status == 200) if resp else False,
            }
        except Exception as e:
            credentials["verification"] = {"url": verify_url, "error": str(e), "success": False}

    return credentials


# ── 主捕获流程 ────────────────────────────────────────────────
def capture_login(url: str, timeout: int, verify_url: str | None,
                  output: str | None, role_label: str,
                  hint_username: str | None, hint_password: str | None,
                  manual_confirm: bool = False) -> dict | None:
    """
    打开浏览器 → 显示凭证提示 → 等待登录（自动检测 OR 用户按 Enter）→ 提取凭证
    全程无 stdin 交互提示，可安全从模型 Bash 工具调用。
    """

    # ── 后台线程：监听用户按 Enter ────────────────────────────
    enter_event = threading.Event()

    def _wait_enter():
        try:
            line = sys.stdin.readline()
            # readline() 在真实终端按 Enter 返回 "\n"，在管道/EOF 立即返回 ""
            # 只有真实按键才触发，防止 stdin 是管道时误触发
            if line:
                enter_event.set()
        except Exception:
            pass

    enter_thread = threading.Thread(target=_wait_enter, daemon=True)
    enter_thread.start()

    credentials = None

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
            ],
        )
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()

        # 加载目标页面
        print(f"\n[*] 正在打开: {url}")
        try:
            page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                print(f"[WARN] 页面加载超时: {e}，继续等待用户操作...")

        # 若不是登录页，自动发现并跳转
        try:
            is_login = page.evaluate(
                '() => !!document.querySelector(\'input[type="password"]\')'
            )
        except Exception:
            is_login = False

        if not is_login:
            print(f"[!] 当前页面无密码框: {page.url}")
            login_kw_in_url = any(
                kw in page.url.lower()
                for kw in ["/login", "/signin", "/auth", "/logon"]
            )
            if not login_kw_in_url:
                # 尝试常见登录路径
                base = url.rstrip("/").split("?")[0]
                for path in ["/login", "/signin", "/auth/login", "/admin/login", "/user/login"]:
                    try_url = base + path
                    try:
                        resp = page.goto(try_url, wait_until="domcontentloaded", timeout=8000)
                        has_pwd = page.evaluate(
                            '() => !!document.querySelector(\'input[type="password"]\')'
                        )
                        if has_pwd:
                            print(f"[+] 自动发现登录页: {page.url}")
                            break
                    except Exception:
                        continue
                else:
                    print("[*] 未自动找到登录页，请在浏览器中手动导航到登录页")

        initial_url = page.url

        # 记录初始密码框状态：只有"之前有、现在没了"才触发该信号，防止页面未渲染完时误判
        try:
            had_password_field = page.evaluate(
                '() => !!document.querySelector(\'input[type="password"]\')'
            )
        except Exception:
            had_password_field = True  # 保守默认

        # 记录登录前 Cookie（会话固定检测用）
        try:
            cookies_before = [
                {"name": c["name"], "value": c["value"]}
                for c in context.cookies()
            ]
        except Exception:
            cookies_before = []

        # 监听 POST 登录请求（网络层触发）
        login_submitted = threading.Event()
        login_submit_url = [None]

        def on_request(request):
            if login_submitted.is_set():
                return
            auth_kw = ["/login", "/auth", "/signin", "/sign-in",
                       "/oauth/token", "/api/login", "/api/auth", "/api/token"]
            if request.method == "POST" and any(
                kw in request.url.lower() for kw in auth_kw
            ):
                login_submitted.set()
                login_submit_url[0] = request.url

        page.on("request", on_request)

        # ── 打印操作说明 ─────────────────────────────────────
        print()
        if manual_confirm:
            print("  Manual confirm mode: form submission alone will not trigger extraction.")
        print("=" * 60)
        print("  浏览器已打开，请手动完成登录")
        if hint_username or hint_password:
            print("  ─" * 30)
            if hint_username:
                print(f"  用户名: {hint_username}")
            if hint_password:
                print(f"  密  码: {hint_password}")
            print("  ─" * 30)
            print("  ↑ 请将以上账号密码输入到浏览器的登录表单中")
        print()
        print(f"  等待最长 {timeout} 秒，满足以下任一条件即自动提取凭证:")
        print(f"    1. 自动检测到登录成功（URL 跳转 / DOM 变化 / Token 出现）")
        print(f"    2. 在浏览器中完成登录后，回到此终端按 Enter 键")
        print("=" * 60)
        print()

        # ── 轮询等待 ──────────────────────────────────────────
        poll_ms = 800
        elapsed_ms = 0
        timeout_ms = timeout * 1000
        trigger_reason = "超时"

        while elapsed_ms < timeout_ms:
            page.wait_for_timeout(poll_ms)
            elapsed_ms += poll_ms

            # 优先级 1：用户按 Enter
            if enter_event.is_set():
                trigger_reason = "用户按 Enter 确认"
                page.wait_for_timeout(500)  # 短暂等待 JS 写入 storage
                break

            # 优先级 2：网络层检测到 POST 登录请求
            if login_submitted.is_set() and not manual_confirm:
                trigger_reason = f"检测到登录请求 → {login_submit_url[0]}"
                page.wait_for_timeout(2000)  # 等待 token 写入 localStorage
                break

            # 优先级 3a：URL 跳转（5秒后才检测，单独触发，无需凑信号数）
            if elapsed_ms >= 5000:
                try:
                    current_url = page.url
                    if current_url != initial_url:
                        login_kw = ["/login", "/signin", "/auth", "/sign-in", "/logon"]
                        if not any(kw in current_url.lower() for kw in login_kw):
                            trigger_reason = f"URL 跳转 → {current_url[:100]}"
                            print(f"  [+] [URL跳转] {current_url[:100]}")
                            page.wait_for_timeout(800)
                            break
                except Exception:
                    pass

            # 优先级 3b：DOM 信号（5秒后才开始，每 2 秒检测一次，需 ≥2 个）
            if elapsed_ms >= 5000 and elapsed_ms % 2000 < poll_ms:
                signals = get_login_signals(page, initial_url, had_password_field)
                if len(signals) >= 2:
                    trigger_reason = f"自动检测到 {len(signals)} 个登录信号"
                    for sig_type, sig_val in signals[:4]:
                        print(f"  [+] [{sig_type}] {sig_val}")
                    page.wait_for_timeout(800)
                    break

        print(f"\n[+] 触发提取: {trigger_reason}")
        print("[*] 正在提取凭证...")

        credentials = extract_credentials_from_page(
            page,
            cookies_before=cookies_before,
            verify_url=verify_url,
            role_label=role_label,
        )

        try:
            browser.close()
        except Exception:
            pass

    # ── 保存 & 打印摘要 ───────────────────────────────────────
    if credentials:
        _print_summary(credentials)

        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "target": url,
                    "capture_time": datetime.now(timezone.utc).isoformat(),
                    "roles": [credentials],
                }, f, indent=2, ensure_ascii=False)
            print(f"\n[+] 凭证已保存: {out_path}")

    return credentials


def _print_summary(role: dict):
    label = role.get("role_label", "user")
    print(f"\n┌─ 凭证摘要 [{label}]")
    print(f"│ Cookie 数:  {len(role['cookies'])}")
    for c in role["cookies"]:
        flags = (" [HttpOnly]" if c["httpOnly"] else "") + (" [Secure]" if c["secure"] else "")
        val = c["value"][:50] + ("..." if len(c["value"]) > 50 else "")
        print(f"│   {c['name']} = {val}{flags}")
    if role.get("tokens"):
        print(f"│ Token 数:   {len(role['tokens'])}")
        for t in role["tokens"][:3]:
            val = t["value"][:60] + ("..." if len(t["value"]) > 60 else "")
            print(f"│   [{t['type']}] {t['key']} = {val}")
    if role.get("jwt_analysis"):
        for ja in role["jwt_analysis"][:1]:
            p = ja.get("payload", {})
            user_id = p.get("sub") or p.get("user_id") or p.get("id") or "?"
            uname = p.get("username") or p.get("name") or p.get("email") or "?"
            role_val = p.get("role") or p.get("roles") or p.get("scope") or "?"
            print(f"│ JWT 解析:   sub={user_id}  username={uname}  role={role_val}")
            if ja.get("expires_at"):
                print(f"│             过期: {ja['expires_at']}")
            if ja.get("warning"):
                print(f"│ [!] {ja['warning']}")
    if role.get("auth_headers"):
        print("│ 认证头 (供 verify_vuln.py 使用):")
        for ah in role["auth_headers"]:
            val = ah["value"][:80] + ("..." if len(ah["value"]) > 80 else "")
            print(f"│   {ah['name']}: {val}")
    if role.get("session_fixation") and role["session_fixation"].get("detected"):
        print(f"│ [!] 会话固定: {role['session_fixation']['detail']}")
    for w in role.get("warnings", []):
        print(f"│ [!] {w}")
    print(f"└{'─' * 50}")


# ── CDP 模式 ──────────────────────────────────────────────────
def cdp_capture(cdp_port: int, verify_url: str | None, output: str | None):
    """连接已有 Chrome/Edge 实例，直接提取当前页面凭证"""
    print(f"[*] 连接 CDP → 127.0.0.1:{cdp_port}")
    with sync_playwright() as p:
        try:
            browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{cdp_port}")
        except Exception as e:
            print(f"[ERROR] 无法连接 CDP: {e}", file=sys.stderr)
            print(
                f"[INFO] 请用 --remote-debugging-port={cdp_port} 启动 Chrome",
                file=sys.stderr,
            )
            sys.exit(1)

        contexts = browser.contexts
        if not contexts:
            print("[ERROR] 没有找到浏览器上下文", file=sys.stderr)
            sys.exit(1)

        page = contexts[0].pages[-1] if contexts[0].pages else None
        if not page:
            print("[ERROR] 没有打开的页面", file=sys.stderr)
            sys.exit(1)

        print(f"[+] 当前页面: {page.url}")
        print("[*] 提取凭证...")

        try:
            cookies_before = [
                {"name": c["name"], "value": c["value"]}
                for c in contexts[0].cookies()
            ]
        except Exception:
            cookies_before = []

        credentials = extract_credentials_from_page(
            page, cookies_before=cookies_before,
            verify_url=verify_url, role_label="cdp_capture",
        )
        browser.close()

    _print_summary(credentials)

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({
                "capture_time": datetime.now(timezone.utc).isoformat(),
                "roles": [credentials],
            }, f, indent=2, ensure_ascii=False)
        print(f"[+] 凭证已保存: {out_path}")

    return credentials


# ── CLI ───────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Vibe CSA — 交互式浏览器登录凭证捕获",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 打开浏览器，用户手动登录
  python extract_credentials.py --url https://target.com/login --output workDir/sessions/creds.json

  # 带账号密码提示（显示在终端，用户在浏览器中输入）
  python extract_credentials.py --url https://target.com/login \\
    --hint-username admin --hint-password admin123 \\
    --output workDir/sessions/creds.json

  # 连接已有 Chrome
  python extract_credentials.py --cdp-port 9222 --output workDir/sessions/creds.json
        """,
    )
    parser.add_argument("--url", help="登录页面 URL")
    parser.add_argument("--timeout", type=int, default=180,
                        help="等待登录的超时秒数（默认 180）")
    parser.add_argument("--hint-username", metavar="USER",
                        help="在终端打印的用户名提示（用户手动输入到浏览器）")
    parser.add_argument("--hint-password", metavar="PASS",
                        help="在终端打印的密码提示（用户手动输入到浏览器）")
    parser.add_argument("--role-label", default="user",
                        help="角色标签（用于输出区分，默认 user）")
    parser.add_argument("--verify-url", help="登录后验证凭证的 URL")
    parser.add_argument("--output", "-o", default="workDir/sessions/creds.json", help="凭证输出路径（JSON 格式）")
    parser.add_argument("--manual-confirm", action="store_true",
                        help="Wait for Enter or strong login-success signals; do not extract on form submission")
    parser.add_argument("--cdp-port", type=int,
                        help="CDP 调试端口（连接已有 Chrome/Edge）")
    # 保留向后兼容，不再使用
    parser.add_argument("--roles", type=int, default=1, help=argparse.SUPPRESS)
    parser.add_argument("--hint-username-list", action="append", help=argparse.SUPPRESS)
    parser.add_argument("--hint-password-list", action="append", help=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    if args.cdp_port:
        cdp_capture(args.cdp_port, args.verify_url, args.output)
    elif args.url:
        capture_login(
            url=args.url,
            timeout=args.timeout,
            verify_url=args.verify_url,
            output=args.output,
            role_label=args.role_label,
            hint_username=args.hint_username,
            hint_password=args.hint_password,
            manual_confirm=args.manual_confirm,
        )
    else:
        parser.error("需要指定 --url 或 --cdp-port")


if __name__ == "__main__":
    main()
