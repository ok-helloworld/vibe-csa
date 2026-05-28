#!/usr/bin/env python3
"""Verify vibe-csa-{timestamp}.json findings against a live target.

Core capabilities (P0 rewrite):
  1. Cross-step state passing via `extract` + `${steps.N.var}` template
  2. Session-based cookie auto-propagation
  3. Retry-on-transient-error (Timeout / ConnectionError) with backoff;
     distinguished from validation failures
  4. Differentiated exit codes (0/1/2/3/4)
  5. multipart/form-data and binary upload support
  6. Manual redirect chain logging
  7. Response truncation marker (body_truncated, body_full_length)
  8. Auto-fill step number; auto-generate failure_log entries on failure
  9. --dry-run actually previews requests instead of sending
 10. --credentials sessions/creds.json auto-loads cookies/headers

Usage:
    python verify_vuln.py vibe-csa-draft.json \
      --target https://target.com \
      [--finding FINDING-001] \
      [--max-retries 5] \
      [--retry-on-error 2] \
      [--credentials sessions/creds.json] \
      [--timeout 10] \
      [--dry-run] \
      [--verbose]

Exit codes:
    0 = success: at least one finding reached a terminal poc.result
    1 = parameter / IO error (do not retry)
    2 = transient network errors exhausted retries (retry later)
    3 = target unreachable for all findings
    4 = partial: some findings updated, others still pending more steps

Cross-step state passing
========================
A `request` may declare `extract` to capture values from its response. Later
steps reference those values with `${steps.<idx>.<varname>}`.

Extraction expressions (right-hand side of `extract`):
    $.path.to.field      JSONPath-lite (dot path into JSON body)
    header:Name          response header by name (case-insensitive)
    cookie:Name          Set-Cookie value by name
    regex:<pattern>      first capture group from response.body
    status               literal HTTP status code (integer)

Template substitution
=====================
`${steps.N.var}` placeholders inside any string in request.url / params /
headers / cookies / body are replaced before sending. `${steps.N.cookies.X}`
references cookies *received* in step N's response (not request).

multipart/form-data
===================
Set request.body to: {"_type":"multipart","fields":{...},"files":[
  {"name":"upload","filename":"a.jpg","content":"base64:...","content_type":"image/jpeg"}
]}  — `content` may also be plain text.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
import urllib.parse

# Ensure UTF-8 output on Windows cp936 terminals
try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from pathlib import Path
from typing import Any

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    print("Missing dependency: pip install requests", file=sys.stderr)
    sys.exit(1)

# Silence noisy InsecureRequestWarning from urllib3 when verify=False
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _utf8 import configure_utf8_runtime, find_text_quality_issues  # noqa: E402

configure_utf8_runtime()

DEFAULT_TIMEOUT = 10
DEFAULT_MAX_RETRIES = 5
DEFAULT_RETRY_ON_ERROR = 2
MAX_REDIRECTS = 10
BODY_TRUNCATE_LEN = 4096
BODY_EVIDENCE_WINDOW = 1200
BODY_HEAD_TAIL_LEN = 1500
PLACEHOLDER_PATTERN = re.compile(r"\$\{([^}]+)\}")
POC_SKELETON_EVIDENCE = "PoC 骨架已初始化，尚未写入运行时证据。"

# ─── 实质性证据签名库（与 references/exploit-success-signatures.md 对齐） ───────
# 每个签名条目：(regex_str, strength, flags). strength ∈ {"L2","L3"}.
SIGNATURE_LIBRARY: dict[str, list[tuple[str, str, int]]] = {
    "traversal-linux": [
        (r"^root:[x*!]:0:0:", "L3", re.MULTILINE),
        (r"^daemon:[x*!]:\d+:\d+:", "L3", re.MULTILINE),
        (r"^(root|nobody|bin|daemon):.*:/(bin/(bash|sh|nologin)|sbin/nologin|usr/sbin/nologin)\s*$", "L3", re.MULTILINE),
        (r"^root:\$[1-6y]\$[A-Za-z0-9./$]+:", "L3", re.MULTILINE),
        (r"^127\.0\.0\.1\s+localhost", "L2", re.MULTILINE),
        (r"Linux version \d+\.\d+\.\d+", "L3", 0),
        (r"-----BEGIN (OPENSSH |RSA |DSA |EC )?PRIVATE KEY-----", "L3", 0),
        (r"sshd\[\d+\]:|pam_unix\(", "L2", 0),
    ],
    "traversal-windows": [
        (r"\[fonts\][\s\S]{0,500}\[extensions\]", "L3", re.IGNORECASE),
        (r"\[boot loader\][\s\S]{0,500}multi\(0\)disk\(0\)rdisk\(0\)", "L3", re.IGNORECASE),
        (r"\[386Enh\]|\[drivers\]", "L3", re.IGNORECASE),
        (r"^127\.0\.0\.1\s+localhost", "L2", re.MULTILINE),
        (r"<configuration>[\s\S]{0,2000}<system\.webServer>", "L2", re.IGNORECASE),
    ],
    "cmd-exec": [
        (r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)", "L3", 0),
        (r"groups=\d+\([^)]+\)(,\d+\([^)]+\))*", "L3", 0),
        (r"^(root|www-data|nginx|apache|tomcat|mysql|nobody|ubuntu|admin)\s*$", "L2", re.MULTILINE),
        (r"Linux \S+ \d+\.\d+\.\d+.+ (GNU/Linux|x86_64|aarch64)", "L3", 0),
        (r"(nt authority\\|^[a-z0-9_\-]+\\)\S+", "L3", re.IGNORECASE | re.MULTILINE),
        (r"Windows IP Configuration|IPv4 Address[. ]+:", "L3", 0),
        (r"Host Name:\s+\S+[\s\S]{0,200}OS Name:\s+Microsoft Windows", "L3", 0),
        (r"Volume in drive \w is|Directory of \S", "L3", 0),
    ],
    "upload-marker": [
        # Generic VIBECSA marker. Per-finding x_unique_marker is added dynamically.
        (r"VIBECSA[_-][0-9a-fA-F]{6,32}", "L3", 0),
    ],
    "sqli": [
        (r"SQL syntax.+MySQL|MySQLSyntaxErrorException|mysqli?_query\(\)", "L3", re.IGNORECASE),
        (r"You have an error in your SQL syntax", "L3", re.IGNORECASE),
        (r"\b\d+\.\d+\.\d+-(log|MariaDB)\b", "L3", 0),
        (r"Microsoft OLE DB|SqlException|System\.Data\.SqlClient", "L3", re.IGNORECASE),
        (r"PostgreSQL.+ERROR|psycopg2\.errors|PG::SyntaxError", "L3", re.IGNORECASE),
        (r"\bORA-\d{5}\b", "L3", 0),
        (r"SQLite3::SQLException|sqlite3\.OperationalError", "L3", re.IGNORECASE),
    ],
    "ssrf": [
        (r'"AccessKeyId"|"SecretAccessKey"|"Token":"|169\.254\.169\.254', "L3", re.IGNORECASE),
        (r"Metadata-Flavor:\s*Google", "L3", 0),
        (r"^SSH-[12]\.\d+-", "L3", re.MULTILINE),
        (r"\+PONG\b|redis_version:", "L3", 0),
        (r"meta-data/[\w/\-]+", "L3", re.IGNORECASE),
    ],
    "ssti": [
        (r"(?<![\d])343(?![\d])", "L2", 0),   # 7*7*7
        (r"(?<![\d])2401(?![\d])", "L2", 0),  # 49*49
        (r"posix\.uname_result|<class 'jinja2\.runtime\.\w+'>|<module 'os'", "L3", 0),
    ],
    "xxe": [
        (r"java\.io\.FileNotFoundException|XMLStreamException.*DOCTYPE", "L2", re.IGNORECASE),
        (r"simplexml_load_string|libxml_disable_entity_loader", "L2", re.IGNORECASE),
        # XXE often pulls /etc/passwd or win.ini → caller should also attach traversal-* types
    ],
    "deser": [
        (r"java\.io\.(NotSerializableException|InvalidClassException)", "L2", 0),
        (r"org\.apache\.commons\.collections\.(functors|map)\.", "L3", 0),
        (r"CommonsCollections[0-9]+|JdbcRowSetImpl", "L3", re.IGNORECASE),
        (r"pickle\.\w*Error|\b_pickle\.\w*Error", "L2", 0),
        (r"PHP (Notice|Warning).*unserialize\(\)", "L2", 0),
    ],
    "xss-stored": [
        # Requires x_unique_marker; matcher is built dynamically below.
    ],
    "idor": [
        # Requires x_idor_other_user_marker; built dynamically below.
    ],
}

# Signatures considered too weak/generic — refuse to use as evidence.
WEAK_PATTERN_BLACKLIST = (r"^\.\+$", r"^\.\*$", r"^\\w\+$", r"^\\w\*$", r"^.$", r"^\\S+$")
PROOF_TYPE_BY_SIGNATURE = {
    "cmd-exec": "command_output",
    "upload-marker": "file_access",
    "file-delete-effect": "business_state_change",
    "idor": "business_state_change",
    "ssrf": "sensitive_data",
    "sqli": "sensitive_data",
    "traversal-linux": "sensitive_data",
    "traversal-windows": "sensitive_data",
    "xss-stored": "http_signal",
}


# ─── 状态容器 ────────────────────────────────────────────────────────────────

class FindingState:
    """Holds extracted variables and the requests.Session for one finding."""

    def __init__(self) -> None:
        self.steps: dict[int, dict[str, Any]] = {}   # step_index → {var: value}
        self.cookies: dict[int, dict[str, str]] = {} # step_index → set-cookie names→values
        self.session = requests.Session()
        self.session.trust_env = False
        # Don't auto-follow; we manage redirects manually for chain logging
        self.session.max_redirects = 0


# ─── 模板替换 & 提取 ─────────────────────────────────────────────────────────

def _resolve_var(state: FindingState, expr: str) -> str:
    """Resolve a single placeholder body like 'steps.0.token' or 'steps.0.cookies.session'."""
    parts = expr.strip().split(".")
    if len(parts) < 3 or parts[0] != "steps":
        return "${" + expr + "}"
    try:
        idx = int(parts[1])
    except ValueError:
        return "${" + expr + "}"

    field = parts[2]
    if field == "cookies" and len(parts) >= 4:
        cookie_name = parts[3]
        return state.cookies.get(idx, {}).get(cookie_name, "")
    # state vars (from extract)
    val = state.steps.get(idx, {}).get(field)
    if val is None:
        return "${" + expr + "}"
    if isinstance(val, (dict, list)):
        return json.dumps(val, ensure_ascii=False)
    return str(val)


def substitute(obj: Any, state: FindingState) -> Any:
    """Recursively substitute ${steps.N.var} placeholders in any value."""
    if isinstance(obj, str):
        return PLACEHOLDER_PATTERN.sub(lambda m: _resolve_var(state, m.group(1)), obj)
    if isinstance(obj, list):
        return [substitute(x, state) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute(v, state) for k, v in obj.items()}
    return obj


def _jsonpath_lite(obj: Any, path: str) -> Any:
    """Resolve a simple '$.a.b[0].c' style path. Returns None if missing."""
    if not path.startswith("$"):
        return None
    cur: Any = obj
    # split tokens like 'a', 'b[0]', 'c'
    for tok in re.findall(r"[^.\[\]]+|\[\d+\]", path[1:]):
        if tok.startswith("[") and tok.endswith("]"):
            try:
                idx = int(tok[1:-1])
            except ValueError:
                return None
            if isinstance(cur, list) and 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        else:
            if isinstance(cur, dict):
                cur = cur.get(tok)
            else:
                return None
        if cur is None:
            return None
    return cur


def extract_from_response(rules: dict[str, str], resp_data: dict[str, Any]) -> dict[str, Any]:
    """Apply extract rules to a response dict ({status, headers, body, ...})."""
    out: dict[str, Any] = {}
    body_text = resp_data.get("body", "")
    headers = {k.lower(): v for k, v in (resp_data.get("headers") or {}).items()}

    parsed_json: Any = None
    try:
        parsed_json = json.loads(body_text) if body_text else None
    except (json.JSONDecodeError, TypeError):
        parsed_json = None

    for var, expr in rules.items():
        if not isinstance(expr, str):
            continue
        if expr.startswith("$."):
            out[var] = _jsonpath_lite(parsed_json, expr) if parsed_json is not None else None
        elif expr.lower().startswith("header:"):
            name = expr.split(":", 1)[1].strip().lower()
            out[var] = headers.get(name)
        elif expr.lower().startswith("cookie:"):
            # cookies extracted separately into state.cookies; lookup here for convenience
            name = expr.split(":", 1)[1].strip()
            for c_hdr in (resp_data.get("headers") or {}).get("Set-Cookie", "").split(","):
                m = re.match(rf"\s*{re.escape(name)}=([^;]+)", c_hdr)
                if m:
                    out[var] = m.group(1)
                    break
            out.setdefault(var, None)
        elif expr.lower().startswith("regex:"):
            pattern = expr.split(":", 1)[1]
            try:
                m = re.search(pattern, body_text)
                out[var] = m.group(1) if m and m.groups() else (m.group(0) if m else None)
            except re.error:
                out[var] = None
        elif expr == "status":
            out[var] = resp_data.get("status")
        else:
            out[var] = None
    return out


# ─── 请求构造 ────────────────────────────────────────────────────────────────

def _build_multipart(body: dict, headers: dict) -> tuple[bytes, str]:
    """Build a multipart/form-data body. Returns (bytes, content_type)."""
    import secrets
    boundary = f"----vibecsa{secrets.token_hex(8)}"
    parts: list[bytes] = []
    fields = body.get("fields", {}) or {}
    for name, val in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        parts.append((str(val) + "\r\n").encode("utf-8"))
    for f in body.get("files", []) or []:
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            f'Content-Disposition: form-data; name="{f["name"]}"; '
            f'filename="{f["filename"]}"\r\n'.encode()
        )
        ct = f.get("content_type", "application/octet-stream")
        parts.append(f"Content-Type: {ct}\r\n\r\n".encode())
        content = f.get("content", "")
        if isinstance(content, str) and content.startswith("base64:"):
            try:
                raw = base64.b64decode(content[7:])
            except Exception:
                raw = content[7:].encode("utf-8")
        else:
            raw = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        parts.append(raw)
        parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def build_request(step: dict, target: str, state: FindingState) -> requests.PreparedRequest:
    """Substitute placeholders and build a PreparedRequest."""
    req = substitute(step["request"], state)
    method = (req.get("method") or "GET").upper()
    url = req["url"]
    if url.startswith("/"):
        url = target.rstrip("/") + url

    headers = dict(req.get("headers") or {})
    params = req.get("params") or {}
    body = req.get("body", None)
    cookies = req.get("cookies") or {}

    # cookies → Cookie header (combined with session jar)
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        existing = headers.get("Cookie", "")
        headers["Cookie"] = f"{existing}; {cookie_str}".strip("; ") if existing else cookie_str

    # Serialize body
    data_body: Any = None
    if body is not None:
        if isinstance(body, dict) and body.get("_type") == "multipart":
            data_body, ct = _build_multipart(body, headers)
            headers.setdefault("Content-Type", ct)
        elif isinstance(body, dict):
            data_body = json.dumps(body, ensure_ascii=False)
            headers.setdefault("Content-Type", "application/json")
        else:
            data_body = str(body)

    prepared = state.session.prepare_request(requests.Request(
        method=method,
        url=url,
        headers=headers if headers else None,
        params=params if params else None,
        data=data_body,
    ))
    return prepared


def prepared_request_raw(prepared: requests.PreparedRequest) -> str:
    """Serialize a PreparedRequest as an HTTP/1.1 request block for evidence."""
    parsed = urllib.parse.urlsplit(prepared.url or "")
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    lines = [f"{prepared.method} {path} HTTP/1.1"]
    host = parsed.netloc
    headers = dict(prepared.headers or {})
    if host and not any(k.lower() == "host" for k in headers):
        lines.append(f"Host: {host}")
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    body = prepared.body
    if body is None:
        return "\r\n".join(lines) + "\r\n\r\n"
    if isinstance(body, bytes):
        try:
            body_text = body.decode("utf-8", errors="replace")
        except Exception:
            body_text = "<binary body>"
    else:
        body_text = str(body)
    return "\r\n".join(lines) + "\r\n\r\n" + body_text


def response_raw(resp: requests.Response, body: str) -> str:
    """Serialize a response as an HTTP/1.1 response block for evidence."""
    reason = getattr(resp, "reason", "") or ""
    lines = [f"HTTP/1.1 {resp.status_code} {reason}".rstrip()]
    for key, value in (resp.headers or {}).items():
        lines.append(f"{key}: {value}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def body_excerpt(full_text: str, hits: list[dict[str, Any]],
                 marker: str | None = None) -> tuple[str, dict[str, Any]]:
    """Return a compact body excerpt while preserving evidence context."""
    full_len = len(full_text)
    if full_len <= BODY_TRUNCATE_LEN:
        return full_text, {"strategy": "full", "ranges": [{"start": 0, "end": full_len, "reason": "full_body"}]}

    ranges: list[dict[str, Any]] = []
    for hit in hits:
        offset = hit.get("offset")
        if isinstance(offset, int) and offset >= 0:
            start = max(0, offset - BODY_EVIDENCE_WINDOW)
            end = min(full_len, offset + len(str(hit.get("snippet") or "")) + BODY_EVIDENCE_WINDOW)
            ranges.append({"start": start, "end": end, "reason": f"signature:{hit.get('type') or 'evidence'}"})

    if not ranges and marker:
        pos = full_text.find(marker)
        if pos >= 0:
            ranges.append({
                "start": max(0, pos - BODY_EVIDENCE_WINDOW),
                "end": min(full_len, pos + len(marker) + BODY_EVIDENCE_WINDOW),
                "reason": "unique_marker",
            })

    if ranges:
        ranges = sorted(ranges, key=lambda item: item["start"])
        merged: list[dict[str, Any]] = []
        for item in ranges:
            if merged and item["start"] <= merged[-1]["end"]:
                merged[-1]["end"] = max(merged[-1]["end"], item["end"])
                merged[-1]["reason"] += f",{item['reason']}"
            else:
                merged.append(dict(item))
        parts = []
        for item in merged:
            parts.append(
                f"[excerpt {item['start']}:{item['end']} reason={item['reason']}]\n"
                + full_text[item["start"]:item["end"]]
            )
        return "\n...[vibe-csa body excerpt break]...\n".join(parts), {
            "strategy": "evidence_window",
            "ranges": merged,
        }

    head = full_text[:BODY_HEAD_TAIL_LEN]
    tail = full_text[-BODY_HEAD_TAIL_LEN:]
    omitted = full_len - len(head) - len(tail)
    body = f"{head}\n...[vibe-csa truncated {omitted} chars]...\n{tail}"
    return body, {
        "strategy": "head_tail",
        "ranges": [
            {"start": 0, "end": len(head), "reason": "head"},
            {"start": full_len - len(tail), "end": full_len, "reason": "tail"},
        ],
        "omitted_bytes": omitted,
    }


# ─── 发送 & 响应处理 ─────────────────────────────────────────────────────────

def send_with_redirects(prepared: requests.PreparedRequest, state: FindingState,
                        timeout: int) -> tuple[requests.Response, list[dict]]:
    """Send request manually following redirects, recording each hop."""
    redirect_chain: list[dict] = []
    cur = prepared
    for _ in range(MAX_REDIRECTS):
        resp = state.session.send(cur, timeout=timeout, allow_redirects=False, verify=False)
        # Always log this hop's URL and status
        if 300 <= resp.status_code < 400 and "Location" in resp.headers:
            redirect_chain.append({"url": cur.url, "status": resp.status_code})
            location = resp.headers["Location"]
            next_url = urllib.parse.urljoin(cur.url, location)
            # build next request, drop body on 301/302/303
            next_method = "GET" if resp.status_code in (301, 302, 303) else cur.method
            cur = state.session.prepare_request(requests.Request(
                method=next_method, url=next_url,
            ))
            continue
        return resp, redirect_chain
    return resp, redirect_chain


def capture_cookies(resp: requests.Response) -> dict[str, str]:
    """Pull Set-Cookie values from the response into a name→value dict."""
    out: dict[str, str] = {}
    for c in resp.cookies:
        out[c.name] = c.value
    # Also parse raw Set-Cookie headers in case requests didn't store
    raw = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
    for line in raw:
        m = re.match(r"\s*([^=]+)=([^;]*)", line)
        if m:
            out.setdefault(m.group(1), m.group(2))
    return out


def response_to_dict(resp: requests.Response, redirect_chain: list[dict],
                     elapsed: float, finding: dict | None = None) -> dict[str, Any]:
    """Build the response dict to write into poc.steps[].response."""
    full_text = resp.text or ""
    full_len = len(full_text)
    hits = match_signatures(full_text, finding or {})
    body, excerpt_meta = body_excerpt(full_text, hits, (finding or {}).get("x_unique_marker"))
    truncated = full_len > len(body)

    out: dict[str, Any] = {
        "status": resp.status_code,
        "headers": dict(resp.headers),
        "raw": response_raw(resp, body),
        "body": body,
        "_meta": {"elapsed_ms": round(elapsed * 1000, 1)},
    }
    if hits:
        out["_evidence_match"] = hits
        max_strength = "L3" if any(h["strength"] == "L3" for h in hits) else "L2"
        out.setdefault("_meta", {})["evidence_strength"] = max_strength
    if truncated:
        out["body_truncated"] = True
        out["body_full_length"] = full_len
        out["body_excerpt_strategy"] = excerpt_meta.get("strategy")
        out["body_excerpt_ranges"] = excerpt_meta.get("ranges", [])
        if excerpt_meta.get("omitted_bytes") is not None:
            out["body_omitted_bytes"] = excerpt_meta["omitted_bytes"]
    if redirect_chain:
        out["redirect_chain"] = redirect_chain
    return out


# ─── 签名匹配（实质性证据自动判定） ──────────────────────────────────────────

def _is_weak_pattern(pattern: str) -> bool:
    """Reject overly-permissive patterns that would match anything."""
    if not pattern or len(pattern) < 4:
        return True
    for weak in WEAK_PATTERN_BLACKLIST:
        if re.fullmatch(weak, pattern):
            return True
    return False


def match_signatures(body: str, finding: dict) -> list[dict[str, Any]]:
    """Run signature regexes from SIGNATURE_LIBRARY (+ per-finding markers/customs).

    Returns a list of hits: [{type, pattern, strength, snippet}, ...]
    """
    if not body:
        return []

    hits: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()

    sig_types = finding.get("x_signature_type") or []
    if isinstance(sig_types, str):
        sig_types = [sig_types]
    unique_marker = finding.get("x_unique_marker")
    idor_marker = finding.get("x_idor_other_user_marker")

    # Build the effective rule list
    effective: list[tuple[str, str, str, int]] = []  # (type, pattern, strength, flags)
    for t in sig_types:
        rules = SIGNATURE_LIBRARY.get(t, [])
        for pat, strength, flags in rules:
            effective.append((t, pat, strength, flags))
        # Dynamic per-finding rules
        if t == "upload-marker" and unique_marker:
            escaped = re.escape(unique_marker)
            effective.append(("upload-marker", escaped, "L3", 0))
        if t == "xss-stored" and unique_marker:
            esc = re.escape(unique_marker)
            effective.append(("xss-stored", rf"<script[^>]*>[^<]*{esc}", "L3", 0))
            effective.append(("xss-stored", rf'on\w+=["\']?[^"\'>]*{esc}', "L3", re.IGNORECASE))
            effective.append(("xss-stored", rf'javascript:[^"\'>]*{esc}', "L3", re.IGNORECASE))
        if t == "idor" and idor_marker:
            effective.append(("idor", re.escape(idor_marker), "L3", 0))

    # Custom signatures (user-defined)
    for custom in finding.get("x_custom_signatures") or []:
        if not isinstance(custom, dict):
            continue
        ctype = custom.get("type") or "custom"
        cpat = custom.get("pattern")
        cstrength = custom.get("strength") or "L2"
        if not cpat or _is_weak_pattern(cpat):
            continue
        cflags = re.IGNORECASE if custom.get("ignore_case") else 0
        effective.append((ctype, cpat, cstrength, cflags))

    for sig_type, pat, strength, flags in effective:
        try:
            m = re.search(pat, body, flags)
        except re.error:
            continue
        if not m:
            continue
        key = (sig_type, pat)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        snippet = m.group(0)
        if len(snippet) > 200:
            snippet = snippet[:200] + "..."
        hits.append({
            "type": sig_type,
            "pattern": pat,
            "strength": strength,
            "snippet": snippet,
            "offset": m.start(),
        })

    return hits


def attach_evidence_match(resp_dict: dict[str, Any], finding: dict) -> None:
    """Mutate response dict to add _evidence_match if signatures hit."""
    hits = match_signatures(resp_dict.get("body", ""), finding)
    if hits:
        resp_dict["_evidence_match"] = hits
        # Also expose max strength on the response for quick inspection
        max_strength = "L3" if any(h["strength"] == "L3" for h in hits) else "L2"
        resp_dict.setdefault("_meta", {})["evidence_strength"] = max_strength


# ─── 凭证 & 步骤定位 ─────────────────────────────────────────────────────────
def collect_runtime_snippets(finding: dict) -> list[dict[str, Any]]:
    snippets: list[dict[str, Any]] = []
    poc = finding.get("poc") or {}
    for index, step in enumerate(poc.get("steps") or [], start=1):
        resp = step.get("response") or {}
        step_no = step.get("step") or index
        for hit in resp.get("_evidence_match") or []:
            if not isinstance(hit, dict):
                continue
            snippet = str(hit.get("snippet") or "")
            if not snippet:
                continue
            snippets.append({
                "step": step_no,
                "source": "response._evidence_match",
                "response_field": "response.body",
                "snippet": snippet,
                "signature_type": hit.get("type", ""),
                "strength": hit.get("strength", "L2"),
            })
    return snippets


def proof_type_from_snippets(snippets: list[dict[str, Any]]) -> str:
    types = {s.get("signature_type") for s in snippets}
    for sig_type, proof_type in PROOF_TYPE_BY_SIGNATURE.items():
        if sig_type in types:
            return proof_type
    return "http_signal" if snippets else "none"


def build_poc_evidence(snippets: list[dict[str, Any]]) -> str:
    if not snippets:
        return ""
    proof_type = proof_type_from_snippets(snippets)
    parts: list[str] = []
    for item in snippets[:6]:
        sig_type = item.get("signature_type") or "runtime-evidence"
        snippet = str(item.get("snippet") or "").replace("\r", "\\r").replace("\n", "\\n")
        parts.append(
            f"step {item.get('step')} response.body 命中 {sig_type}: "
            f"\"{snippet}\", proof_type={proof_type}"
        )
    if len(snippets) > 6:
        parts.append(f"additional response._evidence_match hits: {len(snippets) - 6}")
    return "；".join(parts)


def evidence_references_runtime_hits(evidence: str, snippets: list[dict[str, Any]]) -> bool:
    if not evidence:
        return False
    if "response.body" not in evidence and "response._evidence_match" not in evidence:
        return False
    return any(str(s.get("snippet") or "")[:30] in evidence for s in snippets if s.get("snippet"))


def normalize_cleanup_metadata(finding: dict) -> None:
    artifacts = finding.get("x_created_artifacts")
    if not artifacts:
        return
    if not isinstance(artifacts, list):
        finding["x_created_artifacts"] = [{
            "artifact_id": "artifact-1",
            "type": "unknown",
            "location": str(artifacts),
            "created_by_step": None,
            "status": "unknown",
        }]
        artifacts = finding["x_created_artifacts"]

    plan = finding.setdefault("x_cleanup_plan", [])
    if not isinstance(plan, list):
        finding["x_cleanup_plan"] = []
        plan = finding["x_cleanup_plan"]

    planned_ids = {
        item.get("artifact_id")
        for item in plan
        if isinstance(item, dict) and item.get("artifact_id")
    }
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            continue
        artifact_id = artifact.setdefault("artifact_id", f"artifact-{index}")
        artifact.setdefault("status", "created")
        if artifact_id in planned_ids:
            continue
        plan.append({
            "artifact_id": artifact_id,
            "action": "manual_cleanup_required",
            "target": artifact.get("location") or artifact.get("url") or "",
            "status": "pending",
            "safety_note": "Verify this artifact belongs to the current PoC before cleanup.",
        })

    result = finding.setdefault("x_cleanup_result", {})
    if isinstance(result, dict):
        result.setdefault("state", "not_started")
        result.setdefault("items", [])
        result.setdefault("notes", "verify_vuln.py tracks cleanup metadata but does not delete artifacts automatically.")


def normalize_runtime_evidence(finding: dict) -> None:
    poc = finding.setdefault("poc", {})
    snippets = collect_runtime_snippets(finding)
    if snippets:
        max_strength = "L3" if any(s.get("strength") == "L3" for s in snippets) else "L2"
        finding["evidence_level"] = max_strength
        if poc.get("result") == "success" and not evidence_references_runtime_hits(poc.get("evidence", ""), snippets):
            poc["evidence"] = build_poc_evidence(snippets)
        dynamic = finding.setdefault("dynamic_verification", {})
        dynamic["final_evidence"] = {
            "proof_type": proof_type_from_snippets(snippets),
            "summary": poc.get("evidence", ""),
            "snippets": snippets,
        }
    normalize_cleanup_metadata(finding)


def normalize_pending_skeleton_result(finding: dict) -> None:
    """Keep merge output pending when the PoC still only has the initialized skeleton."""
    poc = finding.get("poc")
    if not isinstance(poc, dict):
        return
    if poc.get("evidence") == POC_SKELETON_EVIDENCE:
        poc["result"] = "pending"
        finding["status"] = "HYPOTHESIS"


def load_credentials(path: Path, role: str | None = None) -> dict[str, Any]:
    """Load extract_credentials.py output and return a dict with cookies/headers."""
    if not path.exists():
        return {}
    try:
        creds = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    roles = creds.get("roles") or []
    if not roles:
        return {}
    chosen = roles[0]
    if role:
        for r in roles:
            if r.get("role") == role or r.get("role_label") == role:
                chosen = r
                break
    out: dict[str, Any] = {"cookies": {}, "headers": {}}
    for c in chosen.get("cookies") or []:
        if isinstance(c, dict) and "name" in c and "value" in c:
            out["cookies"][c["name"]] = c["value"]
        elif isinstance(c, (list, tuple)) and len(c) >= 2:
            out["cookies"][c[0]] = c[1]
    # Tokens become Authorization header if marked as such
    for t in chosen.get("tokens") or []:
        if not isinstance(t, dict):
            continue
        name = t.get("name", "")
        if "authorization" in name.lower() or t.get("type") == "bearer":
            out["headers"]["Authorization"] = f"Bearer {t.get('value')}"
    return out


def apply_credentials_to_step(step: dict, creds: dict[str, Any]) -> None:
    """Merge loaded credentials into a step's request (only if not already set)."""
    if not creds:
        return
    req = step.setdefault("request", {})
    if creds.get("cookies"):
        existing = req.setdefault("cookies", {})
        for k, v in creds["cookies"].items():
            existing.setdefault(k, v)
    if creds.get("headers"):
        existing = req.setdefault("headers", {})
        for k, v in creds["headers"].items():
            existing.setdefault(k, v)


def find_next_unsent_step(finding: dict) -> int | None:
    """Return the index of the first step whose response is missing/empty."""
    steps = finding.get("poc", {}).get("steps", [])
    for i, step in enumerate(steps):
        resp = step.get("response") or {}
        if not resp or "body" not in resp:
            return i
    return None


# ─── failure_log 自动生成 ────────────────────────────────────────────────────

def append_failure_log(poc: dict, step_idx: int, reason: str,
                       hypothesis: str, next_action: str) -> None:
    log = poc.setdefault("failure_log", [])
    log.append({
        "step": step_idx + 1,
        "reason": reason,
        "hypothesis": hypothesis,
        "next_action": next_action,
    })


# ─── 单 finding 处理 ─────────────────────────────────────────────────────────

class StepOutcome:
    """Possible outcomes after processing one step of a finding."""
    DONE = "done"            # terminal result set
    NEED_NEXT = "need_next"  # response captured; LLM constructs next step
    TRANSIENT = "transient"  # network error after retries; mark and stop


def process_one_step(finding: dict, target: str, timeout: int,
                     retry_on_error: int, state: FindingState,
                     creds: dict[str, Any], dry_run: bool, verbose: bool) -> str:
    """Process the next unsent step for this finding."""
    poc = finding.setdefault("poc", {})
    poc.setdefault("steps", [])

    idx = find_next_unsent_step(finding)
    if idx is None:
        return StepOutcome.NEED_NEXT  # no more steps to send, LLM decides next

    step = poc["steps"][idx]
    step["step"] = idx + 1  # auto-fill

    # Inject credentials into step 0 only (later steps inherit via session jar)
    if idx == 0 and creds:
        apply_credentials_to_step(step, creds)

    if dry_run:
        prepared = build_request(step, target, state)
        print(f"\n[DRY-RUN] step {idx + 1}: {prepared.method} {prepared.url}")
        for h, v in (prepared.headers or {}).items():
            print(f"  {h}: {v}")
        if prepared.body:
            preview = prepared.body if isinstance(prepared.body, str) else "<binary>"
            print(f"\n{str(preview)[:500]}")
        # Do not modify response in dry-run
        return StepOutcome.NEED_NEXT

    # Network with retry on transient errors only
    last_error: Exception | None = None
    for attempt in range(retry_on_error + 1):
        try:
            prepared = build_request(step, target, state)
            step.setdefault("request", {})["raw"] = prepared_request_raw(prepared)
            start = time.time()
            resp, redirect_chain = send_with_redirects(prepared, state, timeout)
            elapsed = time.time() - start
            resp_data = response_to_dict(resp, redirect_chain, elapsed, finding)
            step["response"] = resp_data
            if verbose and resp_data.get("_evidence_match"):
                hits = resp_data["_evidence_match"]
                print(f"  [signature] step {idx + 1}: {len(hits)} hits → "
                      f"types={sorted({h['type'] for h in hits})} "
                      f"max_strength={resp_data['_meta'].get('evidence_strength')}")

            # Capture cookies into state for ${steps.N.cookies.X}
            state.cookies[idx] = capture_cookies(resp)

            # Apply `extract` rules
            rules = step.get("extract") or {}
            if rules:
                state.steps[idx] = extract_from_response(rules, resp_data)
                if verbose:
                    print(f"  [extract] step {idx + 1}: {state.steps[idx]}")
            return StepOutcome.NEED_NEXT
        except requests.exceptions.Timeout as e:
            last_error = e
            if attempt < retry_on_error:
                wait = 1 * (3 ** attempt)
                if verbose:
                    print(f"  [retry {attempt + 1}/{retry_on_error}] timeout, waiting {wait}s")
                time.sleep(wait)
                continue
            # Final timeout — record but do NOT mark whole poc as timeout yet;
            # let caller decide based on retry-on-error budget
            step["response"] = {
                "status": 0, "headers": {}, "body": f"Request timed out after {timeout}s",
                "_meta": {"error": "timeout", "attempts": attempt + 1},
            }
            poc["result"] = "timeout"
            poc["evidence"] = (
                f"Step {idx + 1} request timed out after {timeout}s "
                f"({retry_on_error + 1} attempts)"
            )
            append_failure_log(poc, idx,
                               reason=f"timeout after {timeout}s × {attempt + 1} attempts",
                               hypothesis="target unreachable or extremely slow",
                               next_action="verify target reachability; consider --timeout increase")
            return StepOutcome.TRANSIENT
        except requests.exceptions.ConnectionError as e:
            last_error = e
            if attempt < retry_on_error:
                wait = 1 * (3 ** attempt)
                if verbose:
                    print(f"  [retry {attempt + 1}/{retry_on_error}] connection error: {e}, waiting {wait}s")
                time.sleep(wait)
                continue
            step["response"] = {
                "status": 0, "headers": {}, "body": f"Connection error: {e}",
                "_meta": {"error": "connection", "attempts": attempt + 1},
            }
            poc["result"] = "failure"
            poc["evidence"] = (
                f"Step {idx + 1} connection failed after {retry_on_error + 1} attempts: {e}"
            )
            append_failure_log(poc, idx,
                               reason=f"connection error × {attempt + 1}: {e}",
                               hypothesis="target host down / firewall / DNS issue",
                               next_action="verify target URL & network; rerun verify_vuln.py")
            return StepOutcome.TRANSIENT
        except Exception as e:
            # non-retryable error
            step["response"] = {
                "status": 0, "headers": {}, "body": f"Error: {type(e).__name__}: {e}",
                "_meta": {"error": "exception"},
            }
            poc["result"] = "failure"
            poc["evidence"] = f"Step {idx + 1} error: {e}"
            append_failure_log(poc, idx,
                               reason=f"{type(e).__name__}: {e}",
                               hypothesis="malformed request or unexpected runtime error",
                               next_action="inspect step request structure")
            return StepOutcome.DONE

    # Should be unreachable
    raise RuntimeError("unreachable: process_one_step did not return") from last_error


# ─── Sub-file 支持 & merge 路径 ──────────────────────────────────────────────

def _detect_subfile(data: dict) -> bool:
    """A sub-file looks like {vuln_id, poc, ...} (no top-level findings/audit)."""
    return "vuln_id" in data and "poc" in data and "findings" not in data


def _wrap_subfile_for_processing(data: dict) -> dict:
    """Wrap a single-finding sub-file in the standard top-level shape so the rest
    of verify_vuln.py treats it as a normal draft with 1 finding."""
    return {
        "_subfile_mode": True,
        "audit": {},  # ignored in sub-file mode
        "findings": [data],
    }


def _unwrap_subfile_after_processing(wrapped: dict) -> dict:
    return wrapped["findings"][0]


def finding_requires_auth(finding: dict) -> bool:
    attack_surface = (finding.get("analysis") or {}).get("attack_surface") or {}
    if attack_surface.get("auth_required") is True:
        return True
    if attack_surface.get("required_role"):
        return True
    for key in ("auth_required", "required_role"):
        if (finding.get("location") or {}).get(key):
            return True
    return False


def auth_capture_hint(target: str, username: str | None, password: str | None,
                      role: str | None, credentials_path: str | None) -> str:
    cmd = [
        "python",
        "vibe-csa/scripts/prepare_auth_session.py",
        "--target",
        target,
        "--output",
        credentials_path or "workDir/sessions/creds.json",
    ]
    if username:
        cmd.extend(["--username", username])
    if password:
        cmd.extend(["--password", password])
    if role:
        cmd.extend(["--role", role])
    return " ".join(cmd)


def merge_subfiles(subfile_paths: list[Path], main_draft_path: Path,
                   verbose: bool = False) -> int:
    """Merge sub-files' poc/failure_log/evidence/result/status/evidence_level
    into the corresponding findings of the main draft. Returns merge count."""
    if not main_draft_path.exists():
        print(f"[merge] main draft not found: {main_draft_path}", file=sys.stderr)
        return -1

    try:
        main_data = json.loads(main_draft_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[merge] failed to parse main draft: {e}", file=sys.stderr)
        return -1

    findings_by_id: dict[str, dict] = {
        f.get("vuln_id"): f for f in main_data.get("findings", []) if f.get("vuln_id")
    }

    merged = 0
    skipped: list[str] = []
    for p in subfile_paths:
        if not p.exists():
            skipped.append(f"{p} (missing)")
            continue
        try:
            sub = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            skipped.append(f"{p} (invalid json: {e})")
            continue

        vid = sub.get("vuln_id")
        if not vid:
            skipped.append(f"{p} (no vuln_id)")
            continue

        target = findings_by_id.get(vid)
        if target is None:
            skipped.append(f"{p} (vuln_id={vid} not in main draft)")
            continue

        # Keys that Phase 4 may have updated; copy whichever the sub-file has set.
        normalize_pending_skeleton_result(sub)
        normalize_runtime_evidence(sub)
        for key in ("poc", "status", "evidence_level", "finding_class", "dynamic_verification",
                    "attack_path", "tracking_completeness", "evidence_refs", "x_finding_class",
                    "x_created_artifacts", "x_cleanup_plan", "x_cleanup_result"):
            if key in sub:
                target[key] = sub[key]
        merged += 1
        if verbose:
            result = sub.get("poc", {}).get("result")
            print(f"[merge] {vid}: poc.result={result}, status={sub.get('status')}, "
                  f"evidence_level={sub.get('evidence_level')}")

    # Atomic write back
    for finding in main_data.get("findings", []):
        normalize_pending_skeleton_result(finding)
        normalize_runtime_evidence(finding)
    tmp = main_draft_path.with_suffix(main_draft_path.suffix + ".tmp")
    tmp.write_text(json.dumps(main_data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(main_draft_path)

    print(f"\n[merge] merged {merged} sub-file(s) into {main_draft_path}")
    if skipped:
        print(f"[merge] skipped {len(skipped)}:")
        for s in skipped:
            print(f"  - {s}")
    return merged


def ensure_dynamic_verified_draft(main_draft_path: Path, verbose: bool = False) -> bool:
    """Ensure merge target exists and is marked as Stage 2 output.

    If `main_draft_path` does not exist, bootstrap it from
    `<parent>/static-merged.json`. Whether bootstrapped or pre-existing, force
    `audit.stage = "dynamic_verification"` before merge.
    """
    source_static_path = main_draft_path.parent / "static-merged.json"

    if not main_draft_path.exists():
        if not source_static_path.exists():
            print(
                "[merge] main draft not found and bootstrap source is missing: "
                f"{source_static_path}",
                file=sys.stderr,
            )
            return False
        try:
            data = json.loads(source_static_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"[merge] failed to parse bootstrap source: {e}", file=sys.stderr)
            return False
        if verbose:
            print(f"[merge] bootstrapping {main_draft_path} from {source_static_path}")
    else:
        try:
            data = json.loads(main_draft_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"[merge] failed to parse main draft: {e}", file=sys.stderr)
            return False
        if verbose:
            print(f"[merge] updating existing draft: {main_draft_path}")

    audit = data.setdefault("audit", {})
    previous_stage = audit.get("stage")
    audit["stage"] = "dynamic_verification"

    main_draft_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = main_draft_path.with_suffix(main_draft_path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(main_draft_path)

    if verbose:
        print(
            "[merge] ensured dynamic draft: "
            f"stage {previous_stage!r} -> 'dynamic_verification'"
        )
    return True


# ─── 主循环 ──────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify vibe-csa findings against a live target (or merge Phase 4 sub-files)",
    )
    parser.add_argument("json_file", nargs="?",
                        help="Path to vibe-csa-draft.json or a single-finding sub-file")
    parser.add_argument("--merge", nargs="+", metavar="SUBFILE",
                        help="Merge mode: paths/globs of Phase 4 sub-files to merge")
    parser.add_argument("--into", help="Merge mode: target main draft JSON path")
    parser.add_argument("--target",
                        help="Target base URL (required in verify mode)")
    parser.add_argument("--finding",
                        help="Verify only this vuln_id (e.g. FINDING-001)")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES,
                        help=f"Max steps per finding (default {DEFAULT_MAX_RETRIES})")
    parser.add_argument("--retry-on-error", type=int, default=DEFAULT_RETRY_ON_ERROR,
                        help=f"Retries on Timeout/ConnectionError (default {DEFAULT_RETRY_ON_ERROR})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Request timeout in seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--credentials",
                        help="Path to extract_credentials.py output (workDir/sessions/creds.json)")
    parser.add_argument("--role",
                        help="Which role to use when credentials file has multiple roles")
    parser.add_argument("--auth-required", action="store_true",
                        help="Require --credentials before sending requests")
    parser.add_argument("--username",
                        help="Username hint used only in the prepare_auth_session.py command suggestion")
    parser.add_argument("--password",
                        help="Password hint used only in the prepare_auth_session.py command suggestion")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview the next request without sending")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print extra diagnostic info")
    args = parser.parse_args()

    # ── Merge mode dispatch ──
    if args.merge:
        if not args.into:
            print("--merge requires --into <main-draft.json>", file=sys.stderr)
            sys.exit(1)
        main_draft_path = Path(args.into)
        if not ensure_dynamic_verified_draft(main_draft_path, args.verbose):
            sys.exit(1)
        # Expand globs (the shell may not have done it on Windows)
        import glob as _glob
        paths: list[Path] = []
        for pattern in args.merge:
            matched = _glob.glob(pattern)
            if matched:
                paths.extend(Path(m) for m in matched)
            else:
                paths.append(Path(pattern))
        merged = merge_subfiles(paths, main_draft_path, args.verbose)
        sys.exit(0 if merged > 0 else 1)

    # ── Verify mode (default) ──
    if not args.json_file:
        print("json_file is required (or use --merge)", file=sys.stderr)
        sys.exit(1)
    if not args.target:
        print("--target is required in verify mode", file=sys.stderr)
        sys.exit(1)

    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"File not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    try:
        raw_data = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Detect sub-file mode and wrap if so
    subfile_mode = _detect_subfile(raw_data)
    if subfile_mode:
        data = _wrap_subfile_for_processing(raw_data)
        if args.verbose:
            print(f"[mode] sub-file detected (vuln_id={raw_data.get('vuln_id')}); "
                  "processing as single-finding draft")
    else:
        data = raw_data

    findings = data.get("findings", [])
    if args.finding:
        findings = [f for f in findings if f.get("vuln_id") == args.finding]
        if not findings:
            print(f"Finding not found: {args.finding}", file=sys.stderr)
            sys.exit(1)

    creds: dict[str, Any] = {}
    if args.credentials:
        creds_path = Path(args.credentials)
        creds = load_credentials(creds_path, args.role)
        if not creds and args.verbose:
            print(f"[warn] no usable credentials in {creds_path}", file=sys.stderr)

    auth_needed = args.auth_required or any(finding_requires_auth(f) for f in findings)
    if auth_needed and not creds:
        print("[auth] credentials are required before dynamic verification.", file=sys.stderr)
        print("[auth] run browser-based credential capture first:", file=sys.stderr)
        print(
            "  " + auth_capture_hint(
                args.target,
                args.username,
                args.password,
                args.role,
                args.credentials,
            ),
            file=sys.stderr,
        )
        sys.exit(1)

    transient_count = 0
    completed_count = 0
    progress_count = 0  # responses captured but more steps needed
    unreachable_count = 0

    for finding in findings:
        vid = finding.get("vuln_id", "unknown")
        poc = finding.setdefault("poc", {})
        steps = poc.setdefault("steps", [])

        # Already terminal
        if poc.get("result") in ("success", "failure", "timeout", "skipped", "auth_failed"):
            print(f"[{vid}] already verified: result={poc['result']}, skipping")
            completed_count += 1
            continue

        if not steps:
            print(f"[{vid}] no poc.steps defined — LLM must construct initial request")
            continue

        # Max-retries gate: count of steps with response (i.e. completed sends)
        sent_count = sum(1 for s in steps if (s.get("response") or {}).get("body") is not None)
        if sent_count >= args.max_retries:
            poc["result"] = "failure"
            poc["evidence"] = (
                f"Max retries ({args.max_retries}) exhausted without conclusive result"
            )
            append_failure_log(poc, sent_count - 1,
                               reason=f"reached --max-retries={args.max_retries}",
                               hypothesis="vulnerability may not exist or further bypass needed",
                               next_action="enter Phase 4.5 (exploit-chain discovery) or downgrade to HYPOTHESIS")
            print(f"[{vid}] max retries reached, marking failure")
            completed_count += 1
            continue

        state = FindingState()

        outcome = process_one_step(
            finding, args.target, args.timeout, args.retry_on_error,
            state, creds, args.dry_run, args.verbose,
        )

        if outcome == StepOutcome.TRANSIENT:
            transient_count += 1
            if poc.get("result") in ("timeout", "failure"):
                last_meta = (steps[find_next_unsent_step(finding) or len(steps) - 1]
                             .get("response", {}).get("_meta", {}))
                if last_meta.get("error") == "timeout":
                    unreachable_count += 1
            print(f"[{vid}] transient: result={poc.get('result')}, "
                  f"evidence={poc.get('evidence')}")
        elif outcome == StepOutcome.DONE:
            completed_count += 1
            print(f"[{vid}] done: result={poc.get('result')}, "
                  f"evidence={poc.get('evidence')}")
        else:  # NEED_NEXT
            progress_count += 1
            try:
                last_idx = max(i for i, s in enumerate(poc["steps"]) if (s.get("response") or {}).get("body") is not None)
                status = poc["steps"][last_idx]["response"].get("status")
                print(f"[{vid}] step {last_idx + 1} sent — status={status}")
                print(f"[{vid}] LLM must analyze response and construct next step (or set result)")
            except ValueError:
                # dry-run, nothing sent
                pass

    # Atomic write — unwrap if sub-file mode
    for finding in data.get("findings", []):
        normalize_runtime_evidence(finding)

    payload = _unwrap_subfile_after_processing(data) if subfile_mode else data
    tmp = json_path.with_suffix(json_path.suffix + ".tmp")
    text_issues = find_text_quality_issues(payload)
    if text_issues:
        for issue in text_issues[:20]:
            print(f"[ERROR] text quality issue at {issue['path']}: {issue['message']}", file=sys.stderr)
        sys.exit(1)
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(json_path)

    print(f"\nUpdated: {args.json_file}")
    print(f"Summary: completed={completed_count}, progress={progress_count}, "
          f"transient={transient_count}, unreachable={unreachable_count}")

    # Differentiated exit codes
    if not findings:
        sys.exit(1)
    if unreachable_count == len(findings):
        sys.exit(3)
    if transient_count > 0 and completed_count == 0:
        sys.exit(2)
    if progress_count > 0 and completed_count + transient_count == 0:
        sys.exit(4)
    sys.exit(0)


if __name__ == "__main__":
    main()
