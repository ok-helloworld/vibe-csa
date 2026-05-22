"""Shared consistency checks between generate_report.py and validate_report.py.

These are *business rules* that go beyond what JSON Schema can express
(or beyond what we want to express there to keep schemas readable).

Two strictness levels:
  mode="draft"  — relaxed: allow empty steps / failure_log; only the most
                  important integrity rules are enforced.
  mode="final"  — strict: full enforcement (default for generate_report and
                  for `validate_report --mode final`).

Return shape:
    consistency_checks(data, mode) -> (errors: list[str], warnings: list[str])
"""

from __future__ import annotations

from typing import Any


EVIDENCE_MIN_LEN_SUCCESS = 10
LLM_PLACEHOLDER_HINTS = ["响应内容", "待填充", "TODO", "请填写", "<填入"]

# Vulnerability types that REQUIRE signature-matched runtime evidence
# to support CONFIRMED + L2/L3. See references/exploit-success-signatures.md.
SIGNATURE_REQUIRED_VULN_TYPES = {
    "sql injection", "sqli", "sql-injection",
    "sql 注入", "sql注入",
    "rce", "command injection", "command-injection", "cmd injection",
    "命令执行", "命令注入", "代码执行", "任意代码执行",
    "code injection", "code-execution",
    "path traversal", "path-traversal", "directory traversal",
    "路径穿越", "目录穿越", "目录遍历",
    "arbitrary file read", "file read", "file-read", "lfi",
    "任意文件读取", "任意文件下载", "本地文件包含",
    "file upload rce", "file-upload-rce", "arbitrary file upload",
    "web shell upload", "web-shell-upload",
    "文件上传", "任意文件创建", "任意文件写入", "任意文件删除",
    "ssrf",
    "服务器端请求伪造", "http 请求伪造", "http请求伪造",
    "ssti", "template injection",
    "xxe", "xml external entity",
    "xml 注入",
    "deserialization", "deser", "unsafe deserialization",
    "反序列化",
    "idor", "broken access control", "horizontal privilege escalation",
    "越权访问", "登录绕过",
    "stored xss", "xss-stored",
    "跨站脚本", "通用跨站脚本",
}

# Vulnerability types that REQUIRE the upload→access→execute 3-step proof
UPLOAD_RCE_VULN_TYPES = {
    "file upload rce", "file-upload-rce",
    "arbitrary file upload",
    "web shell upload", "web-shell-upload",
    "文件上传 rce", "文件上传rce", "webshell 上传", "webshell上传",
}

SEBUG_VULN_TYPES = {
    "HTTP 参数污染", "后门", "Cookie 验证错误", "跨站请求伪造", "ShellCode", "SQL 注入",
    "任意文件下载", "任意文件创建", "任意文件删除", "任意文件读取", "其他类型", "变量覆盖",
    "命令执行", "嵌入恶意代码", "弱密码", "拒绝服务", "数据库发现", "文件上传", "远程文件包含",
    "本地溢出", "权限提升", "信息泄漏", "登录绕过", "目录穿越", "解析错误", "越权访问",
    "跨站脚本", "路径泄漏", "代码执行", "远程密码修改", "远程溢出", "目录遍历", "空字节注入",
    "中间人攻击", "格式化字符串", "缓冲区溢出", "HTTP 请求拆分", "CRLF 注入", "XML 注入",
    "本地文件包含", "证书预测", "HTTP 响应拆分", "SSI 注入", "内存溢出", "整数溢出",
    "HTTP 响应伪造", "HTTP 请求伪造", "内容欺骗", "XQuery 注入", "缓存区过读", "暴力破解",
    "LDAP 注入", "安全模式绕过", "备份文件发现", "XPath 注入", "URL 重定向", "代码泄漏",
    "释放后重用", "DNS 劫持", "错误的输入验证", "通用跨站脚本", "服务器端请求伪造", "跨域漏洞",
    "错误的证书验证", "缓存投毒", "HTTP请求走私", "命令注入",
}


def _step_has_request(step: dict) -> bool:
    req = step.get("request") or {}
    return bool(req.get("method") and req.get("url"))


def _step_has_response(step: dict) -> bool:
    resp = step.get("response") or {}
    return "status" in resp and "body" in resp


def _vuln_type_key(finding: dict) -> str:
    """Normalize vuln_type for set lookup."""
    return (finding.get("vuln_type") or "").strip().lower().replace("　", " ")


def _collect_all_evidence_match(finding: dict) -> list[dict]:
    """Aggregate _evidence_match across all poc.steps' responses."""
    out: list[dict] = []
    for s in (finding.get("poc") or {}).get("steps") or []:
        resp = s.get("response") or {}
        for hit in (resp.get("_evidence_match") or []):
            if isinstance(hit, dict):
                out.append(hit)
    return out


def _has_runtime_signature(finding: dict) -> tuple[bool, str | None]:
    """Returns (has_hit, max_strength). max_strength ∈ {L2,L3,None}."""
    hits = _collect_all_evidence_match(finding)
    if not hits:
        return False, None
    strengths = {h.get("strength", "L2") for h in hits}
    if "L3" in strengths:
        return True, "L3"
    if "L2" in strengths:
        return True, "L2"
    return True, "L1"


def _has_upload_access_step(finding: dict) -> bool:
    """For upload-RCE findings, require ≥2 steps where a later GET fetches the
    uploaded resource (uses ${steps.N....} template referencing earlier step) and
    response.body of that step matches upload-marker or cmd-exec signatures."""
    poc = finding.get("poc") or {}
    steps = poc.get("steps") or []
    if len(steps) < 2:
        return False
    # Find any GET step that references ${steps.N...} in url AND has _evidence_match
    for s in steps[1:]:
        req = s.get("request") or {}
        method = (req.get("method") or "").upper()
        url = req.get("url") or ""
        if method != "GET":
            continue
        references_prior = "${steps." in url
        resp = s.get("response") or {}
        hits = resp.get("_evidence_match") or []
        match_types = {h.get("type") for h in hits if isinstance(h, dict)}
        if references_prior and (match_types & {"upload-marker", "cmd-exec"}):
            return True
    return False


def _evidence_looks_real(evidence: str, finding: dict) -> bool:
    """Cheap heuristic: evidence should reference response, snippet, or location."""
    if not evidence:
        return False
    e = evidence.lower()
    if any(k in e for k in ("response", "body", "snippet", "file://", "line ")):
        return True
    # Allow static-only findings to point at the source snippet
    snippet = (finding.get("location") or {}).get("snippet") or ""
    if snippet and snippet[:30] and snippet[:30] in evidence:
        return True
    return False


def _is_published_failed_hypothesis(finding: dict, result: str) -> bool:
    dynamic = finding.get("dynamic_verification") or {}
    return (
        result in {"failure", "timeout", "auth_failed"}
        and finding.get("status") == "HYPOTHESIS"
        and finding.get("finding_class") == "code_only"
        and dynamic.get("state") in {"failed", "blocked"}
    )


def consistency_checks(data: dict, mode: str = "final") -> tuple[list[str], list[str]]:
    """Check business rules. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []
    strict = mode == "final"

    # Top-level audit basics
    audit = data.get("audit") or {}
    summary = audit.get("summary") or {}

    # If summary present, basic arithmetic check (fixed+open+unverified should ≤ total)
    if summary:
        total = summary.get("total", 0)
        fixed = summary.get("fixed", 0)
        open_ = summary.get("open", 0)
        unverified = summary.get("unverified", 0)
        if (fixed + open_ + unverified) > total:
            warnings.append(
                f"audit.summary: fixed+open+unverified ({fixed + open_ + unverified}) "
                f"exceeds total ({total}); statistics may be out of sync."
            )

    # chains[] referential integrity
    chains = data.get("chains") or []
    findings = data.get("findings") or []
    vuln_ids = {f.get("vuln_id") for f in findings if f.get("vuln_id")}
    for ch in chains:
        cid = ch.get("chain_id", "?")
        for s in (ch.get("steps") or []):
            fid = s.get("finding_id")
            if fid and fid not in vuln_ids:
                errors.append(
                    f"chains[{cid}].steps references unknown finding_id '{fid}'"
                )

    for i, f in enumerate(findings):
        vid = f.get("vuln_id", f"findings[{i}]")
        poc = f.get("poc") or {}
        result = poc.get("result") or ""
        steps = poc.get("steps") or []
        evidence = poc.get("evidence") or ""
        failure_log = poc.get("failure_log") or []

        # ── chain_id back-ref check ──
        if f.get("chain_id"):
            if not any(c.get("chain_id") == f["chain_id"] for c in chains):
                warnings.append(
                    f"{vid}: chain_id='{f['chain_id']}' not present in top-level chains[]"
                )

        # ── related_findings integrity ──
        for rel in (f.get("related_findings") or []):
            rid = rel.get("vuln_id")
            if rid and rid not in vuln_ids:
                errors.append(
                    f"{vid}: related_findings references unknown vuln_id '{rid}'"
                )

        # ── poc rules by result ──
        if result == "success":
            # Allow static-only success (e.g. hardcoded secret) if evidence references snippet
            if not steps:
                if not _evidence_looks_real(evidence, f):
                    errors.append(
                        f"{vid}: poc.result=success but poc.steps is empty AND evidence "
                        "does not reference location.snippet (static evidence must cite snippet)"
                    )
            else:
                for j, s in enumerate(steps):
                    if not _step_has_request(s):
                        errors.append(f"{vid}: poc.steps[{j}] missing request.method/url")
                    if not _step_has_response(s):
                        errors.append(
                            f"{vid}: poc.result=success but poc.steps[{j}] missing response.status/body "
                            "(must be written by verify_vuln.py)"
                        )

            # Evidence quality
            if len(evidence) < EVIDENCE_MIN_LEN_SUCCESS:
                errors.append(
                    f"{vid}: poc.result=success but evidence too short "
                    f"({len(evidence)} chars, min {EVIDENCE_MIN_LEN_SUCCESS})"
                )
            elif strict and not _evidence_looks_real(evidence, f):
                warnings.append(
                    f"{vid}: poc.evidence should reference response.body or location.snippet "
                    "to be considered strong evidence"
                )

            # No LLM placeholder text in response bodies
            for j, s in enumerate(steps):
                body = (s.get("response") or {}).get("body", "")
                if any(ph in str(body) for ph in LLM_PLACEHOLDER_HINTS):
                    errors.append(
                        f"{vid}: poc.steps[{j}].response.body contains placeholder text "
                        f"({str(body)[:40]!r}); must be real response from verify_vuln.py"
                    )

        elif result == "failure":
            if not steps:
                if strict and not _is_published_failed_hypothesis(f, result):
                    errors.append(
                        f"{vid}: poc.result=failure but poc.steps is empty; "
                        "must record at least one attempted request+response"
                    )
            else:
                for j, s in enumerate(steps):
                    if not _step_has_request(s):
                        errors.append(f"{vid}: poc.steps[{j}] missing request")
                    if not _step_has_response(s) and strict:
                        errors.append(
                            f"{vid}: poc.result=failure but poc.steps[{j}] missing response"
                        )
            if not failure_log and strict and not _is_published_failed_hypothesis(f, result):
                errors.append(
                    f"{vid}: poc.result=failure but poc.failure_log is empty; "
                    "must record reason/hypothesis/next_action per attempt"
                )

        elif result == "timeout":
            if not steps and strict and not _is_published_failed_hypothesis(f, result):
                errors.append(
                    f"{vid}: poc.result=timeout but poc.steps is empty; "
                    "must record at least the timed-out request"
                )
            else:
                for j, s in enumerate(steps):
                    if not _step_has_request(s):
                        errors.append(f"{vid}: poc.steps[{j}] missing request")

        elif result == "auth_failed":
            if not steps:
                warnings.append(
                    f"{vid}: poc.result=auth_failed — consider recording the auth probe request"
                )

        elif result == "skipped":
            for j, s in enumerate(steps):
                if not _step_has_request(s):
                    errors.append(f"{vid}: poc.steps[{j}] missing request")

        # ── general warnings ──
        analysis_data_flow = (f.get("analysis") or {}).get("data_flow")
        if f.get("status") == "CONFIRMED" and not (f.get("data_flow") or analysis_data_flow):
            sev = f.get("severity", "")
            if sev in ("critical", "high"):
                warnings.append(
                    f"{vid}: CONFIRMED {sev} finding lacks data_flow — consider adding taint chain"
                )

        if f.get("dktss_score") == 0:
            warnings.append(f"{vid}: dktss_score=0, please confirm intentional")

        # ── evidence_level vs status coherence (v2 vulnerability-conditions) ──
        status = f.get("status")
        el = f.get("evidence_level")
        if status == "CONFIRMED":
            if el is None:
                warnings.append(
                    f"{vid}: status=CONFIRMED but evidence_level missing — "
                    "per vulnerability-conditions.md v2, CONFIRMED should record evidence_level=L3 (L2 acceptable when Phase 4 supplies business-data evidence)"
                )
            elif el in ("L0", "L1"):
                msg = (
                    f"{vid}: status=CONFIRMED but evidence_level={el} — "
                    "L0/L1 represents weak evidence; downgrade to HYPOTHESIS unless Phase 4 L2/L3 evidence is added"
                )
                if strict:
                    errors.append(msg)
                else:
                    warnings.append(msg)
        elif status == "HYPOTHESIS" and el == "L3":
            warnings.append(
                f"{vid}: status=HYPOTHESIS but evidence_level=L3 — strong evidence may justify upgrading to CONFIRMED"
            )

        # ── Signature evidence requirement (exploit-success-signatures.md) ──
        # For vuln types listed in SIGNATURE_REQUIRED_VULN_TYPES, a CONFIRMED+L2/L3
        # finding MUST have at least one _evidence_match in steps responses.
        vt_key = _vuln_type_key(f)
        finding_class = f.get("x_finding_class")
        vuln_type = (f.get("vuln_type") or "").strip()
        if vuln_type and vuln_type not in SEBUG_VULN_TYPES:
            warnings.append(
                f"{vid}: vuln_type='{vuln_type}' is not in the bundled bug category list; "
                "prefer a Chinese type from references/bug-categories.md."
            )
        is_sig_required_type = any(vt_key == t or t in vt_key for t in SIGNATURE_REQUIRED_VULN_TYPES) if vt_key else False
        if is_sig_required_type:
            has_hit, max_strength = _has_runtime_signature(f)

            # Check x_signature_type declared
            if not f.get("x_signature_type"):
                warnings.append(
                    f"{vid}: vuln_type='{vt_key}' is signature-required but "
                    "x_signature_type is missing — verify_vuln.py won't auto-match evidence. "
                    "See references/exploit-success-signatures.md."
                )

            if status == "CONFIRMED" and el in ("L2", "L3") and not has_hit:
                msg = (
                    f"{vid}: status=CONFIRMED+evidence_level={el} for vuln_type='{vt_key}' "
                    f"but NO signature match in any poc.steps[].response._evidence_match. "
                    f"Per exploit-success-signatures.md, runtime evidence is REQUIRED — "
                    f"downgrade to HYPOTHESIS + x_finding_class='code_only', or add a step "
                    f"whose response body matches the relevant signature library."
                )
                if strict:
                    errors.append(msg)
                else:
                    warnings.append(msg)

            if result == "success" and not has_hit and strict:
                # Allow user override: x_signature_waiver explains why no signature applies
                if not f.get("x_signature_waiver"):
                    errors.append(
                        f"{vid}: poc.result=success for vuln_type='{vt_key}' but no "
                        f"_evidence_match in any step. The runtime did not confirm exploitation. "
                        f"Set poc.result='failure' + status='HYPOTHESIS' + x_finding_class='code_only', "
                        f"or add an x_signature_waiver explaining why this case is exempt."
                    )

            # If signatures DID match L3 but status is HYPOTHESIS, suggest upgrade
            if max_strength == "L3" and status == "HYPOTHESIS":
                warnings.append(
                    f"{vid}: L3 signature match present but status=HYPOTHESIS — "
                    "consider upgrading to CONFIRMED (runtime evidence is strong)."
                )

        # ── x_finding_class consistency ──
        if finding_class == "code_only":
            if status == "CONFIRMED" and strict:
                errors.append(
                    f"{vid}: x_finding_class='code_only' is incompatible with status=CONFIRMED. "
                    "Code-only findings (no runtime proof) must remain HYPOTHESIS."
                )
            if result == "success" and strict:
                errors.append(
                    f"{vid}: x_finding_class='code_only' but poc.result=success — "
                    "runtime success requires class='runtime_verified'."
                )
        elif finding_class == "runtime_verified":
            has_hit, _ = _has_runtime_signature(f)
            if not has_hit and strict:
                errors.append(
                    f"{vid}: x_finding_class='runtime_verified' but no _evidence_match "
                    "found in any step. Either add signature matches or use 'code_only'."
                )

        # ── Upload RCE: enforce upload→access→execute proof ──
        is_upload_rce = any(vt_key == t for t in UPLOAD_RCE_VULN_TYPES)
        if is_upload_rce and status == "CONFIRMED" and result == "success":
            if len(steps) < 2:
                if strict:
                    errors.append(
                        f"{vid}: upload-RCE CONFIRMED requires ≥2 poc.steps "
                        "(upload + access). See core/upload-verification.md."
                    )
            elif not _has_upload_access_step(f):
                msg = (
                    f"{vid}: upload-RCE CONFIRMED but no step issues GET against the uploaded "
                    "path with upload-marker/cmd-exec signature match. Without proof the file is "
                    "executed, this is at best 'arbitrary file upload' (lower severity), not RCE."
                )
                if strict:
                    errors.append(msg)
                else:
                    warnings.append(msg)

        # ── extract / template syntax sanity ──
        for j, s in enumerate(steps):
            extr = s.get("extract") or {}
            for var, expr in extr.items():
                if not isinstance(expr, str):
                    errors.append(
                        f"{vid}: poc.steps[{j}].extract.{var} must be a string expression"
                    )
                    continue
                if not (expr.startswith("$.") or expr.startswith("header:")
                        or expr.startswith("cookie:") or expr.startswith("regex:")
                        or expr == "status"):
                    warnings.append(
                        f"{vid}: poc.steps[{j}].extract.{var} uses unknown expression form "
                        f"'{expr}'; expected $.jsonpath / header:Name / cookie:Name / regex:... / status"
                    )

    return errors, warnings
