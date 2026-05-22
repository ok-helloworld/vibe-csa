#!/usr/bin/env python3
"""Generate a normalized vibe-csa v3 JSON report.

The v3 contract uses one finding shape for all stages:
static audit, dynamic verification, and final report generation.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import date, datetime
from pathlib import Path
from typing import Any

try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    from jsonschema import Draft7Validator
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _consistency import consistency_checks  # noqa: E402
from _utf8 import configure_utf8_runtime, find_text_quality_issues  # noqa: E402

configure_utf8_runtime()


SCHEMA_FILE = Path(__file__).resolve().parent.parent / "vibe-csa-schema.json"
CURRENT_SCHEMA_VERSION = "3.0"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DEFAULT_DKTSS_BY_SEVERITY = {"critical": 8.5, "high": 6.5, "medium": 4.5, "low": 2.0}
DEFAULT_REPORT_DIR = Path("workDir") / "reports"
DERIVED_REPORT_SCRIPTS = {
    "html": "vibe_csa_html.py",
    "docx": "vibe_csa_report.py",
}
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


def ensure(obj: dict, key: str, default: Any) -> None:
    if key not in obj or obj.get(key) in (None, ""):
        obj[key] = default


def collect_runtime_snippets(f: dict) -> list[dict]:
    snippets: list[dict] = []
    poc = f.get("poc") or {}
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


def proof_type_from_snippets(snippets: list[dict]) -> str:
    types = {s.get("signature_type") for s in snippets}
    for sig_type, proof_type in PROOF_TYPE_BY_SIGNATURE.items():
        if sig_type in types:
            return proof_type
    return "http_signal" if snippets else "none"


def build_poc_evidence(snippets: list[dict]) -> str:
    if not snippets:
        return ""
    proof_type = proof_type_from_snippets(snippets)
    parts = []
    for item in snippets[:6]:
        sig_type = item.get("signature_type") or "runtime-evidence"
        snippet = str(item.get("snippet") or "").replace("\r", "\\r").replace("\n", "\\n")
        parts.append(
            f"step {item.get('step')} response.body 命中 {sig_type}: "
            f"\"{snippet}\", proof_type={proof_type}"
        )
    if len(snippets) > 6:
        parts.append(f"另有 {len(snippets) - 6} 条 response._evidence_match 命中")
    return "；".join(parts)


def evidence_references_runtime_hits(evidence: str, snippets: list[dict]) -> bool:
    if not evidence:
        return False
    if "response.body" not in evidence and "response._evidence_match" not in evidence:
        return False
    return any(str(s.get("snippet") or "")[:30] in evidence for s in snippets if s.get("snippet"))


def summarize_failed_runtime_attempts(f: dict, result: str) -> None:
    poc = f.setdefault("poc", {})
    dynamic = f.setdefault("dynamic_verification", {})
    attempts = dynamic.setdefault("attempts", [])
    failure_log = poc.get("failure_log") or []
    if not attempts and failure_log:
        for index, item in enumerate(failure_log, start=1):
            if not isinstance(item, dict):
                continue
            attempts.append({
                "attempt": index,
                "payload_strategy": item.get("hypothesis") or "Runtime verification attempt failed.",
                "result": "timeout" if result == "timeout" else "failure",
                "evidence_snippet": item.get("reason", ""),
                "next_action": item.get("next_action", "Keep the finding as HYPOTHESIS or retry with corrected environment."),
            })
    dynamic["final_evidence"] = {"proof_type": "none", "summary": "", "snippets": []}
    dynamic["runtime_notes"] = (
        dynamic.get("runtime_notes") or
        "Runtime verification did not confirm the finding. Failed PoC request/response details are omitted from the final report."
    )
    poc["steps"] = []
    poc["failure_log"] = []
    poc["evidence"] = (
        "动态验证未确认漏洞成立，最终报告保留静态审计发现并标记为 HYPOTHESIS；"
        "失败 PoC 请求与响应不在最终报告发布。"
    )


def normalize_cleanup_metadata(f: dict) -> None:
    artifacts = f.get("x_created_artifacts")
    if not artifacts:
        return
    if not isinstance(artifacts, list):
        f["x_created_artifacts"] = [{
            "artifact_id": "artifact-1",
            "type": "unknown",
            "location": str(artifacts),
            "created_by_step": None,
            "status": "unknown",
        }]
        artifacts = f["x_created_artifacts"]

    plan = f.setdefault("x_cleanup_plan", [])
    if not isinstance(plan, list):
        f["x_cleanup_plan"] = []
        plan = f["x_cleanup_plan"]

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
            "safety_note": "Do not run destructive cleanup automatically; verify the target belongs to this PoC first.",
        })

    result = f.setdefault("x_cleanup_result", {})
    if isinstance(result, dict):
        result.setdefault("state", "not_started")
        result.setdefault("items", [])
        result.setdefault("notes", "Cleanup is tracked but not executed automatically by report generation.")


def normalize_audit(data: dict) -> None:
    data["schema_version"] = CURRENT_SCHEMA_VERSION
    audit = data.setdefault("audit", {})
    ensure(audit, "audit_id", datetime.now().strftime("%Y%m%d-%H%M%S"))
    ensure(audit, "title", "vibe-csa security audit")
    ensure(audit, "repository", "")
    ensure(audit, "stage", "report")
    ensure(audit, "mode", "standard")
    ensure(audit, "scope", "full")
    if isinstance(audit.get("language"), str):
        audit["language"] = [audit["language"]]
    ensure(audit, "language", ["unknown"])
    target = audit.setdefault("target", {})
    ensure(target, "source_path", "")
    ensure(target, "base_url", "")
    ensure(target, "environment", "unknown")
    auth = target.setdefault("auth_context", {})
    ensure(auth, "required", False)
    ensure(auth, "credential_source", "unknown")
    auth.setdefault("roles", [])
    audit.setdefault("tool_versions", {})
    audit.setdefault("coverage_summary", {})
    ad = audit.setdefault("audit_date", {})
    ensure(ad, "end", date.today().isoformat())
    ensure(ad, "start", ad["end"])


def normalize_finding(f: dict, index: int) -> None:
    vid = f.get("vuln_id") or f"FINDING-{index:03d}"
    f["vuln_id"] = vid
    ensure(f, "title", f.get("type") or f.get("vuln_type") or vid)
    ensure(f, "vuln_type", f.get("type") or "other")
    ensure(f, "category", "other")
    if f.get("severity") not in SEVERITY_ORDER:
        f["severity"] = "medium"
    ensure(f, "status", "HYPOTHESIS")
    ensure(f, "confidence", "medium")
    ensure(f, "evidence_level", "L0")
    ensure(f, "finding_class", f.get("x_finding_class") or "code_only")
    f["x_finding_class"] = f["finding_class"]
    ensure(f, "dktss_score", DEFAULT_DKTSS_BY_SEVERITY[f["severity"]])
    ensure(f, "description", f.get("summary") or f"{vid} static finding")

    loc = f.setdefault("location", {})
    ensure(loc, "file", f.get("file") or "unknown")
    ensure(loc, "line_start", f.get("line") or 1)
    ensure(loc, "snippet", f.get("snippet") or "(no snippet)")

    analysis = f.setdefault("analysis", {})
    analysis.setdefault("source", {"description": "unknown"})
    analysis.setdefault("sink", {"description": "unknown"})
    analysis.setdefault("data_flow", f.get("data_flow") if isinstance(f.get("data_flow"), list) else [])
    analysis.setdefault("attack_surface", {"entrypoint": loc.get("route") or loc.get("file") or "unknown"})
    analysis.setdefault("preconditions", [])
    analysis.setdefault("security_controls", [])
    analysis.setdefault("bypass_strategy", {"feasible": False, "difficulty": "unknown", "ideas": []})
    analysis.setdefault("verification_plan", {
        "objective": "Verify that attacker-controlled input reaches the vulnerable sink and produces L2/L3 evidence.",
        "steps": [],
        "success_criteria": [],
    })

    static = f.setdefault("static_evidence", {})
    evidence_refs = f.get("evidence_refs")
    if isinstance(evidence_refs, list):
        evidence_refs = {f"EVID-{i + 1:03d}": str(value) for i, value in enumerate(evidence_refs)}
    elif not isinstance(evidence_refs, dict):
        evidence_refs = {}
    static.setdefault("agent", f.get("agent") or f.get("x_agent") or "unknown")
    static.setdefault("confidence_reason", f.get("confidence_reason") or "Static source review finding.")
    static.setdefault("evidence_refs", evidence_refs)
    static.setdefault("reviewed_files", [])
    static.setdefault("anti_false_positive", {"checked": [], "notes": ""})

    dynamic = f.setdefault("dynamic_verification", {})
    dynamic.setdefault("state", "not_started")
    dynamic.setdefault("attempts", [])
    dynamic.setdefault("final_evidence", {"proof_type": "none", "summary": "", "snippets": []})
    dynamic.setdefault("runtime_notes", "")

    poc = f.setdefault("poc", {})
    poc.setdefault("steps", [])
    poc.setdefault("result", "pending")
    poc.setdefault("evidence", "Static analysis only; runtime PoC evidence is pending.")
    poc.setdefault("failure_log", [])

    f.setdefault("tracking_completeness", "PARTIAL")
    rem = f.setdefault("remediation", {})
    ensure(rem, "short_term", "Add validation, authorization, or parameterization at the vulnerable boundary.")
    ensure(rem, "long_term", "Refactor the data flow so untrusted input cannot directly reach the sink.")
    fix = f.setdefault("fix", {})
    ensure(fix, "language", "text")
    ensure(fix, "before", loc.get("snippet", ""))
    ensure(fix, "after", "")
    normalize_cleanup_metadata(f)


def sync_dynamic_from_poc(f: dict) -> None:
    poc = f.get("poc") or {}
    result = poc.get("result")
    dynamic = f.setdefault("dynamic_verification", {})
    if result == "success":
        f["status"] = "CONFIRMED"
        f["finding_class"] = "runtime_verified"
        f["x_finding_class"] = "runtime_verified"
        dynamic["state"] = "verified"
        has_l3 = any(
            (hit.get("strength") == "L3")
            for step in poc.get("steps") or []
            for hit in ((step.get("response") or {}).get("_evidence_match") or [])
            if isinstance(hit, dict)
        )
        f["evidence_level"] = "L3" if has_l3 else "L2"
    elif result in ("failure", "timeout", "auth_failed"):
        f["status"] = "HYPOTHESIS"
        f["finding_class"] = "code_only"
        f["x_finding_class"] = "code_only"
        f["evidence_level"] = "L0"
        dynamic["state"] = "failed" if result in ("failure", "timeout", "auth_failed") else "blocked"
        summarize_failed_runtime_attempts(f, result)
    elif result == "skipped":
        dynamic["state"] = "skipped"
    else:
        dynamic["state"] = dynamic.get("state") or "not_started"

    snippets = collect_runtime_snippets(f)
    if snippets:
        max_strength = "L3" if any(s["strength"] == "L3" for s in snippets) else "L2"
        f["evidence_level"] = max_strength
        normalized_evidence = build_poc_evidence(snippets)
        if result == "success" and not evidence_references_runtime_hits(poc.get("evidence", ""), snippets):
            poc["evidence"] = normalized_evidence
        dynamic["final_evidence"] = {
            "proof_type": proof_type_from_snippets(snippets),
            "summary": poc.get("evidence", ""),
            "snippets": snippets,
        }


def compute_summary(data: dict) -> None:
    findings = data.setdefault("findings", [])
    counts = {k: 0 for k in SEVERITY_ORDER}
    confirmed = hypothesis = runtime_verified = code_only = open_ = unverified = 0
    by_sev_status: dict[str, dict[str, int]] = {}
    by_type: dict[str, int] = {}

    for i, finding in enumerate(findings, start=1):
        normalize_finding(finding, i)
        sync_dynamic_from_poc(finding)
        sev = finding["severity"]
        counts[sev] += 1
        status = finding["status"].lower()
        by_sev_status.setdefault(sev, {}).setdefault(status, 0)
        by_sev_status[sev][status] += 1
        by_type[finding["vuln_type"]] = by_type.get(finding["vuln_type"], 0) + 1
        if finding["status"] == "CONFIRMED":
            confirmed += 1
        else:
            hypothesis += 1
        if finding["finding_class"] == "runtime_verified":
            runtime_verified += 1
        else:
            code_only += 1
        result = (finding.get("poc") or {}).get("result")
        if result in ("pending", "skipped", "auth_failed", "timeout"):
            unverified += 1
        elif result == "failure":
            open_ += 1

    data["findings"] = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 99))
    data["audit"]["summary"] = {
        "total": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "confirmed": confirmed,
        "hypothesis": hypothesis,
        "runtime_verified": runtime_verified,
        "code_only": code_only,
        "open": open_,
        "unverified": unverified,
        "by_severity_status": by_sev_status,
        "by_type": by_type,
    }


def validate_schema(data: dict) -> list[dict]:
    if not HAS_JSONSCHEMA:
        return [{"path": "", "message": "Missing dependency: pip install jsonschema"}]
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    out = []
    for err in errors:
        parts = []
        for p in err.absolute_path:
            if isinstance(p, int) and parts:
                parts[-1] += f"[{p}]"
            else:
                parts.append(str(p))
        out.append({"path": ".".join(parts) or "(root)", "message": err.message})
    return out


def safe_write(data: dict, output_path: Path, no_backup: bool) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=output_path.parent, prefix=".vibe-csa-", suffix=".tmp")
    tmp_path = Path(tmp_name)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    if output_path.exists() and not no_backup:
        output_path.replace(output_path.with_suffix(output_path.suffix + ".bak"))
    tmp_path.replace(output_path)


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_derived_path(json_output: Path, suffix: str) -> Path:
    return json_output.with_suffix(f".{suffix}")


def run_derived_report(kind: str, json_output: Path, derived_output: Path, logo: str | None = None) -> None:
    script_name = DERIVED_REPORT_SCRIPTS[kind]
    script_path = workspace_root() / script_name
    if not script_path.exists():
        raise SystemExit(f"[ERROR] {script_name} not found at {script_path}")

    derived_output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(script_path),
        "--input",
        str(json_output),
        "--output",
        str(derived_output),
    ]
    if kind == "docx" and logo:
        cmd.extend(["--logo", logo])

    result = subprocess.run(cmd, cwd=str(workspace_root()), text=True)
    if result.returncode != 0:
        raise SystemExit(f"[ERROR] failed to generate {kind} report: {derived_output}")
    print(f"[OK] wrote {kind} report {derived_output}")


def load_json(path: str | None) -> dict:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    if sys.stdin.isatty():
        raise SystemExit("[ERROR] --input is required when stdin is empty")
    return json.loads(sys.stdin.read())


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate normalized vibe-csa v3 report")
    parser.add_argument("--input", "-i")
    parser.add_argument("--output", "-o")
    parser.add_argument("--html-output", help="Optional derived HTML report path. Use 'auto' to place it next to the JSON report.")
    parser.add_argument("--docx-output", help="Optional derived Word report path. Use 'auto' to place it next to the JSON report.")
    parser.add_argument("--logo", help="Optional logo image passed to the Word report generator.")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--no-backup", action="store_true")
    parser.add_argument("--mode", choices=("draft", "final"), default="final")
    args = parser.parse_args()

    data = load_json(args.input)
    normalize_audit(data)
    compute_summary(data)

    schema_errors = validate_schema(data)
    if schema_errors:
        print(json.dumps({"status": "FAIL", "errors": schema_errors}, indent=2, ensure_ascii=False))
        sys.exit(1)

    biz_errors, warnings = consistency_checks(data, mode=args.mode)
    if biz_errors:
        print(json.dumps({"status": "FAIL", "errors": biz_errors, "warnings": warnings}, indent=2, ensure_ascii=False))
        sys.exit(1)
    if warnings:
        print(json.dumps({"status": "PASS_WITH_WARNINGS", "warnings": warnings}, indent=2, ensure_ascii=False))

    text_issues = find_text_quality_issues(data)
    if text_issues:
        print(json.dumps({
            "status": "FAIL",
            "errors": text_issues,
        }, indent=2, ensure_ascii=False))
        sys.exit(1)

    if args.validate_only:
        print("[OK] validation passed")
        return

    output = Path(args.output).resolve() if args.output else DEFAULT_REPORT_DIR / f"vibe-csa-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    safe_write(data, output, args.no_backup)
    summary = data["audit"]["summary"]
    print(f"[OK] wrote {output}")
    if args.html_output:
        html_output = default_derived_path(output, "html") if args.html_output == "auto" else Path(args.html_output).resolve()
        run_derived_report("html", output, html_output)
    if args.docx_output:
        docx_output = default_derived_path(output, "docx") if args.docx_output == "auto" else Path(args.docx_output).resolve()
        run_derived_report("docx", output, docx_output, logo=args.logo)
    print(f"[SUMMARY] total={summary['total']} confirmed={summary['confirmed']} runtime_verified={summary['runtime_verified']} code_only={summary['code_only']}")


if __name__ == "__main__":
    main()
