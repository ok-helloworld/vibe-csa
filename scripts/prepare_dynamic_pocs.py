#!/usr/bin/env python3
"""Initialize Stage 2 PoC working files from Stage 1 static findings.

The output is a single-finding JSON scaffold based on
`references/dynamic-init-example.json`, then filled with the static finding
content from `static-merged.json`.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _utf8 import configure_utf8_runtime, find_text_quality_issues  # noqa: E402

configure_utf8_runtime()

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_TEMPLATE = REPO_ROOT / "references" / "dynamic-init-example.json"


def signature_type_for(finding: dict) -> str:
    key = (finding.get("vuln_type") or "").lower().replace(" ", "")
    if "sql" in key:
        return "sqli"
    if any(k in key for k in ("命令执行", "命令注入", "代码执行", "rce", "command")):
        return "cmd-exec"
    if any(k in key for k in ("任意文件", "文件上传", "fileupload", "filewrite")):
        return "upload-marker"
    if any(k in key for k in ("ssrf", "请求伪造")):
        return "ssrf"
    if any(k in key for k in ("路径穿越", "目录遍历", "文件读取", "lfi", "traversal")):
        return "traversal-linux"
    if any(k in key for k in ("xxe", "xml注入")):
        return "xxe"
    if any(k in key for k in ("ssti", "模板")):
        return "ssti"
    if any(k in key for k in ("反序列化", "deser")):
        return "deser"
    if any(k in key for k in ("越权", "idor")):
        return "idor"
    if "xss" in key or "跨站脚本" in key:
        return "xss-stored"
    return ""


def marker_for(finding: dict) -> str:
    raw = re.sub(r"[^A-Za-z0-9]", "", finding.get("vuln_id", "FINDING"))[-12:]
    return f"VIBECSA-{raw or 'POC'}"


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"[ERROR] file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[ERROR] invalid JSON: {path}: {exc}") from exc


def scaffold_from_template(template: Any) -> Any:
    if isinstance(template, dict):
        return {key: scaffold_from_template(value) for key, value in template.items()}
    if isinstance(template, list):
        if not template:
            return []
        return [scaffold_from_template(template[0])]
    if isinstance(template, bool):
        return False
    if isinstance(template, int) and not isinstance(template, bool):
        return 0
    if isinstance(template, float):
        return 0.0
    if isinstance(template, str):
        return ""
    return None


def merge_with_scaffold(scaffold: Any, raw: Any) -> Any:
    if isinstance(scaffold, dict):
        if not isinstance(raw, dict):
            return copy.deepcopy(scaffold)
        merged: dict[str, Any] = {}
        for key, value in scaffold.items():
            if key in raw:
                merged[key] = merge_with_scaffold(value, raw[key])
            else:
                merged[key] = copy.deepcopy(value)
        for key, value in raw.items():
            if key not in merged:
                merged[key] = copy.deepcopy(value)
        return merged

    if isinstance(scaffold, list):
        if not isinstance(raw, list) or not raw:
            return copy.deepcopy(scaffold)
        if not scaffold:
            return copy.deepcopy(raw)
        item_scaffold = scaffold[0]
        return [merge_with_scaffold(item_scaffold, item) for item in raw]

    return copy.deepcopy(raw)


def apply_dynamic_defaults(finding: dict, template: dict[str, Any]) -> None:
    sig = finding.get("x_signature_type") or signature_type_for(finding)
    if sig:
        finding["x_signature_type"] = sig
    finding["x_unique_marker"] = finding.get("x_unique_marker") or marker_for(finding)
    finding["status"] = "HYPOTHESIS"
    finding["evidence_level"] = "L0"
    finding["finding_class"] = "code_only"
    finding["x_finding_class"] = "code_only"

    dynamic = finding.setdefault("dynamic_verification", {})
    dynamic["state"] = "not_started"
    dynamic["runtime_notes"] = "Stage 2 PoC 骨架已初始化，尚未发送真实请求。"

    attempts_template = (((template.get("dynamic_verification") or {}).get("attempts") or [None])[0]) or {}
    final_evidence_template = ((template.get("dynamic_verification") or {}).get("final_evidence") or {})
    snippet_template = ((final_evidence_template.get("snippets") or [None])[0]) or {}

    attempts = dynamic.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        dynamic["attempts"] = [scaffold_from_template(attempts_template)] if attempts_template else []

    final_evidence = dynamic.setdefault("final_evidence", {})
    if not isinstance(final_evidence, dict):
        final_evidence = {}
        dynamic["final_evidence"] = final_evidence
    final_evidence["proof_type"] = "none"
    final_evidence["summary"] = ""
    snippets = final_evidence.get("snippets")
    if not isinstance(snippets, list) or not snippets:
        final_evidence["snippets"] = [scaffold_from_template(snippet_template)] if snippet_template else []

    poc = finding.setdefault("poc", {})
    poc["result"] = "pending"
    poc["evidence"] = "PoC 骨架已初始化，尚未写入运行时证据。"
    failure_log = poc.get("failure_log")
    if not isinstance(failure_log, list):
        poc["failure_log"] = []

    poc_step_template = ((template.get("poc") or {}).get("steps") or [None])[0] or {}
    steps = poc.get("steps")
    if not isinstance(steps, list) or not steps:
        poc["steps"] = [scaffold_from_template(poc_step_template)] if poc_step_template else []

    if poc.get("steps"):
        first_step = poc["steps"][0]
        if isinstance(first_step, dict):
            first_step["step"] = first_step.get("step") or 1
            first_step.setdefault("name", "")
            request = first_step.setdefault("request", {})
            response = first_step.setdefault("response", {})
            if isinstance(request, dict):
                request.setdefault("headers", {})
                request.setdefault("params", {})
                request.setdefault("cookies", {})
            if isinstance(response, dict):
                response.setdefault("headers", {})
                response.setdefault("redirect_chain", [])
                response.setdefault("_evidence_match", [])

    if dynamic.get("attempts"):
        first_attempt = dynamic["attempts"][0]
        if isinstance(first_attempt, dict):
            first_attempt["attempt"] = first_attempt.get("attempt") or 1
            first_attempt["request_ref"] = "poc.steps[0].request"
            first_attempt["response_ref"] = "poc.steps[0].response"


def prepare_finding(raw: dict) -> dict:
    finding = merge_with_scaffold(DYNAMIC_FINDING_TEMPLATE, raw)
    apply_dynamic_defaults(finding, DYNAMIC_TEMPLATE)
    return finding


def should_prepare(finding: dict, include_all: bool) -> bool:
    if include_all:
        return True
    return (finding.get("poc") or {}).get("result", "pending") == "pending"


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize minimal Stage 2 PoC sub-files from static findings")
    parser.add_argument("--input", required=True, help="Path to .vibe-csa/static-merged.json")
    parser.add_argument("--output-dir", required=True, help="Directory for FINDING-xxx.poc.json")
    parser.add_argument(
        "--template",
        default=str(DEFAULT_TEMPLATE),
        help="Path to the dynamic finding example JSON template.",
    )
    parser.add_argument("--finding", action="append", default=[], help="Only prepare this vuln_id; can repeat")
    parser.add_argument("--all", action="store_true", help="Prepare all findings even if poc.result is not pending")
    args = parser.parse_args()

    global DYNAMIC_TEMPLATE, DYNAMIC_FINDING_TEMPLATE
    DYNAMIC_TEMPLATE = load_json(Path(args.template))
    if not isinstance(DYNAMIC_TEMPLATE, dict):
        raise SystemExit(f"[ERROR] template root must be an object: {args.template}")
    DYNAMIC_FINDING_TEMPLATE = scaffold_from_template(DYNAMIC_TEMPLATE)
    if not isinstance(DYNAMIC_FINDING_TEMPLATE, dict):
        raise SystemExit(f"[ERROR] template root must produce an object scaffold: {args.template}")

    data = load_json(Path(args.input))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    wanted = set(args.finding)
    count = 0
    for finding in data.get("findings") or []:
        vid = finding.get("vuln_id")
        if wanted and vid not in wanted:
            continue
        if not should_prepare(finding, args.all):
            continue
        prepared = prepare_finding(finding)
        issues = find_text_quality_issues(prepared)
        if issues:
            print(f"[ERROR] text quality issue detected in {vid}", file=sys.stderr)
            for issue in issues[:10]:
                print(f"  - {issue['path']}: {issue['message']}", file=sys.stderr)
            sys.exit(1)
        out = output_dir / f"{vid}.poc.json"
        out.write_text(json.dumps(prepared, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        count += 1
        print(f"[OK] prepared {vid}: {out}")

    if count == 0:
        print("[WARN] no findings prepared", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
