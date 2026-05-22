#!/usr/bin/env python3
"""Create a Stage 1 static audit skeleton file for a sub-agent."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _utf8 import configure_utf8_runtime  # noqa: E402

configure_utf8_runtime()


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_TEMPLATE = REPO_ROOT / "references" / "agent-result-example.json"


def default_output_dir() -> Path:
    return Path.cwd() / "workDir" / "agent-results"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a static audit result skeleton for a sub-agent."
    )
    parser.add_argument("agent_name", help="Sub-agent name used as the output filename stem.")
    parser.add_argument(
        "--template",
        default=str(DEFAULT_TEMPLATE),
        help="Path to the example JSON template.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(default_output_dir()),
        help="Directory used to store generated agent result JSON files. Defaults to ./workDir/agent-results under the current working directory.",
    )
    parser.add_argument(
        "--source-path",
        default="",
        help="Initial audit.target.source_path value.",
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="Initial audit.target.base_url value.",
    )
    parser.add_argument(
        "--mode",
        default="standard",
        help="Initial audit.mode value.",
    )
    parser.add_argument(
        "--scope",
        default="full",
        help="Initial audit.scope value.",
    )
    parser.add_argument(
        "--language",
        action="append",
        default=[],
        help="Language value. Repeat this option to provide multiple languages.",
    )
    parser.add_argument(
        "--title",
        default="vibe-csa 代码安全审计",
        help="Initial audit.title value.",
    )
    parser.add_argument(
        "--repository",
        default="",
        help="Initial audit.repository value.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the target file if it already exists.",
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"[ERROR] file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[ERROR] invalid JSON: {path}: {exc}") from exc


def save_json(path: Path, data: Any) -> None:
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def infer_empty_value(template: Any) -> Any:
    if isinstance(template, dict):
        return {key: infer_empty_value(value) for key, value in template.items()}
    if isinstance(template, list):
        return []
    if isinstance(template, bool):
        return False
    if isinstance(template, int) and not isinstance(template, bool):
        return 0
    if isinstance(template, float):
        return 0.0
    if isinstance(template, str):
        return ""
    return None


def normalize_languages(values: list[str]) -> list[str]:
    languages: list[str] = []
    for raw in values:
        for item in raw.split(","):
            text = item.strip()
            if text:
                languages.append(text)
    return languages or ["unknown"]


def build_static_finding_skeleton(template: dict[str, Any]) -> dict[str, Any]:
    finding_template = ((template.get("findings") or [None])[0]) or {}
    finding = infer_empty_value(finding_template)
    if not isinstance(finding, dict):
        return {}

    analysis = finding.setdefault("analysis", {})
    if isinstance(analysis, dict):
        data_flow_template = (((finding_template.get("analysis") or {}).get("data_flow") or [None])[0]) or {}
        security_control_template = (((finding_template.get("analysis") or {}).get("security_controls") or [None])[0]) or {}
        idea_template = ((((finding_template.get("analysis") or {}).get("bypass_strategy") or {}).get("ideas") or [None])[0]) or {}
        verification_step_template = ((((finding_template.get("analysis") or {}).get("verification_plan") or {}).get("steps") or [None])[0]) or {}

        analysis["data_flow"] = [infer_empty_value(data_flow_template)]
        analysis["security_controls"] = [infer_empty_value(security_control_template)]

        bypass_strategy = analysis.setdefault("bypass_strategy", {})
        if isinstance(bypass_strategy, dict):
            bypass_strategy["ideas"] = [infer_empty_value(idea_template)]

        verification_plan = analysis.setdefault("verification_plan", {})
        if isinstance(verification_plan, dict):
            verification_plan["steps"] = [infer_empty_value(verification_step_template)]

    static_evidence = finding.setdefault("static_evidence", {})
    if isinstance(static_evidence, dict):
        reviewed_file_template = (((finding_template.get("static_evidence") or {}).get("reviewed_files") or [None])[0]) or {}
        static_evidence["reviewed_files"] = [infer_empty_value(reviewed_file_template)]

    finding["status"] = "HYPOTHESIS"
    finding["evidence_level"] = "L0"
    finding["finding_class"] = "code_only"
    finding["x_finding_class"] = "code_only"

    dynamic = finding.setdefault("dynamic_verification", {})
    if isinstance(dynamic, dict):
        dynamic["state"] = "not_started"

    poc = finding.setdefault("poc", {})
    if isinstance(poc, dict):
        poc["result"] = "pending"
        poc["evidence"] = "静态代码审计阶段未执行动态验证，PoC 请求和响应留空。"

    return finding


def build_skeleton(template: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    data = infer_empty_value(template)
    if not isinstance(data, dict):
        raise SystemExit("[ERROR] template root must be a JSON object")

    today = date.today().isoformat()
    audit = data.setdefault("audit", {})
    target = audit.setdefault("target", {})
    auth_context = target.setdefault("auth_context", {})

    data["schema_version"] = template.get("schema_version", "3.0")
    data["chains"] = []
    data["findings"] = [build_static_finding_skeleton(template)]

    audit["audit_id"] = f"{args.agent_name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    audit["title"] = args.title
    audit["repository"] = args.repository
    audit["stage"] = "static_audit"
    audit["mode"] = args.mode
    audit["scope"] = args.scope
    audit["language"] = normalize_languages(args.language)
    audit["tool_versions"] = {}
    audit["audit_date"] = {"start": today, "end": today}
    audit["summary"] = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "confirmed": 0,
        "hypothesis": 0,
        "runtime_verified": 0,
        "code_only": 0,
        "open": 0,
        "unverified": 0,
        "by_severity_status": {
            "high": {"confirmed": 0, "hypothesis": 0},
            "medium": {"confirmed": 0, "hypothesis": 0},
        },
        "by_type": infer_empty_value(((template.get("audit") or {}).get("summary") or {}).get("by_type") or {}),
    }

    target["source_path"] = args.source_path
    target["base_url"] = args.base_url
    target["environment"] = "unknown"
    auth_context["required"] = False
    auth_context["credential_source"] = "unknown"
    auth_context["roles"] = []

    return data


def main() -> int:
    args = parse_args()
    template_path = Path(args.template).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_path = output_dir / f"agent-{args.agent_name}.json"

    if output_path.exists() and not args.force:
        raise SystemExit(f"[ERROR] output already exists: {output_path}. Use --force to overwrite.")

    template_data = load_json(template_path)
    if not isinstance(template_data, dict):
        raise SystemExit(f"[ERROR] template root must be an object: {template_path}")

    skeleton = build_skeleton(template_data, args)
    save_json(output_path, skeleton)

    print(f"template={template_path}")
    print(f"output={output_path}")
    print("stage=static_audit")
    print(f"findings={len(skeleton.get('findings') or [])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
