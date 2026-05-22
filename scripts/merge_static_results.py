#!/usr/bin/env python3
"""Merge Stage 1 multi-agent static audit JSON files into one strict v3 draft."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

try:
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
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
VALID_CATEGORIES = {
    "injection",
    "auth",
    "ssrf_file",
    "deserialization",
    "business_logic",
    "info_crypto",
    "dependency",
    "configuration",
    "other",
}


def load_json_files(input_dir: Path) -> list[tuple[Path, dict]]:
    files = sorted(input_dir.glob("*.json"))
    out: list[tuple[Path, dict]] = []
    for path in files:
        try:
            out.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"[ERROR] invalid JSON: {path}: {exc}") from exc
    return out


def default_audit(source_path: str, target_url: str, mode: str, language: list[str]) -> dict:
    today = date.today().isoformat()
    return {
        "audit_id": datetime.now().strftime("%Y%m%d-%H%M%S"),
        "title": "vibe-csa 代码安全审计",
        "repository": "",
        "target": {
            "source_path": source_path,
            "base_url": target_url,
            "environment": "unknown",
            "auth_context": {
                "required": False,
                "credential_source": "unknown",
                "roles": [],
            },
        },
        "stage": "static_audit",
        "mode": mode,
        "scope": "full",
        "tool_versions": {},
        "coverage_summary": {},
        "audit_date": {"start": today, "end": today},
        "language": language or ["unknown"],
        "summary": {},
    }


def normalize_text_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    return []


def normalize_multiline_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        items = []
        for raw_line in value.replace("\r", "\n").split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("-"):
                line = line[1:].strip()
            if len(line) > 2 and line[0].isdigit() and line[1] in {".", "、"}:
                line = line[2:].strip()
            items.append(line)
        return items
    return []


def safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_confidence(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in CONFIDENCE_ORDER:
        return text
    if text.endswith("%"):
        text = text[:-1].strip()
    try:
        score = float(text)
        if score > 1:
            score /= 100.0
        if score >= 0.8:
            return "high"
        if score >= 0.5:
            return "medium"
        return "low"
    except ValueError:
        return "medium"


def normalize_category(value: Any, vuln_type: str) -> str:
    text = str(value or "").strip().lower()
    if text in VALID_CATEGORIES:
        return text
    vt = vuln_type.strip().lower()
    aliases = {
        "authentication_bypass": "auth",
        "csrf": "auth",
        "idor": "auth",
        "session_fixation": "auth",
        "sql injection": "injection",
        "sqli": "injection",
        "command injection": "injection",
        "xss": "injection",
        "stored xss": "injection",
        "file_upload": "ssrf_file",
        "path traversal": "ssrf_file",
        "lfi": "ssrf_file",
        "ssrf": "ssrf_file",
        "deserialization": "deserialization",
        "insecure_password_storage": "info_crypto",
        "business_logic": "business_logic",
        "dependency": "dependency",
        "configuration": "configuration",
    }
    return aliases.get(text or vt, "other")


def normalize_cwe(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    if not text:
        return None
    if text.startswith("CWE-") and text[4:].isdigit():
        return text
    digits = "".join(ch for ch in text if ch.isdigit())
    return f"CWE-{digits}" if digits else None


def normalize_cve(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    if not text:
        return None
    if text.startswith("CVE-"):
        return text
    parts = [part for part in text.replace("_", "-").split("-") if part]
    if len(parts) >= 2 and parts[0].isdigit() and "".join(parts[1:]).isdigit():
        return f"CVE-{parts[0]}-{''.join(parts[1:])}"
    return None


def normalize_location(raw: dict) -> dict:
    location = raw.get("location")
    if not isinstance(location, dict):
        location = {}
    snippet = (
        location.get("snippet")
        or location.get("code_snippet")
        or raw.get("snippet")
        or raw.get("code_snippet")
        or "(no snippet)"
    )
    normalized = {
        "file": str(location.get("file") or raw.get("file") or "unknown"),
        "line_start": max(1, safe_int(location.get("line_start", location.get("line", raw.get("line", 1))), 1)),
        "snippet": str(snippet),
    }
    if location.get("line_end") is not None:
        normalized["line_end"] = max(normalized["line_start"], safe_int(location.get("line_end"), normalized["line_start"]))
    if location.get("function"):
        normalized["function"] = str(location.get("function"))
    if location.get("route"):
        normalized["route"] = str(location.get("route"))
    if location.get("http_method"):
        normalized["http_method"] = str(location.get("http_method"))
    return normalized


def normalize_data_flow(value: Any) -> list[dict]:
    items = value if isinstance(value, list) else normalize_multiline_list(value)
    normalized = []
    for index, item in enumerate(items, start=1):
        if isinstance(item, dict):
            normalized.append({
                "step": max(1, safe_int(item.get("step"), index)),
                "type": item.get("type") if item.get("type") in {"source", "propagation", "validation", "sink"} else "propagation",
                "location": str(item.get("location") or "unknown"),
                "desc": str(item.get("desc") or item.get("description") or ""),
                **({"code": str(item.get("code"))} if item.get("code") else {}),
            })
            continue
        text = str(item).strip()
        if not text:
            continue
        location, desc = ("unknown", text)
        if "->" in text:
            location, desc = [part.strip() for part in text.split("->", 1)]
        elif ":" in text:
            location, desc = [part.strip() for part in text.split(":", 1)]
        normalized.append({
            "step": index,
            "type": "source" if index == 1 else "propagation",
            "location": location or "unknown",
            "desc": desc or text,
        })
    if normalized:
        normalized[-1]["type"] = "sink"
    return normalized


def normalize_security_controls(value: Any) -> list[dict]:
    items = value if isinstance(value, list) else normalize_multiline_list(value)
    normalized = []
    for item in items:
        if isinstance(item, dict):
            normalized.append({
                "control": str(item.get("control") or item.get("name") or "unknown"),
                "location": str(item.get("location") or "unknown"),
                "assessment": item.get("assessment") if item.get("assessment") in {"missing", "present_bypassable", "present_effective", "unknown"} else "unknown",
                **({"bypass_notes": str(item.get("bypass_notes"))} if item.get("bypass_notes") else {}),
            })
            continue
        text = str(item).strip()
        if not text:
            continue
        normalized.append({"control": text, "location": "unknown", "assessment": "unknown"})
    return normalized


def normalize_bypass_strategy(value: Any, legacy_text: Any = None) -> dict:
    if isinstance(value, dict):
        ideas_raw = value.get("ideas")
        ideas = []
        for item in ideas_raw if isinstance(ideas_raw, list) else []:
            if isinstance(item, dict):
                ideas.append({
                    "technique": str(item.get("technique") or "legacy-note"),
                    "reason": str(item.get("reason") or item.get("payload_hint") or ""),
                    **({"payload_hint": str(item.get("payload_hint"))} if item.get("payload_hint") else {}),
                })
            else:
                text = str(item).strip()
                if text:
                    ideas.append({"technique": "legacy-note", "reason": text})
        return {
            "feasible": bool(ideas or legacy_text),
            "difficulty": value.get("difficulty") if value.get("difficulty") in {"none", "low", "medium", "high", "unknown"} else "unknown",
            "ideas": ideas,
        }
    text = str(value or legacy_text or "").strip()
    return {
        "feasible": bool(text),
        "difficulty": "unknown",
        "ideas": [{"technique": "legacy-note", "reason": text}] if text else [],
    }


def normalize_verification_plan(value: Any) -> dict:
    if isinstance(value, dict):
        steps = []
        for index, item in enumerate(value.get("steps") or [], start=1):
            if not isinstance(item, dict):
                continue
            steps.append({
                "step": max(1, safe_int(item.get("step"), index)),
                "action": str(item.get("action") or item.get("desc") or ""),
                "expected_signal": str(item.get("expected_signal") or item.get("signal") or ""),
            })
        return {
            "objective": str(value.get("objective") or "基于静态数据流构造 PoC 并获取 L2/L3 运行时证据。"),
            "steps": steps,
            "success_criteria": normalize_text_list(value.get("success_criteria")),
        }
    lines = normalize_multiline_list(value)
    return {
        "objective": lines[0] if lines else "基于静态数据流构造 PoC 并获取 L2/L3 运行时证据。",
        "steps": [{"step": index, "action": line, "expected_signal": ""} for index, line in enumerate(lines, start=1)],
        "success_criteria": [],
    }


def normalize_analysis(raw: dict, location: dict) -> dict:
    analysis = raw.get("analysis")
    if not isinstance(analysis, dict):
        analysis = {}
    source = analysis.get("source")
    sink = analysis.get("sink")
    attack_surface = analysis.get("attack_surface")
    return {
        "source": {
            "description": str(source.get("description") if isinstance(source, dict) else source or "待动态验证确认输入来源")
        },
        "sink": {
            "description": str(sink.get("description") if isinstance(sink, dict) else sink or "待动态验证确认危险汇点")
        },
        "data_flow": normalize_data_flow(analysis.get("data_flow") or raw.get("data_flow")),
        "attack_surface": {
            "entrypoint": str(
                attack_surface.get("entrypoint") if isinstance(attack_surface, dict) else attack_surface or location.get("route") or location["file"]
            )
        },
        "preconditions": normalize_text_list(analysis.get("preconditions")),
        "security_controls": normalize_security_controls(analysis.get("security_controls") or raw.get("controls_observed")),
        "bypass_strategy": normalize_bypass_strategy(analysis.get("bypass_strategy"), raw.get("bypass_potential")),
        "verification_plan": normalize_verification_plan(analysis.get("verification_plan")),
    }


def normalize_evidence_refs(value: Any) -> dict[str, str]:
    if isinstance(value, list):
        return {f"EVID-{i + 1:03d}": str(item) for i, item in enumerate(value)}
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if isinstance(value, str) and value.strip():
        return {"EVID-001": value}
    return {}


def normalize_reviewed_files(value: Any) -> list[dict]:
    items = value if isinstance(value, list) else []
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "related")
        normalized.append({
            "file": str(item.get("file") or "unknown"),
            "role": role if role in {"source", "propagation", "sink", "control", "entrypoint", "related"} else "related",
            "summary": str(item.get("summary") or ""),
        })
    return normalized


def normalize_static_evidence(raw: dict, agent_name: str) -> dict:
    static = raw.get("static_evidence")
    if not isinstance(static, dict):
        static = {}
    anti_fp = static.get("anti_false_positive")
    anti_fp_notes = anti_fp.get("notes") if isinstance(anti_fp, dict) else anti_fp
    anti_fp_checked = anti_fp.get("checked") if isinstance(anti_fp, dict) else []
    return {
        "agent": str(static.get("agent") or raw.get("agent") or agent_name),
        "confidence_reason": str(static.get("confidence_reason") or raw.get("confidence_reason") or "静态 Agent 发现。"),
        "evidence_refs": normalize_evidence_refs(static.get("evidence_refs") or raw.get("evidence_refs")),
        "reviewed_files": normalize_reviewed_files(static.get("reviewed_files")),
        "anti_false_positive": {
            "checked": normalize_text_list(anti_fp_checked),
            "notes": str(anti_fp_notes or "静态-only 阶段保持 HYPOTHESIS。"),
        },
    }


def normalize_remediation(raw: dict) -> dict:
    remediation = raw.get("remediation")
    if not isinstance(remediation, dict):
        remediation = {"short_term": remediation} if isinstance(remediation, str) else {}
    return {
        "short_term": str(remediation.get("short_term") or "根据漏洞类型增加输入校验、权限校验或安全 API 替换。"),
        "long_term": str(remediation.get("long_term") or "重构不可信输入到危险汇点的数据流，并增加回归测试。"),
    }


def normalize_fix(raw: dict, snippet: str) -> dict:
    fix = raw.get("fix")
    if not isinstance(fix, dict):
        fix = {}
    return {
        "language": str(fix.get("language") or "text"),
        "before": str(fix.get("before") or snippet),
        "after": str(fix.get("after") or ""),
    }


def collect_extension_fields(raw: dict) -> dict:
    extensions = {}
    for key, value in raw.items():
        if key.startswith("x_") and key not in {"x_finding_class", "x_legacy_fields"}:
            extensions[key] = value
    return extensions


def collect_legacy_fields(raw: dict) -> dict:
    known = {
        "vuln_id", "id", "title", "type", "vuln_type", "category", "severity", "status",
        "confidence", "evidence_level", "finding_class", "x_finding_class", "dktss_score",
        "description", "summary", "impact", "file", "line", "snippet", "code_snippet",
        "location", "analysis", "data_flow", "controls_observed", "bypass_potential",
        "static_evidence", "dynamic_verification", "poc", "tracking_completeness",
        "remediation", "fix", "cwe", "cve", "agent", "confidence_reason", "evidence_refs",
        "related_findings", "attack_path",
    }
    legacy = {}
    for key, value in raw.items():
        if key in known or key.startswith("x_"):
            continue
        legacy[key] = value
    return legacy


def merge_audit(base: dict, incoming: dict) -> dict:
    audit = incoming.get("audit") or {}
    if audit.get("title") and base.get("title") == "vibe-csa 代码安全审计":
        base["title"] = audit["title"]
    for key in ("repository", "scope"):
        if audit.get(key) and not base.get(key):
            base[key] = audit[key]
    if audit.get("language"):
        langs = base.setdefault("language", [])
        for lang in audit["language"] if isinstance(audit["language"], list) else [audit["language"]]:
            if lang not in langs:
                langs.append(lang)
    if audit.get("tool_versions"):
        base.setdefault("tool_versions", {}).update(audit["tool_versions"])
    if audit.get("coverage_summary"):
        base.setdefault("coverage_summary", {}).update(audit["coverage_summary"])
    return base


def normalize_static_finding(finding: dict, agent_name: str, index: int) -> dict:
    raw = dict(finding)
    vuln_id = str(raw.get("vuln_id") or raw.get("id") or f"FINDING-{index:03d}")
    vuln_type = str(raw.get("vuln_type") or raw.get("type") or "other")
    severity = str(raw.get("severity") or "medium").strip().lower()
    if severity not in SEVERITY_ORDER:
        severity = "medium"
    location = normalize_location(raw)
    normalized = {
        "vuln_id": vuln_id,
        "title": str(raw.get("title") or vuln_type or vuln_id),
        "vuln_type": vuln_type,
        "category": normalize_category(raw.get("category"), vuln_type),
        "severity": severity,
        "status": "HYPOTHESIS",
        "confidence": normalize_confidence(raw.get("confidence")),
        "evidence_level": "L0",
        "finding_class": "code_only",
        "x_finding_class": "code_only",
        "dktss_score": raw.get("dktss_score") if isinstance(raw.get("dktss_score"), (int, float)) else {"critical": 8.5, "high": 6.5, "medium": 4.5, "low": 2.0}[severity],
        "description": str(raw.get("description") or raw.get("summary") or raw.get("title") or vuln_id),
        "location": location,
        "analysis": normalize_analysis(raw, location),
        "static_evidence": normalize_static_evidence(raw, agent_name),
        "dynamic_verification": {
            "state": "not_started",
            "attempts": [],
            "final_evidence": {"proof_type": "none", "summary": "", "snippets": []},
            "runtime_notes": "",
        },
        "poc": {
            "steps": [],
            "result": "pending",
            "evidence": "静态代码审计阶段未执行动态验证，PoC 请求和响应留空。",
            "failure_log": [],
        },
        "tracking_completeness": "PARTIAL",
        "remediation": normalize_remediation(raw),
        "fix": normalize_fix(raw, location["snippet"]),
    }
    normalized["impact"] = str(raw.get("impact") or "")
    cwe = normalize_cwe(raw.get("cwe"))
    if cwe:
        normalized["cwe"] = cwe
    cve = normalize_cve(raw.get("cve"))
    if cve:
        normalized["cve"] = cve
    if isinstance(raw.get("related_findings"), list):
        related = []
        for item in raw.get("related_findings") or []:
            if isinstance(item, dict) and item.get("vuln_id"):
                relation = str(item.get("relation") or "alternative")
                related.append({
                    "vuln_id": str(item["vuln_id"]),
                    "relation": relation if relation in {"depends_on", "escalates_to", "alternative", "duplicate_of", "same_root_cause"} else "alternative",
                    **({"note": str(item.get("note"))} if item.get("note") else {}),
                })
        if related:
            normalized["related_findings"] = related
    extensions = collect_extension_fields(raw)
    normalized.update(extensions)
    legacy = collect_legacy_fields(raw)
    if legacy:
        normalized["x_legacy_fields"] = legacy
    return normalized


def dedupe_key(finding: dict) -> tuple[str, int, str]:
    loc = finding.get("location") or {}
    return (str(loc.get("file", "")), safe_int(loc.get("line_start"), 1), str(finding.get("vuln_type", "")))


def better(a: dict, b: dict) -> dict:
    a_conf = CONFIDENCE_ORDER.get(a.get("confidence", "medium"), 1)
    b_conf = CONFIDENCE_ORDER.get(b.get("confidence", "medium"), 1)
    if b_conf < a_conf:
        primary, secondary = b, a
    else:
        primary, secondary = a, b
    merge_static_metadata(primary, secondary)
    return primary


def merge_static_metadata(primary: dict, secondary: dict) -> None:
    p_static = primary.setdefault("static_evidence", {})
    s_static = secondary.get("static_evidence") or {}
    p_static.setdefault("evidence_refs", {}).update(s_static.get("evidence_refs") or {})
    p_reviewed = p_static.setdefault("reviewed_files", [])
    for item in s_static.get("reviewed_files") or []:
        if item not in p_reviewed:
            p_reviewed.append(item)
    agents = {p_static.get("agent"), s_static.get("agent")}
    agents.discard(None)
    p_static["agent"] = ",".join(sorted(agents))
    p_afp = p_static.setdefault("anti_false_positive", {"checked": [], "notes": ""})
    s_afp = s_static.get("anti_false_positive") or {}
    for item in s_afp.get("checked") or []:
        if item not in p_afp["checked"]:
            p_afp["checked"].append(item)
    if s_afp.get("notes") and s_afp["notes"] not in p_afp.get("notes", ""):
        p_afp["notes"] = "；".join(part for part in [p_afp.get("notes", ""), s_afp["notes"]] if part)
    if secondary.get("x_legacy_fields"):
        primary.setdefault("x_legacy_fields", {}).update(secondary["x_legacy_fields"])


def compute_summary(audit: dict, findings: list[dict]) -> None:
    counts = {k: 0 for k in SEVERITY_ORDER}
    by_type: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] += 1
        vt = finding.get("vuln_type", "other")
        by_type[vt] = by_type.get(vt, 0) + 1
    audit["summary"] = {
        "total": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "confirmed": 0,
        "hypothesis": len(findings),
        "runtime_verified": 0,
        "code_only": len(findings),
        "open": 0,
        "unverified": len(findings),
        "by_severity_status": {sev: {"hypothesis": count} for sev, count in counts.items() if count},
        "by_type": by_type,
    }


def format_path(path: list[Any]) -> str:
    parts: list[str] = []
    for item in path:
        if isinstance(item, int):
            if parts:
                parts[-1] += f"[{item}]"
            else:
                parts.append(f"[{item}]")
        else:
            parts.append(str(item))
    return ".".join(parts) if parts else "(root)"


def validate_stage1_report(report: dict) -> tuple[list[dict], list[str]]:
    errors: list[dict] = []
    warnings: list[str] = []
    if not HAS_JSONSCHEMA:
        errors.append({"path": "", "message": "Missing dependency: pip install jsonschema"})
        return errors, warnings

    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    validator = Draft7Validator(schema)
    schema_errors = sorted(validator.iter_errors(report), key=lambda err: list(err.absolute_path))
    for err in schema_errors:
        errors.append({"path": format_path(list(err.absolute_path)), "message": err.message})

    biz_errors, biz_warnings = consistency_checks(report, mode="draft")
    for err in biz_errors:
        errors.append({"path": "(business-rule)", "message": err})
    warnings.extend(biz_warnings)

    text_issues = find_text_quality_issues(report)
    for issue in text_issues:
        errors.append({"path": issue["path"], "message": issue["message"]})
    return errors, warnings


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge vibe-csa Stage 1 agent JSON results")
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-path", default="")
    parser.add_argument("--target-url", default="")
    parser.add_argument("--mode", choices=("quick", "standard", "deep"), default="standard")
    parser.add_argument("--language", action="append", default=[])
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    items = load_json_files(input_dir)
    if not items:
        raise SystemExit(f"[ERROR] no JSON files found in {input_dir}")

    audit = default_audit(args.source_path, args.target_url, args.mode, args.language)
    findings_by_key: dict[tuple[str, int, str], dict] = {}
    next_index = 1

    for path, data in items:
        audit = merge_audit(audit, data)
        agent_name = data.get("agent") or path.stem
        for raw in data.get("findings") or []:
            if not isinstance(raw, dict):
                continue
            finding = normalize_static_finding(raw, str(agent_name), next_index)
            key = dedupe_key(finding)
            if key in findings_by_key:
                findings_by_key[key] = better(findings_by_key[key], finding)
            else:
                findings_by_key[key] = finding
                next_index += 1

    findings = sorted(
        findings_by_key.values(),
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "low"), 9), f.get("vuln_id", "")),
    )
    for idx, finding in enumerate(findings, start=1):
        finding["vuln_id"] = f"FINDING-{idx:03d}"

    compute_summary(audit, findings)
    report = {"schema_version": "3.0", "audit": audit, "chains": [], "findings": findings}

    errors, warnings = validate_stage1_report(report)
    if errors:
        print(json.dumps({"status": "FAIL", "errors": errors, "warnings": warnings}, indent=2, ensure_ascii=False))
        raise SystemExit(1)
    if warnings:
        print(json.dumps({"status": "PASS_WITH_WARNINGS", "warnings": warnings}, indent=2, ensure_ascii=False))

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[OK] merged {len(items)} agent file(s), findings={len(findings)}, output={output}")


if __name__ == "__main__":
    main()
