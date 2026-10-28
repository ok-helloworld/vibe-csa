#!/usr/bin/env python3
"""Stage 1 contract gate for vibe-csa.

Fails the static stage when the merged report cannot prove its own conclusions:

  1. every exclusion (negative conclusion) carries source-level evidence;
  2. no contradiction between agents is left unresolved;
  3. every finding keeps the required analysis chain;
  4. (optional) every code-map entrypoint file was actually reviewed.

The coverage gate exists because "N agents ran" is not evidence of coverage:
a file only counts as reviewed when an agent recorded it explicitly.

Usage:
    python scripts/check_static_contracts.py \
        --merged workDir/static-merged.json \
        --agent-dir workDir/agent-results \
        --code-map workDir/agent-results/agent-static-code-map.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load(path: str | None) -> Any:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _reviewed_files_from_agents(agent_dir: str | None) -> set[str]:
    files: set[str] = set()
    if not agent_dir:
        return files
    for path in sorted(Path(agent_dir).glob("*.json")):
        data = _load(str(path))
        if not isinstance(data, dict):
            continue
        for finding in data.get("findings") or []:
            for entry in (finding.get("static_evidence") or {}).get("reviewed_files") or []:
                if isinstance(entry, dict) and entry.get("file"):
                    files.add(str(entry["file"]))
                elif isinstance(entry, str):
                    files.add(entry)
        summary = (data.get("audit") or {}).get("coverage_summary") or {}
        reviewed_summary = summary.get("reviewed_files")
        if not isinstance(reviewed_summary, list):
            reviewed_summary = []
        for entry in reviewed_summary:
            if isinstance(entry, dict) and entry.get("file"):
                files.add(str(entry["file"]))
            elif isinstance(entry, str):
                files.add(entry)
    return files


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _check_exclusions(report: dict) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if (report.get("findings") or []) and not (report.get("exclusions") or []):
        warnings.append("没有任何结构化负向结论（exclusions=[]）：请确认是否把所有被否证的候选都写进了说明文字而未结构化")

    for exclusion in report.get("exclusions") or []:
        eid = exclusion.get("exclusion_id") or "<unknown>"
        if not str(exclusion.get("reason") or "").strip():
            errors.append(f"{eid}: 缺少排除理由 reason")
        evidence = exclusion.get("evidence") or []
        usable = [
            e for e in evidence
            if isinstance(e, dict) and str(e.get("file") or "").strip() and _to_int(e.get("line")) > 0
        ]
        if not usable:
            errors.append(f"{eid}: 缺少源码级证据（evidence[].file + line），该排除不成立")
        if exclusion.get("verdict") not in {"not_vulnerable", "out_of_scope", "blocked"}:
            errors.append(f"{eid}: verdict 非法")
        if exclusion.get("verdict") == "blocked":
            warnings.append(f"{eid}: 标记为 blocked，报告中需体现未覆盖风险")
    return errors, warnings


def _check_contradictions(report: dict, allow_open: bool) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    for contradiction in report.get("contradictions") or []:
        cid = contradiction.get("contradiction_id") or "<unknown>"
        status = contradiction.get("status")
        if status == "open":
            message = f"{cid}: 跨 Agent 结论冲突未复验（{contradiction.get('topic', '')}）"
            if allow_open:
                warnings.append(message)
            else:
                errors.append(message)
        elif status == "resolved":
            if not str(contradiction.get("resolution") or "").strip():
                errors.append(f"{cid}: resolved 但缺少 resolution 说明")
    return errors, warnings


def _check_findings(report: dict) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    for finding in report.get("findings") or []:
        vid = finding.get("vuln_id") or "<unknown>"
        analysis = finding.get("analysis") or {}
        for field in ("source", "sink", "data_flow", "attack_surface", "verification_plan"):
            if not analysis.get(field):
                errors.append(f"{vid}: analysis.{field} 为空，不满足证据契约")
        if not (finding.get("location") or {}).get("file"):
            errors.append(f"{vid}: 缺少 location.file")
        if finding.get("status") == "CONFIRMED" and not (finding.get("poc") or {}).get("steps"):
            errors.append(f"{vid}: CONFIRMED 但缺少 poc.steps")
    return errors, warnings


def _check_coverage(report: dict, code_map: dict | None, agent_dir: str | None) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not code_map:
        warnings.append("未提供 code-map，跳过入口覆盖率门禁")
        return errors, warnings
    if not agent_dir:
        warnings.append("未提供 --agent-dir，无法验证 reviewed_files，跳过入口覆盖率门禁")
        return errors, warnings

    reviewed = _reviewed_files_from_agents(agent_dir)
    for finding in report.get("findings") or []:
        for entry in (finding.get("static_evidence") or {}).get("reviewed_files") or []:
            if isinstance(entry, dict) and entry.get("file"):
                reviewed.add(str(entry["file"]))

    entrypoints = code_map.get("entrypoints") or []
    if not entrypoints:
        warnings.append("code-map 中没有 entrypoints，覆盖率门禁无对象")
        return errors, warnings

    def _covers(source: str) -> bool:
        src = str(source).strip().lstrip("./")
        src_name = src.rsplit("/", 1)[-1]
        for item in reviewed:
            cand = str(item).strip().lstrip("./")
            if not cand:
                continue
            if cand == src or src.endswith("/" + cand) or cand.endswith("/" + src):
                return True
            if cand.rsplit("/", 1)[-1] == src_name:
                return True
        return False

    missing: list[str] = []
    for entrypoint in entrypoints:
        source = (entrypoint.get("source") or {}).get("file")
        if not source:
            continue
        if not _covers(source):
            missing.append(f"{entrypoint.get('id', '?')}:{source}")

    if missing:
        errors.append(
            f"入口覆盖率不足：{len(missing)}/{len(entrypoints)} 个入口文件没有 [REVIEWED] 凭证，"
            f"例如 {', '.join(missing[:5])}"
        )
    return errors, warnings


def main() -> None:
    parser = argparse.ArgumentParser(description="vibe-csa Stage 1 contract gate")
    parser.add_argument("--merged", required=True, help="workDir/static-merged.json")
    parser.add_argument("--agent-dir", default="", help="workDir/agent-results")
    parser.add_argument("--code-map", default="", help="agent-static-code-map.json")
    parser.add_argument("--allow-open-contradictions", action="store_true")
    parser.add_argument("--skip-coverage", action="store_true")
    args = parser.parse_args()

    report = _load(args.merged)
    if not isinstance(report, dict):
        print(json.dumps({"status": "FAIL", "errors": [f"无法读取或解析 {args.merged}"]}, ensure_ascii=False, indent=2))
        raise SystemExit(1)

    errors: list[str] = []
    warnings: list[str] = []

    for errs, warns in (
        _check_exclusions(report),
        _check_contradictions(report, args.allow_open_contradictions),
        _check_findings(report),
    ):
        errors.extend(errs)
        warnings.extend(warns)

    if not args.skip_coverage:
        errs, warns = _check_coverage(report, _load(args.code_map), args.agent_dir or None)
        errors.extend(errs)
        warnings.extend(warns)

    result = {
        "status": "FAIL" if errors else ("PASS_WITH_WARNINGS" if warnings else "PASS"),
        "counts": {
            "findings": len(report.get("findings") or []),
            "exclusions": len(report.get("exclusions") or []),
            "contradictions": len(report.get("contradictions") or []),
            "open_contradictions": sum(
                1 for c in report.get("contradictions") or [] if c.get("status") == "open"
            ),
        },
        "errors": errors,
        "warnings": warnings,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
