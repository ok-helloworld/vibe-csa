#!/usr/bin/env python3
"""Review duplicated findings in a merged Stage 1 report and rewrite the report."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from merge_static_results import (  # noqa: E402
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    compute_summary,
    safe_int,
    validate_stage1_report,
)


TITLE_NOISE_RE = re.compile(r"[^\w\u4e00-\u9fff]+", re.UNICODE)
ASCII_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")
CJK_RUN_RE = re.compile(r"[\u4e00-\u9fff]{2,}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dedupe repeated findings in workDir/static-merged.json and rewrite the report"
    )
    parser.add_argument("--input", required=True, help="Path to merged Stage 1 report JSON")
    parser.add_argument(
        "--output",
        help="Output path. Defaults to overwriting --input",
    )
    parser.add_argument(
        "--title-threshold",
        type=float,
        default=0.84,
        help="Similarity threshold for title-based duplicate review (default: 0.84)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Review duplicates and print summary without writing output",
    )
    return parser.parse_args()


def load_report(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"[ERROR] input file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[ERROR] invalid JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"[ERROR] expected top-level object in {path}")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise SystemExit(f"[ERROR] expected findings[] list in {path}")
    return data


def location_key(finding: dict[str, Any]) -> tuple[str, int, int]:
    location = finding.get("location") or {}
    line_start = max(1, safe_int(location.get("line_start"), 1))
    line_end = max(line_start, safe_int(location.get("line_end"), line_start))
    return (str(location.get("file") or ""), line_start, line_end)


def normalize_title_text(text: Any) -> str:
    value = str(text or "").strip().lower()
    value = TITLE_NOISE_RE.sub("", value)
    return value


def text_similarity(a: Any, b: Any) -> float:
    left = normalize_title_text(a)
    right = normalize_title_text(b)
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    shorter = min(len(left), len(right))
    if shorter >= 6 and (left in right or right in left):
        return 0.96
    return SequenceMatcher(None, left, right).ratio()


def root_cause_text(finding: dict[str, Any]) -> str:
    analysis = finding.get("analysis") or {}
    sink = analysis.get("sink") or {}
    parts = [
        finding.get("title"),
        finding.get("vuln_type"),
        finding.get("description"),
        sink.get("description"),
    ]
    return " ".join(str(part or "") for part in parts if str(part or "").strip())


def text_terms(text: Any) -> set[str]:
    raw = str(text or "").lower()
    terms = set(ASCII_TOKEN_RE.findall(raw))
    for run in CJK_RUN_RE.findall(raw):
        for index in range(len(run) - 1):
            terms.add(run[index : index + 2])
    return terms


def term_overlap_ratio(a: Any, b: Any) -> float:
    left = text_terms(a)
    right = text_terms(b)
    if not left or not right:
        return 0.0
    shared = left & right
    if len(shared) < 2:
        return 0.0
    return len(shared) / len(left | right)


def sink_signature(finding: dict[str, Any]) -> tuple[str, str]:
    analysis = finding.get("analysis") or {}
    sink = analysis.get("sink") or {}
    return (
        str(sink.get("location") or "").strip().lower(),
        str(sink.get("dangerous_api") or "").strip().lower(),
    )


def same_root_cause(a: dict[str, Any], b: dict[str, Any], threshold: float) -> bool:
    if location_key(a) != location_key(b):
        return False
    if text_similarity(a.get("title"), b.get("title")) >= threshold:
        return True
    if text_similarity(root_cause_text(a), root_cause_text(b)) >= max(0.72, threshold - 0.10):
        return True
    if term_overlap_ratio(root_cause_text(a), root_cause_text(b)) >= 0.18:
        return True
    sink_a = sink_signature(a)
    sink_b = sink_signature(b)
    if sink_a == sink_b and any(sink_a):
        return True
    return False


def union(parent: list[int], left: int, right: int) -> None:
    left_root = find(parent, left)
    right_root = find(parent, right)
    if left_root != right_root:
        parent[right_root] = left_root


def find(parent: list[int], index: int) -> int:
    while parent[index] != index:
        parent[index] = parent[parent[index]]
        index = parent[index]
    return index


def pick_primary(cluster: list[dict[str, Any]]) -> dict[str, Any]:
    def rank(finding: dict[str, Any]) -> tuple[int, int, int, int, int, int]:
        static = finding.get("static_evidence") or {}
        evidence_refs = static.get("evidence_refs") or {}
        reviewed_files = static.get("reviewed_files") or []
        anti_fp = (static.get("anti_false_positive") or {}).get("checked") or []
        fix = finding.get("fix") or {}
        detail_score = len(evidence_refs) + len(reviewed_files) + len(anti_fp)
        description_score = min(len(str(finding.get("description") or "").strip()), 600)
        impact_score = min(len(str(finding.get("impact") or "").strip()), 300)
        has_fix = 1 if any(str(fix.get(key) or "").strip() for key in ("before", "after")) else 0
        confidence_score = 2 - CONFIDENCE_ORDER.get(str(finding.get("confidence") or "medium"), 1)
        severity_score = 10 - SEVERITY_ORDER.get(str(finding.get("severity") or "low"), 9)
        return (confidence_score, severity_score, detail_score, description_score, impact_score, has_fix)

    return max(cluster, key=rank)


def dedupe_related_findings(
    finding: dict[str, Any],
    replacement_map: dict[str, str],
    existing_ids: set[str],
) -> None:
    updated: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    current_id = str(finding.get("vuln_id") or "")
    for item in finding.get("related_findings") or []:
        if not isinstance(item, dict):
            continue
        target = str(item.get("vuln_id") or "")
        if not target:
            continue
        target = replacement_map.get(target, target)
        if not target or target == current_id or target not in existing_ids:
            continue
        relation = str(item.get("relation") or "alternative")
        note = str(item.get("note") or "")
        marker = (target, relation, note)
        if marker in seen:
            continue
        seen.add(marker)
        new_item = {"vuln_id": target, "relation": relation}
        if note:
            new_item["note"] = note
        updated.append(new_item)
    if updated:
        finding["related_findings"] = updated
    elif "related_findings" in finding:
        del finding["related_findings"]


def review_duplicates(
    findings: list[dict[str, Any]],
    threshold: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    groups: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
    for finding in findings:
        groups.setdefault(location_key(finding), []).append(finding)

    kept: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    replacement_map: dict[str, str] = {}

    for items in groups.values():
        if len(items) == 1:
            kept.extend(items)
            continue

        parent = list(range(len(items)))
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                if same_root_cause(items[i], items[j], threshold):
                    union(parent, i, j)

        clusters: dict[int, list[dict[str, Any]]] = {}
        for index, finding in enumerate(items):
            clusters.setdefault(find(parent, index), []).append(finding)

        for cluster in clusters.values():
            if len(cluster) == 1:
                kept.extend(cluster)
                continue
            primary = pick_primary(cluster)
            kept.append(primary)
            primary_id = str(primary.get("vuln_id") or "")
            for duplicate in cluster:
                if duplicate is primary:
                    continue
                duplicate_id = str(duplicate.get("vuln_id") or "")
                if duplicate_id:
                    replacement_map[duplicate_id] = primary_id
                removed.append(duplicate)

    return kept, removed, replacement_map


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(finding: dict[str, Any]) -> tuple[int, str, int, int, str]:
        location = finding.get("location") or {}
        return (
            SEVERITY_ORDER.get(str(finding.get("severity") or "low"), 9),
            str(location.get("file") or ""),
            safe_int(location.get("line_start"), 1),
            safe_int(location.get("line_end"), safe_int(location.get("line_start"), 1)),
            str(finding.get("vuln_id") or ""),
        )

    return sorted(findings, key=sort_key)


def renumber_findings(findings: list[dict[str, Any]], replacement_map: dict[str, str]) -> None:
    old_to_new: dict[str, str] = {}
    for index, finding in enumerate(findings, start=1):
        old_id = str(finding.get("vuln_id") or "")
        new_id = f"FINDING-{index:03d}"
        finding["vuln_id"] = new_id
        if old_id:
            old_to_new[old_id] = new_id

    for old_id, target_id in list(replacement_map.items()):
        replacement_map[old_id] = old_to_new.get(target_id, target_id)

    existing_ids = {str(finding.get("vuln_id") or "") for finding in findings}
    for finding in findings:
        dedupe_related_findings(finding, {**old_to_new, **replacement_map}, existing_ids)


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path
    backup_path = input_path.with_name("static-dedupe-bak.json")

    report = load_report(input_path)
    findings = [item for item in report.get("findings", []) if isinstance(item, dict)]
    kept, removed, replacement_map = review_duplicates(findings, args.title_threshold)
    kept = sort_findings(kept)
    renumber_findings(kept, replacement_map)

    audit = report.get("audit")
    if not isinstance(audit, dict):
        audit = {}
        report["audit"] = audit
    compute_summary(audit, kept)
    report["findings"] = kept
    if not isinstance(report.get("chains"), list):
        report["chains"] = []

    errors, warnings = validate_stage1_report(report)
    if errors and all(err.get("message", "").startswith("Missing dependency: pip install jsonschema") for err in errors):
        warnings = [*warnings, "jsonschema 未安装：已跳过 schema 校验，仅完成去重与结构重写"]
        errors = []
    summary = {
        "status": "PASS" if not errors else "FAIL",
        "input": str(input_path),
        "output": str(output_path),
        "original_findings": len(findings),
        "removed_duplicates": len(removed),
        "final_findings": len(kept),
        "replacements": replacement_map,
        "warnings": warnings,
        "errors": errors,
    }

    if args.dry_run:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        raise SystemExit(0 if not errors else 1)

    if errors:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        raise SystemExit(1)

    shutil.copy2(input_path, backup_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary["backup"] = str(backup_path)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
