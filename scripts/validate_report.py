#!/usr/bin/env python3
"""Validate vibe-csa.json against the JSON Schema + business rules.

Usage:
    python validate_report.py [json_file] [--mode draft|final] [--strict|--lenient] [--verbose]

Modes:
    --mode final  (default) full business-rule enforcement
    --mode draft  relaxed: allow empty steps/failure_log during authoring

Flags:
    --lenient   skip business-rule checks; only validate JSON Schema
    --strict    same as --mode final (alias)
    --verbose   include schema field hints in error messages

Output (JSON to stdout):
    {"status": "PASS"}
    {"status": "PASS", "warnings": [...]}
    {"status": "FAIL", "errors": [{"path","message","hint?"}], "warnings"?: [...]}
"""

from __future__ import annotations

import argparse
import json
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from pathlib import Path

try:
    from jsonschema import Draft7Validator
except ImportError:
    print(json.dumps({
        "status": "FAIL",
        "errors": [{"path": "", "message": "Missing dependency: pip install jsonschema"}],
    }, ensure_ascii=False))
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _consistency import consistency_checks  # noqa: E402
from _utf8 import configure_utf8_runtime, find_text_quality_issues  # noqa: E402

configure_utf8_runtime()

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "vibe-csa-schema.json"


def extract_json(text: str) -> str:
    """Accept raw JSON, fenced JSON, or embedded JSON object."""
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        m = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
        if m:
            return m.group(1)
        m = re.search(r"(\{[\s\S]*\})", text)
        if m:
            return m.group(1)
    raise ValueError(
        "No valid JSON found. File must contain a JSON object or ```json fenced block."
    )


def format_path(path: list) -> str:
    parts: list[str] = []
    for p in path:
        if isinstance(p, int):
            if parts:
                parts[-1] += f"[{p}]"
            else:
                parts.append(f"[{p}]")
        else:
            parts.append(p)
    return ".".join(parts) if parts else "(root)"


def field_hint(error, schema: dict) -> str | None:
    """Best-effort field-level hint from the schema for verbose mode."""
    try:
        node = schema
        for p in error.absolute_path:
            if isinstance(p, int):
                node = node.get("items", {})
            else:
                node = (node.get("properties") or {}).get(p, {})
            if not node:
                return None
        bits = []
        if "type" in node:
            bits.append(f"expected type: {node['type']}")
        if "enum" in node:
            bits.append(f"allowed: {node['enum']}")
        if "minLength" in node:
            bits.append(f"min length: {node['minLength']}")
        if "minimum" in node:
            bits.append(f"min value: {node['minimum']}")
        if "pattern" in node:
            bits.append(f"pattern: {node['pattern']}")
        return "; ".join(bits) if bits else None
    except Exception:
        return None


def validate(json_file: str, mode: str, lenient: bool, verbose: bool) -> dict:
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    with open(json_file, encoding="utf-8") as f:
        raw = f.read()

    try:
        json_text = extract_json(raw)
        data = json.loads(json_text)
    except (json.JSONDecodeError, ValueError) as e:
        return {"status": "FAIL", "errors": [{"path": "", "message": str(e)}]}

    validator = Draft7Validator(schema)
    schema_errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))

    error_list: list[dict] = []
    for err in schema_errors:
        item = {
            "path": format_path(list(err.absolute_path)),
            "message": err.message,
        }
        if verbose:
            hint = field_hint(err, schema)
            if hint:
                item["hint"] = hint
        error_list.append(item)

    warnings: list[str] = []
    if not lenient:
        biz_errors, biz_warnings = consistency_checks(data, mode=mode)
        for e in biz_errors:
            error_list.append({"path": "(business-rule)", "message": e})
        warnings = biz_warnings

    text_issues = find_text_quality_issues(data)
    for issue in text_issues:
        error_list.append({"path": issue["path"], "message": issue["message"], "hint": issue["hint"]})

    if error_list:
        out: dict = {"status": "FAIL", "errors": error_list}
        if warnings:
            out["warnings"] = warnings
        return out
    return {"status": "PASS"} if not warnings else {"status": "PASS", "warnings": warnings}


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate vibe-csa.json")
    parser.add_argument("json_file", nargs="?", default="vibe-csa.json")
    parser.add_argument("--mode", choices=("draft", "final"), default="final",
                        help="business-rule strictness (default: final)")
    parser.add_argument("--strict", action="store_true",
                        help="alias for --mode final")
    parser.add_argument("--lenient", action="store_true",
                        help="skip business rules; only validate JSON Schema")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="include schema field hints in errors")
    args = parser.parse_args()

    if args.strict:
        args.mode = "final"

    if not Path(args.json_file).exists():
        print(json.dumps({
            "status": "FAIL",
            "errors": [{"path": "", "message": f"File not found: {args.json_file}"}],
        }, ensure_ascii=False))
        sys.exit(1)

    result = validate(args.json_file, args.mode, args.lenient, args.verbose)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result["status"] == "FAIL":
        sys.exit(1)


if __name__ == "__main__":
    main()
