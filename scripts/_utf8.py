from __future__ import annotations

import os
import re
import sys
from typing import Any


TEXT_FIELD_KEYS = {
    "title",
    "vuln_type",
    "description",
    "impact",
    "desc",
    "control",
    "bypass_notes",
    "reason",
    "objective",
    "action",
    "expected_signal",
    "confidence_reason",
    "summary",
    "note",
    "notes",
    "short_term",
    "long_term",
    "payload_strategy",
    "runtime_notes",
    "evidence",
    "x_category_label",
    "name",
    "type",
    "status",
    "purpose",
    "message",
}

QUESTION_RUN_RE = re.compile(r"\?{3,}")
PLACEHOLDER_HINTS = {"TODO", "TBD", "PLACEHOLDER", "<TODO>", "REPLACE_ME"}


def configure_utf8_runtime() -> None:
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8:replace")
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _format_path(path: tuple[Any, ...]) -> str:
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


def _should_inspect_path(path: tuple[Any, ...]) -> bool:
    return any(isinstance(item, str) and item in TEXT_FIELD_KEYS for item in path)


def _is_placeholder_only_text(text: str) -> bool:
    normalized = text.strip().upper()
    return normalized in PLACEHOLDER_HINTS


def _is_question_placeholder_text(text: str) -> bool:
    if not QUESTION_RUN_RE.search(text):
        return False
    return not any(char.isalnum() for char in text)


def _is_suspicious_text(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if "\ufffd" in text:
        return True
    if _is_question_placeholder_text(text):
        return True
    if _is_placeholder_only_text(text):
        return True
    return False


def find_text_quality_issues(data: Any, root: str | None = None) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []

    def walk(node: Any, path: tuple[Any, ...]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                new_path = path + (key,)
                if isinstance(value, str):
                    if _should_inspect_path(new_path) and _is_suspicious_text(value):
                        issues.append({
                            "path": _format_path(new_path),
                            "message": "Suspicious placeholder text detected",
                            "hint": "Keep all human-readable fields in UTF-8 and avoid placeholder substitution.",
                        })
                else:
                    walk(value, new_path)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                new_path = path + (index,)
                if isinstance(value, str):
                    if _should_inspect_path(path) and _is_suspicious_text(value):
                        issues.append({
                            "path": _format_path(new_path),
                            "message": "Suspicious placeholder text detected",
                            "hint": "Keep all human-readable fields in UTF-8 and avoid placeholder substitution.",
                        })
                else:
                    walk(value, new_path)

    walk(data, (root,) if root else ())
    return issues
