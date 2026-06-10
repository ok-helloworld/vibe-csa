#!/usr/bin/env python3
"""
Install the 8 bundled sub-agent markdown definitions into an agent platform folder.

Default provider mapping:
    - <provider> -> <project_root>/.<provider>/agents

Examples:
    python scripts/install_sub_agents.py --provider trae
    python scripts/install_sub_agents.py --provider codex --project-root D:/demo/app
    python scripts/install_sub_agents.py --provider claude --force
    python scripts/install_sub_agents.py --dest-dir D:/demo/app/.custom/agents
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

SUB_AGENT_FILES = [
    "static-code-map.md",
    "dynamic-verifier.md",
    "static-auth.md",
    "static-deser.md",
    "static-file-ssrf.md",
    "static-info.md",
    "static-injection.md",
    "static-logic.md",
]

def resolve_skill_root() -> Path:
    return Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="将内置的 7 个 sub-agent 定义复制到智能体软件的 Agent 创建目录。"
    )
    parser.add_argument(
        "--provider",
        help="目标智能体软件类型，如 trae、qoder、codex、claude；未提供时必须使用 --dest-dir。",
    )
    parser.add_argument(
        "--project-root",
        default=".",
        help="目标项目根目录。默认当前工作目录。",
    )
    parser.add_argument(
        "--dest-dir",
        help="自定义目标目录；提供后优先于 --provider 计算出的默认目录。",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="若目标文件已存在则覆盖。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅显示将要复制的内容，不实际写入。",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 输出结果，便于脚本调用。",
    )
    return parser


def ensure_source_dir(skill_root: Path) -> Path:
    source_dir = skill_root / "references" / "sub_agents"
    if not source_dir.is_dir():
        raise RuntimeError(f"sub-agent 源目录不存在: {source_dir}")

    missing = [name for name in SUB_AGENT_FILES if not (source_dir / name).is_file()]
    if missing:
        raise RuntimeError(
            "sub-agent 源文件缺失: " + ", ".join(missing)
        )
    return source_dir


def resolve_dest_dir(args: argparse.Namespace, project_root: Path) -> Path:
    if args.dest_dir:
        return Path(args.dest_dir).resolve()

    if not args.provider:
        raise RuntimeError("必须提供 --provider 或 --dest-dir 其中之一。")

    provider = str(args.provider).strip()
    if not provider:
        raise RuntimeError("--provider 不能为空。")
    return (project_root / f".{provider}" / "agents").resolve()


def copy_sub_agents(
    source_dir: Path,
    dest_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, object]:
    copied: list[str] = []
    skipped: list[str] = []

    if not dry_run:
        dest_dir.mkdir(parents=True, exist_ok=True)

    for name in SUB_AGENT_FILES:
        src = source_dir / name
        dst = dest_dir / name

        if dst.exists() and not force:
            skipped.append(name)
            continue

        if not dry_run:
            shutil.copy2(src, dst)
        copied.append(name)

    return {
        "source_dir": str(source_dir),
        "dest_dir": str(dest_dir),
        "copied": copied,
        "skipped": skipped,
        "total": len(SUB_AGENT_FILES),
    }


def emit_result(result: dict[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print(f"源目录: {result['source_dir']}")
    print(f"目标目录: {result['dest_dir']}")
    print(f"复制成功: {len(result['copied'])}/{result['total']}")
    if result["copied"]:
        print("已复制: " + ", ".join(result["copied"]))
    if result["skipped"]:
        print("已跳过(目标已存在，未使用 --force): " + ", ".join(result["skipped"]))


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        skill_root = resolve_skill_root()
        project_root = Path(args.project_root).resolve()
        source_dir = ensure_source_dir(skill_root)
        dest_dir = resolve_dest_dir(args, project_root)
        result = copy_sub_agents(
            source_dir=source_dir,
            dest_dir=dest_dir,
            force=args.force,
            dry_run=args.dry_run,
        )
        result["provider"] = args.provider
        result["dry_run"] = args.dry_run
        emit_result(result, as_json=args.json)
        return 0
    except Exception as exc:  # pragma: no cover - CLI fallback
        error_result = {"ok": False, "error": str(exc)}
        if args.json:
            print(json.dumps(error_result, ensure_ascii=False, indent=2))
        else:
            print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
