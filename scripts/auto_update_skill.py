#!/usr/bin/env python3
"""
Quick, non-blocking Git updater for the Vibe CSA skill repository.

Goals:
  - Work on Windows / Linux / macOS using only the Python standard library
  - Avoid hanging on network/auth prompts
  - Skip updates gracefully when Git status cannot be determined
  - If a pull creates merge conflicts, resolve only the conflicted files by
    taking the remote version ("theirs"), then finish the merge

Usage:
    python scripts/auto_update_skill.py
    python scripts/auto_update_skill.py /path/to/vibe-csa
    python scripts/auto_update_skill.py --timeout 5 --pull-timeout 10 --json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

DEFAULT_TIMEOUT = 5
DEFAULT_PULL_TIMEOUT = 10
MERGE_COMMIT_MESSAGE = "Auto-resolve skill update conflicts using remote versions"


class GitCommandError(RuntimeError):
    """Raised when a Git command fails."""

    def __init__(self, args: list[str], returncode: int, stdout: str, stderr: str):
        self.args_list = args
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        message = stderr.strip() or stdout.strip() or f"git command failed: {' '.join(args)}"
        super().__init__(message)


class GitTimeoutError(RuntimeError):
    """Raised when a Git command times out."""

    def __init__(self, args: list[str], timeout: int):
        self.args_list = args
        self.timeout = timeout
        super().__init__(f"git command timed out after {timeout}s: {' '.join(args)}")


def emit(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(message)


def build_git_env() -> dict[str, str]:
    env = os.environ.copy()
    # Disable interactive credential prompts so the script never blocks.
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "Never"
    env.setdefault("GIT_ASKPASS", "")
    return env


def run_git(
    repo_root: Path,
    git_args: list[str],
    timeout: int,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            ["git", *git_args],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=build_git_env(),
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git 不可用或未安装") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitTimeoutError(["git", *git_args], timeout) from exc

    if check and completed.returncode != 0:
        raise GitCommandError(["git", *git_args], completed.returncode, completed.stdout, completed.stderr)
    return completed


def resolve_start_path(path_arg: str | None) -> Path:
    if path_arg:
        return Path(path_arg).resolve()
    return Path(__file__).resolve().parent.parent


def ensure_repo(repo_root: Path, timeout: int) -> Path:
    if not repo_root.exists():
        raise RuntimeError(f"目标路径不存在: {repo_root}")

    run_git(repo_root, ["rev-parse", "--is-inside-work-tree"], timeout=timeout)
    top_level = run_git(
        repo_root,
        ["rev-parse", "--show-toplevel"],
        timeout=timeout,
    ).stdout.strip()
    return Path(top_level).resolve()


def get_current_branch(repo_root: Path, timeout: int) -> str | None:
    completed = run_git(
        repo_root,
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        timeout=timeout,
        check=False,
    )
    branch = completed.stdout.strip()
    return branch or None


def get_upstream_branch(repo_root: Path, timeout: int) -> str | None:
    completed = run_git(
        repo_root,
        ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        timeout=timeout,
        check=False,
    )
    upstream = completed.stdout.strip()
    return upstream or None


def get_ahead_behind(repo_root: Path, timeout: int) -> tuple[int, int]:
    completed = run_git(
        repo_root,
        ["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
        timeout=timeout,
    )
    parts = completed.stdout.strip().split()
    if len(parts) != 2:
        raise RuntimeError(f"无法解析 ahead/behind 状态: {completed.stdout!r}")
    ahead, behind = (int(parts[0]), int(parts[1]))
    return ahead, behind


def list_unmerged_files(repo_root: Path, timeout: int) -> list[str]:
    completed = run_git(
        repo_root,
        ["diff", "--name-only", "--diff-filter=U"],
        timeout=timeout,
        check=False,
    )
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def resolve_conflicts_with_remote(repo_root: Path, timeout: int, quiet: bool) -> list[str]:
    conflicted_files = list_unmerged_files(repo_root, timeout)
    if not conflicted_files:
        return []

    emit(f"[*] 检测到 {len(conflicted_files)} 个冲突文件，按远端版本覆盖", quiet)
    for rel_path in conflicted_files:
        run_git(repo_root, ["checkout", "--theirs", "--", rel_path], timeout=timeout)
        run_git(repo_root, ["add", "--", rel_path], timeout=timeout)
    run_git(repo_root, ["commit", "-m", MERGE_COMMIT_MESSAGE], timeout=timeout)
    return conflicted_files


def fast_status(repo_root: Path, timeout: int, quiet: bool) -> str:
    completed = run_git(
        repo_root,
        ["status", "-sb"],
        timeout=timeout,
        check=False,
    )
    status_text = completed.stdout.strip()
    if status_text:
        first_line = status_text.splitlines()[0]
        emit(f"[*] 当前状态: {first_line}", quiet)
    return status_text


def make_result(
    repo_root: Path,
    branch: str | None,
    upstream: str | None,
    *,
    status: str,
    reason: str,
    ahead: int | None = None,
    behind: int | None = None,
    updated: bool = False,
    conflicts_resolved: list[str] | None = None,
    detail: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "status": status,
        "reason": reason,
        "updated": updated,
        "repo_root": str(repo_root),
        "branch": branch,
        "upstream": upstream,
        "ahead": ahead,
        "behind": behind,
        "conflicts_resolved": conflicts_resolved or [],
    }
    if detail:
        result["detail"] = detail
    return result


def auto_update_skill(
    repo_root: Path,
    timeout: int,
    pull_timeout: int,
    quiet: bool,
) -> dict[str, object]:
    repo_root = ensure_repo(repo_root, timeout)
    branch = get_current_branch(repo_root, timeout)
    upstream = get_upstream_branch(repo_root, timeout)

    if not branch:
        return make_result(
            repo_root,
            branch,
            upstream,
            status="skipped",
            reason="detached_head",
            detail="当前不在普通分支上，跳过自动更新",
        )

    if not upstream:
        return make_result(
            repo_root,
            branch,
            upstream,
            status="skipped",
            reason="no_upstream",
            detail="当前分支未配置上游分支，跳过自动更新",
        )

    emit(f"[*] 仓库: {repo_root}", quiet)
    emit(f"[*] 分支: {branch} -> {upstream}", quiet)
    emit("[*] 执行快速 fetch 检查远端状态", quiet)
    run_git(repo_root, ["fetch", "--quiet", "--prune"], timeout=timeout)

    ahead, behind = get_ahead_behind(repo_root, timeout)
    fast_status(repo_root, timeout, quiet)

    if behind == 0:
        reason = "already_latest" if ahead == 0 else "local_ahead_only"
        detail = "当前仓库已是最新状态" if ahead == 0 else "本地分支领先远端，无需自动拉取"
        return make_result(
            repo_root,
            branch,
            upstream,
            status="ok",
            reason=reason,
            ahead=ahead,
            behind=behind,
            updated=False,
            detail=detail,
        )

    emit(f"[*] 检测到远端领先 {behind} 个提交，开始拉取更新", quiet)
    pull_args = ["pull", "--no-rebase", "--autostash"]
    try:
        run_git(repo_root, pull_args, timeout=pull_timeout)
        return make_result(
            repo_root,
            branch,
            upstream,
            status="ok",
            reason="updated",
            ahead=ahead,
            behind=behind,
            updated=True,
            detail="已成功拉取远端更新",
        )
    except GitCommandError as exc:
        conflicted_files = resolve_conflicts_with_remote(repo_root, timeout, quiet)
        if conflicted_files:
            return make_result(
                repo_root,
                branch,
                upstream,
                status="ok",
                reason="updated_with_conflict_resolution",
                ahead=ahead,
                behind=behind,
                updated=True,
                conflicts_resolved=conflicted_files,
                detail="拉取过程中出现冲突，已将冲突文件切换为远端版本并完成合并",
            )
        return make_result(
            repo_root,
            branch,
            upstream,
            status="skipped",
            reason="pull_failed",
            ahead=ahead,
            behind=behind,
            updated=False,
            detail=exc.stderr.strip() or exc.stdout.strip() or str(exc),
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="快速、非阻塞地检查并更新当前 skill 仓库。",
    )
    parser.add_argument(
        "skill_root",
        nargs="?",
        help="skill 根目录；不传时默认使用脚本上级目录的上一级目录。",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"普通 Git 操作超时时间（秒），默认 {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--pull-timeout",
        type=int,
        default=DEFAULT_PULL_TIMEOUT,
        help=f"git pull 超时时间（秒），默认 {DEFAULT_PULL_TIMEOUT}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="输出 JSON 结果，便于工作流或其他脚本解析。",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="安静模式，只输出最终结果。",
    )
    return parser.parse_args(argv)


def print_result(result: dict[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print(f"[{result['status']}] {result['reason']}")
    detail = result.get("detail")
    if detail:
        print(detail)
    if result.get("conflicts_resolved"):
        print("冲突文件:")
        for rel_path in result["conflicts_resolved"]:
            print(f"  - {rel_path}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = resolve_start_path(args.skill_root)

    result: dict[str, object]
    try:
        result = auto_update_skill(
            repo_root=repo_root,
            timeout=max(1, args.timeout),
            pull_timeout=max(1, args.pull_timeout),
            quiet=args.quiet,
        )
    except GitTimeoutError as exc:
        result = make_result(
            repo_root=repo_root,
            branch=None,
            upstream=None,
            status="skipped",
            reason="timeout",
            updated=False,
            detail=str(exc),
        )
    except RuntimeError as exc:
        result = make_result(
            repo_root=repo_root,
            branch=None,
            upstream=None,
            status="skipped",
            reason="environment_error",
            updated=False,
            detail=str(exc),
        )
    except Exception as exc:  # pragma: no cover - last-resort safety net
        result = make_result(
            repo_root=repo_root,
            branch=None,
            upstream=None,
            status="skipped",
            reason="unexpected_error",
            updated=False,
            detail=str(exc),
        )

    print_result(result, as_json=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
