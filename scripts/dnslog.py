#!/usr/bin/env python3
"""
DNSlog 工具 — 通过 dnslog.cn 实现 DNS 查询记录获取。
用于盲注、SSRF、XXE、命令注入等无回显漏洞验证。

用法:
    python dnslog.py get_domain              # 获取临时域名
    python dnslog.py get_records <domain>    # 查询DNS记录
    python dnslog.py get_records <domain> <wait_seconds>  # 等待后查询
"""

import sys
import requests
import json
import time
import os
import tempfile

BASE_URL = "http://dnslog.cn"
COOKIE_FILE = os.path.join(tempfile.gettempdir(), "dnslog_cookie.txt")


def load_cookie(session: requests.Session) -> None:
    """从临时文件加载 PHPSESSID Cookie 到 session 中。"""
    try:
        if os.path.exists(COOKIE_FILE):
            with open(COOKIE_FILE, "r") as f:
                for line in f:
                    if "PHPSESSID" in line:
                        session.cookies.set("PHPSESSID", line.strip().split("=")[1])
    except Exception:
        pass


def save_cookie(session: requests.Session) -> None:
    """将 session 中的 PHPSESSID Cookie 持久化到临时文件。"""
    try:
        with open(COOKIE_FILE, "w") as f:
            for cookie in session.cookies:
                f.write(f"{cookie.name}={cookie.value}\n")
    except Exception:
        pass


def get_domain(session: requests.Session) -> dict:
    """获取临时 DNS 域名。"""
    response = session.get(f"{BASE_URL}/getdomain.php", timeout=10)
    response.raise_for_status()
    domain = response.text.strip().rstrip("%")

    save_cookie(session)

    if not domain:
        return {"status": "error", "message": "未能获取到域名，请稍后重试"}

    return {
        "status": "success",
        "domain": domain,
        "message": f"成功获取临时域名: {domain}",
        "usage": (
            f"使用此域名进行 DNS 查询测试，例如: "
            f"nslookup {domain} 或 ping http://{domain}"
        ),
        "note": "域名有效期为 24 小时，请及时查询记录",
    }


def get_records(session: requests.Session, domain: str, wait_time: int = 0) -> dict:
    """查询指定域名的 DNS 查询记录。"""
    if wait_time > 0:
        print(f"等待 {wait_time} 秒后查询记录...", file=sys.stderr)
        time.sleep(wait_time)

    load_cookie(session)

    response = session.get(
        f"{BASE_URL}/getrecords.php", params={"t": domain}, timeout=10
    )
    response.raise_for_status()
    records_text = response.text.strip().rstrip("%")

    if not records_text or records_text == "[]" or not records_text.strip():
        return {
            "status": "no_records",
            "domain": domain,
            "records": [],
            "message": "暂无 DNS 查询记录，目标可能尚未触发 DNS 查询",
        }

    # 尝试 JSON 解析
    try:
        records = json.loads(records_text)
        if isinstance(records, list) and len(records) > 0:
            return {
                "status": "success",
                "domain": domain,
                "record_count": len(records),
                "records": records,
                "message": f"发现 {len(records)} 条 DNS 查询记录",
            }
    except json.JSONDecodeError:
        pass

    # 按行解析
    records = [
        line.strip()
        for line in records_text.split("\n")
        if line.strip() and line.strip() != "[]"
    ]
    if records:
        return {
            "status": "success",
            "domain": domain,
            "record_count": len(records),
            "records": records,
            "message": f"发现 {len(records)} 条 DNS 查询记录",
        }

    return {
        "status": "no_records",
        "domain": domain,
        "records": [],
        "message": "暂无 DNS 查询记录",
    }


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("错误: 缺少操作类型参数 (get_domain 或 get_records)\n")
        sys.exit(1)

    operation = sys.argv[1]
    session = requests.Session()
    load_cookie(session)

    try:
        if operation == "get_domain":
            result = get_domain(session)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            if result["status"] == "error":
                sys.exit(1)

        elif operation == "get_records":
            if len(sys.argv) < 3:
                sys.stderr.write("错误: get_records 操作需要提供域名参数\n")
                sys.exit(1)
            domain = sys.argv[2]
            wait_time = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else 0
            result = get_records(session, domain, wait_time)
            print(json.dumps(result, ensure_ascii=False, indent=2))

        else:
            sys.stderr.write(
                f"错误: 未知的操作类型 '{operation}'，支持的操作: get_domain, get_records\n"
            )
            sys.exit(1)

    except requests.RequestException as e:
        print(
            json.dumps(
                {
                    "status": "error",
                    "message": f"请求失败: {e}",
                    "suggestion": "请检查网络连接或稍后重试",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        sys.exit(1)
    except Exception as e:
        print(
            json.dumps(
                {"status": "error", "message": f"执行出错: {e}"},
                ensure_ascii=False,
                indent=2,
            )
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
