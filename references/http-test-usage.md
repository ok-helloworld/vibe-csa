# http_test.py — 纯 Python HTTP 发包工具完整用法

## 概述

`http_test.py` 是 漏洞验证、渗透测试中**唯一推荐使用的 HTTP 发包工具**。

- 基于 `httpx` 的纯 Python 实现，无外部二进制依赖
- 智能 Body 编码（自动推断 charset、form URL-encode、JSON、二进制）
- 连接探针（DNS / TCP / TLS 独立计时）
- 响应体过滤和瘦身（正则过滤 + 行/字节截断），显著减少 Token 消耗
- 重复请求 + 聚合统计（盲注 / 时序测试）
- 自动字符集检测和响应解码

**位置**：`{SKILL_ROOT}/scripts/http_test.py`

---

## 快速开始

> PowerShell 兼容说明：
> - 本节代码块使用 `bash` 风格续行符 `\`，在 PowerShell 中请改为单行执行，或使用反引号 `` ` `` 续行。
> - 表单字段优先使用 `--form`；复杂、较长或需保持原始格式的请求体优先使用 `--data-file body.txt`。旧写法 `--data "@body.txt"` 仍可用，但必须带引号，避免与 splatting 语法冲突。
> - 若命令已出现多层引号、复杂 `--headers` JSON 或进入 `>>` 续行提示，应立即改用专用参数、改写 payload，或改走文件输入，而不是继续硬转义。
> - 复杂正则包含 `$`、引号或换行时，优先将正则写入文件并使用 `--response-filter-file regex.txt`。

### 基础 GET 请求
```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "http://target.com/path" \
  --method GET \
  --show-command \
  --show-summary \
  --include-headers \
  --response-max-lines 80
```

### POST JSON 数据
```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "http://target.com/api/endpoint" \
  --method POST \
  --data '{"key":"value"}' \
  --headers '{"Content-Type":"application/json"}' \
  --show-command \
  --show-summary \
  --include-headers \
  --response-max-lines 80
```

### POST 表单数据
```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "http://target.com/login" \
  --method POST \
  --form '{"username":"admin","password":"test123"}' \
  --show-command \
  --show-summary \
  --include-headers \
  --response-max-lines 80
```

表单字段优先使用 `--form` 结构化传入，由工具安全编码并自动设置 `application/x-www-form-urlencoded`；`--data` 保留给原始请求体或需要精确控制编码的场景； 二进制、较长或易受 shell 转义影响的请求体使用 `--data-file`。

---

## 参数速查表

### 请求控制

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--url` | string | (必填) | 目标URL |
| `--method` | string | `GET` | HTTP方法：GET/POST/PUT/PATCH/OPTIONS/HEAD |
| `--data` | string | `""` | 原始请求体；支持 JSON、XML、文本、已构造表单体、兼容旧写法 `@file` 或 `@-` |
| `--data-file` | string | `""` | 从文件原样加载请求体；推荐优先使用，尤其在 PowerShell 中 |
| `--form` | JSON object | `""` | 结构化表单字段；安全编码字段值并自动设置 `application/x-www-form-urlencoded` |
| `--headers` | object/string | `""` | 请求头，支持 JSON 字典 `{"Key":"Val"}` 或 `"Key: Val"` 字符串 |
| `--cookies` | string | `""` | Cookie字符串：`"PHPSESSID=xxx; token=yyy"` |
| `--user-agent` | string | `""` | 自定义 User-Agent |
| `--proxy` | string | `""` | 代理地址：`http://127.0.0.1:8080` 或 `socks5://127.0.0.1:1080` |
| `--timeout` | float | `60` | 超时秒数（支持小数） |
| `--follow-redirects` | bool | `false` | 跟随 HTTP 重定向 |
| `--allow-insecure` | bool | `false` | 忽略 TLS 证书错误（verify=False） |
| `--auto-encode-url` | bool | `false` | URL 特殊字符自动编码 |

### 响应输出控制

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--show-command` | bool | `true` | 输出请求概览（方法/URL/Headers/Body）；使用 `--no-show-command` 关闭 |
| `--show-summary` | bool | `true` | 输出性能指标（DNS/TCP/TLS/TTFB/Total/Speed）；使用 `--no-show-summary` 关闭 |
| `--include-headers` | bool | `true` | 输出响应头（状态行+所有Header）；使用 `--no-include-headers` 关闭 |
| `--verbose-output` | bool | `false` | 输出额外调试信息 |
| `--debug` | bool | `false` | Body 编码处理细节 |
| `--response-encoding` | string | `""` | 强制响应解码字符集（如 `gbk`、`shift_jis`） |
| `--download` | string | `""` | 响应体保存到本地文件，支持 `{i}` 序号占位符 |

以上三项默认开启，以满足漏洞验证和 findings 证据回填需求；仅在无需留存对应证据时使用 `--no-show-command`、`--no-show-summary` 或 `--no-include-headers` 按需关闭。

### 响应体过滤（Token 优化核心功能）

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--response-filter` | regex | `""` | 正则过滤响应体（默认按行匹配），优先使用 |
| `--response-filter-file` | file | `""` | 从文件读取响应体过滤正则；适合复杂正则或 Shell 转义敏感场景 |
| `--response-filter-mode` | string | `line` | 过滤模式：`line`(按行)/`multiline`(跨行块)/`full`(全文DOTALL) |
| `--response-filter-invert` | bool | `false` | 反向过滤：输出不匹配的行（剔除HTML噪音） |
| `--response-filter-ignore-case` | bool | `false` | 正则忽略大小写（等价 `(?i)`） |
| `--response-max-lines` | int | `0` | stdout最多输出行数（0=不限制） |
| `--response-max-bytes` | int | `0` | stdout UTF-8字节上限（0=不限制） |
| `--response-preview-lines` | int | `5` | filter 零命中时的预览行数 |
| `--response-context-lines` | int | `0` | line模式命中行上下各保留N行上下文（类似 grep -C） |

### 常用证据过滤模板

用于从响应体中提取候选证据，默认采用 `line` 模式：

- 唯一标识回显：`<UNIQUE_MARKER>`
- 精确预期值：`<EXPECTED_VALUE>`
- JSON 关键字段：`(?i)"?<FIELD_NAME>"?\s*:\s*"?<EXPECTED_VALUE>"?`
- 服务端异常栈：`(?i)(Traceback \(most recent call last\)|Fatal error:|Uncaught .*Exception|java\.[\w.$]+Exception|SQLSTATE\[)`
- SQL 注入错误：`(?i)(SQL syntax.*MySQL|Warning.*mysql_|MySqlClient\.|SQLSTATE\[|ORA-\d{4,5}|PostgreSQL.*ERROR|SQLite/JDBCDriver|Microsoft OLE DB Provider for SQL Server)`
- 敏感信息泄露：`(?i)(password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`
- SSRF 服务响应：`(?i)(redis_version|redis_mode|SSH-\d|220[ -].*SMTP|MongoDB|Elasticsearch|<title>.*(consul|jenkins|kibana))`
- 命令执行（Unix `id`）：`uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)`
- 命令执行（Windows `ipconfig`）：`(?i)(Windows IP Configuration|IPv4 Address|Subnet Mask|Default Gateway)`
- XXE / LFI / 路径穿越（`/etc/passwd`）：`(?i)(root:.*:0:0:|daemon:.*:/|nobody:.*:/|/bin/(ba)?sh)`
- XXE / LFI / 路径穿越（`Windows/win.ini`）：`(?i)(\[fonts\]|\[extensions\]|\[mci extensions\]|\[files\])`
- XXE / LFI / 路径穿越（`WEB-INF/web.xml`）：`(?i)(<web-app|<servlet|<servlet-mapping|<filter-mapping|<welcome-file-list)`

以上仅为常见示例，实际应根据目标输入、数据流、Sink、解析器及预期证据扩展或组合模板。替换占位符；跨行内容使用 `multiline` 或 `full`。命中结果仍需结合基线和对照请求确认。


### 高级功能

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--repeat` | int | `1` | 重复请求次数（≥1） |
| `--delay` | float | `0` | 重复请求间隔秒数（支持小数） |
| `--additional-args` | string | `""` | httpx.Client额外选项：`"http2=true cert=/path/cert.pem verify=false max_redirects=5"` |

---

## 渗透测试场景模板

### 场景1: SQL 注入测试（POST，错误过滤）

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL" \
  --method POST \
  --data "id=1' OR '1'='1" \
  --headers '{"Content-Type":"application/x-www-form-urlencoded"}' \
  --response-filter '(?i)(error|exception|syntax|mysql|sql|database|warning|debug|trace|stack|fatal|ora-|sqlstate|postgresql)' \
  --response-filter-mode line \
  --response-context-lines 2 \
  --response-max-lines 40 \
  --show-command \
  --show-summary \
  --include-headers
```

### 场景2: XSS 测试（payload 回显检测）

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL?search=%3Cscript%3Ealert%28%27xss_test%27%29%3C%2Fscript%3E" \
  --method GET \
  --response-filter '<script>alert' \
  --response-filter-mode full \
  --response-max-lines 20 \
  --show-command \
  --include-headers
```

### 场景3: Blind SQLi / 时序差异验证

适用于时间型 SQL/NoSQL 盲注、延迟型命令执行及其他需要多次请求比较响应耗时的场景；布尔型盲注可用基线/true/false 请求配合 `--response-filter`、响应关键词或 `Size Download` 对比。

验证前先确认稳定基线输入；时间型盲注应构造 true/false 两组 payload，并在相同 `--repeat` / `--delay` 条件下比较聚合统计，不得仅凭单次慢响应确认。该工具用于验证与取证，不负责自动化枚举。

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL" \
  --method GET \
  --repeat 5 \
  --delay 0.5 \
  --show-summary \
  --response-max-lines 0
```

### 场景4: 认证测试（带Cookie）

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL" \
  --method GET \
  --cookies "PHPSESSID=xxx; token=yyy" \
  --show-command \
  --show-summary \
  --include-headers \
  --response-max-lines 80
```

### 场景5: SSRF 内网探测（快速超时+错误过滤）

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/api/fetch?url=http://127.0.0.1:6379/" \
  --method GET \
  --timeout 5 \
  --response-filter '(?i)(redis|connection|refused|timeout|error)' \
  --response-filter-mode line \
  --show-summary \
  --include-headers
```

### 场景6: 原始二进制请求体（@file 加载）

```bash
python {SKILL_ROOT}/scripts/http_test.py \
  --url "TARGET_URL/upload" \
  --method POST \
  --data @shell.php \
  --headers '{"Content-Type":"application/octet-stream"}' \
  --show-command \
  --show-summary \
  --include-headers \
  --response-max-lines 40
```

---

## 响应过滤最佳实践

### 原则：永远不要让整页 HTML 进入上下文

```bash
# ❌ 错误：整页HTML灌入上下文，浪费Token
python http_test.py --url "http://target.com/page" --method GET

# ✅ 正确：限制行数 + 关键词过滤
python http_test.py --url "http://target.com/page" --method GET \
  --response-max-lines 80 \
  --response-filter '(?i)(error|warning|version|token|password|admin|debug|exception|trace)'
```

### 无过滤结果的处理

当 `--response-filter` 零命中时，工具会自动输出前 `--response-preview-lines` 行（默认5行）作为预览，帮助判断是否需要调整正则。输出会标记 `[body] no regex match; showing preview:`.

### 二进制/大响应处理

- 使用 `--download output.bin` 将响应体保存到本地文件
- 使用 `--response-max-lines 3` 只摘要输出
- 多次请求时用 `--download "run-{i}.bin"` 自动序号区分
