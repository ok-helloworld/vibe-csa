# Stage 2 PoC 构造协议

动态验证 Agent 必须先从静态审计 JSON 推导 PoC，再发送请求。禁止脱离审计结果手写猜测型 PoC。

## 输入字段优先级

PoC 构造按以下字段取证：

1. `analysis.attack_surface`：路由、HTTP 方法、参数、认证角色、Content-Type。
2. `analysis.data_flow`：确认 source 参数如何到达 sink。
3. `analysis.sink`：确定漏洞类型对应的 payload 语义。
4. `analysis.security_controls`：识别过滤、鉴权、白名单和可绕过点。
5. `analysis.bypass_strategy`：生成候选绕过 payload。
6. `analysis.verification_plan`：确定成功标准和多步骤顺序。
7. `location.route/http_method/snippet`：当 attack_surface 不完整时兜底。

## 固定步骤

1. 动态验证 Agent 读取 `workDir/findings/FINDING-*.json`（例如 `workDir/findings/FINDING-001.json`）
2. 判断此漏洞在利用时是否要加载登录凭据 `workDir/sessions/creds.json`；如需认证，从中提取 Cookie/Token 后通过 `--cookies` 或 `--headers '{"Authorization":"Bearer ..."}'` 传入
3. ★ **必须使用 `{SKILL_ROOT}/scripts/http_test.py` 构造并发送真实 PoC 请求**（禁止使用 curl 或其他工具替代）。先读取 `{SKILL_ROOT}/references/http-test-usage.md` 了解完整用法和场景模板：
   ```bash
   python {SKILL_ROOT}/scripts/http_test.py \
     --url "<TARGET_URL>" --method <METHOD> \
     --data '<PAYLOAD>' --headers '{"Key":"Val"}' --cookies "<SESSION>" \
     --response-filter '<VULN_TYPE_REGEX>' --response-filter-mode line \
     --response-max-lines 100 \
     --show-command --show-summary --include-headers
   ```
   最终写回 finding 时，必须按统一契约回填标准化的 `request` / `response` / `response._evidence_match`
  - 若失败 → 回读源码，改 payload / 改参数 / 改认证上下文 / 尝试绕过，每次重试用新的 http_test.py 调用（保留每轮 `--show-command --show-summary --include-headers` 输出），重试至少 **3 轮**，每一轮都要：
    - 读 response
    - 如果失败，看响应读源码分析为什么失败
    - 改策略（按需切换特殊参数：`--allow-insecure` 绕过 TLS、`--follow-redirects` 跟踪重定向链、`--user-agent` 伪装 UA、`--additional-args "http2=true"` 走私、`--response-encoding gbk` 编码探测）
    - 再发
  - 若成功 → 确认 response body 中有实质性证据（不只看 HTTP 200，不能虚假编造 response ）
    - 利用成功的证据充分：设置 `poc.result="success"`、`status="CONFIRMED"`、`finding_class="runtime_verified"`、`dynamic_verification.state="verified"`
4. 若尝试了3次仍失败
  - 用户若强调了使用`deep`模式或者"深入的进行漏洞验证”，可参考 `{SKILL_ROOT}/pentest_skills/INDEX.md`，再做1至2次定向增强验证，但不能虚假编造 request/response，不跳出当前 finding 范围

## 漏洞类型到 PoC 的映射

| 漏洞类型 | 初始 payload | 必须证明 |
| --- | --- | --- |
| SQL 注入 | `'`、布尔真/假条件、时间函数 | 错误信息、布尔差异、时间差异或可提取数据 |
| 命令执行/命令注入/代码执行 | `id`、`;id`、换行分隔、编码分隔 | 响应中出现真实命令输出 |
| 任意文件创建/文件上传/任意文件写入 | 唯一 marker 文件，必要时脚本文件 | 能访问写入后的文件；RCE 还要命令输出 |
| 任意文件读取/目录穿越/本地文件包含 | `/etc/passwd`、编码穿越、Windows 文件 | 读取到系统文件或敏感文件特征 |
| SSRF/HTTP 请求伪造 | metadata、127.0.0.1、内网地址、OOB URL | 内网响应、metadata、服务指纹或 OOB 回连 |
| 越权访问/IDOR | 当前对象 ID 与相邻对象 ID | 低权限访问到其他用户资源 |
| 跨站脚本 | 唯一 marker payload | 存储/反射后的页面响应包含唯一 payload |
| XML 注入/XXE | 外部实体读取文件或 OOB DTD | 文件内容、解析错误或 OOB 回连 |
| 反序列化 | 安全探测 gadget 或错误触发 payload | 反序列化错误、回显、OOB 或命令输出 |

## 绕过生成规则

动态验证 Agent 只能在已识别到过滤或安全控制后使用绕过 payload。绕过策略来自 `analysis.security_controls` 和 `analysis.bypass_strategy`。

常见绕过：

| 控制 | 候选绕过 |
| --- | --- |
| 后缀黑名单 | 双后缀、大小写、解析差异、可上传文本但由后续流程复制解析 |
| 路径清理 | URL 编码、双重编码、混合分隔符、符号链接、规范化前后差异 |
| 命令过滤 | 分隔符变体、换行、环境变量、空格替代、编码 |
| SSRF 过滤 | 十进制/八进制 IP、IPv6、DNS rebinding、跳转、协议变形 |
| SQL 关键字过滤 | 大小写、注释、编码、函数等价替换 |
| 鉴权控制 | 角色切换、对象 ID 替换、隐藏参数、批量接口 |

## 多步骤 PoC 要求

多步骤利用必须拆开记录：

1. 前置或写入动作。
2. 访问或触发动作。
3. 证明动作。

文件类漏洞最低两步：

```text
step 1: 上传或写入带唯一 marker 的文件
step 2: HTTP 访问该文件，响应体出现 marker
```

文件写入到 RCE 最低三步：

```text
step 1: 写入可执行脚本
step 2: 访问脚本确认 marker
step 3: 传入命令并在响应中看到 uid=... 或等价命令输出
```


## 证据判定

`poc.result="success"` 只能在最终响应足够证明漏洞真实存在时设置。HTTP 200、返回 `success`、无报错都不是充分证据。

必须写入：

- `poc.steps.request`、`poc.steps.response` 都需要保留完整请求与响应数据；其中，`poc.steps.request.raw`、`poc.steps.response.raw` 不是必填项，但其它字段都需要根据实际请求和响应情况填写完整数据
- `poc.evidence`：引用具体 step 和响应原文片段。
- `response._evidence_match[]`：记录 `type/pattern/strength/snippet`。
- `dynamic_verification.final_evidence`：记录最终证明类型和证据片段。

### http_test.py 输出 → 证据字段回填映射

| http_test.py 输出段落 | 对应 finding 字段 | 回填方式 |
|---|---|---|
| `Method: GET/POST/...` | `poc.steps[].request.method` | `"GET"` / `"POST"` 等 |
| `URL: http://...` | `poc.steps[].request.url` | 完整 URL 字符串 |
| `Headers (N total):` + 各行 `Key: Value` | `poc.steps[].request.headers` | JSON dict: `{"Key":"Val",...}` |
| `Body: N bytes (mode, charset=...)` | `poc.steps[].request.body` | 摘要字符串，若超过 4096 字节，可保留关键证据片段 |
| `HTTP/1.1 NNN ...` | `poc.steps[].response.status_code` | 取 `NNN` 整数 |
| 响应头各行 `Key: Value` | `poc.steps[].response.headers` | JSON dict |
| `[body] matched N/M lines` 匹配行内容 | `response._evidence_match[].snippet` | 原文复制匹配行 |
| `----- Meta #N -----` 性能指标 | `response._evidence_match[].strength` | TTFB 或时间盲注证据 |
| `Encoding Used: xxx (source)` | `response._evidence_match[].encoding_source` | `"utf-8 (header)"` 等 |

## 成功/失败状态写回口径

- 成功时必须同时更新：
  - `poc.result="success"`
  - `status="CONFIRMED"`
  - `finding_class="runtime_verified"`
  - `dynamic_verification.state="verified"`
  - `dynamic_verification.final_evidence.proof_type` 设为非 `none`
  - `evidence_level` 至少提升到 `L2`；若 `response._evidence_match` 出现 `L3` 命中，则应写为 `L3`
- 重试过程中必须同步更新：
  - `dynamic_verification.state="in_progress"`
  - `dynamic_verification.attempts[]` 为每轮记录 `attempt`、`payload_strategy`、`result`、`request_ref`、`response_ref`、`next_action`
  - `attempts[].result` 应按真实结果写成 `success|failure|timeout|auth_failed|blocked`
- 失败结束时必须区分真实失败类型，不要统一写成笼统失败：
  - 网络或超时问题：`poc.result="timeout"`，`dynamic_verification.state="failed"` 或 `blocked`
  - 认证失效或登录态不足：`poc.result="auth_failed"`，`dynamic_verification.state="blocked"` 或 `failed`
  - 目标主动拦截、WAF、风控或实验条件不满足（无法绕过防护时）：保留 `poc.result="failure"`，并将 `attempts[].result` 或 `dynamic_verification.state` 写为 `blocked`
  - 用户主动跳过、环境不允许继续：`poc.result="skipped"`，`dynamic_verification.state="skipped"`
- 没有 L2/L3 运行时证据时，不得升级为 `CONFIRMED`；应保持或降回 `HYPOTHESIS + code_only`，并补全 `failure_log[]`（此处存的是对象/字典项）、`dynamic_verification.runtime_notes`、`dynamic_verification.final_evidence.proof_type="none"`
