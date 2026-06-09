# Stage 2 PoC 构造协议

动态验证 Agent 必须先从静态审计 JSON 推导 PoC，再发送请求。禁止脱离审计结果手写猜测型 PoC。

> **漏洞攻击测试原则**
>
> - 允许对测试过程中自己创建的数据、自己上传的文件、自己插入的记录做删除、更新、清理操作，以便验证删除、编辑、恢复、回收类漏洞。
> - 禁止对原始业务数据、他人数据、生产数据做破坏性操作。
> - 允许上传文件进行文件上传测试。

## 总则

### 输入字段优先级

PoC 构造按以下字段顺序取证：

1. `analysis.attack_surface`：路由、HTTP 方法、参数、认证角色、Content-Type。
2. `analysis.data_flow`：确认 source 参数如何到达 sink。
3. `analysis.sink`：确定漏洞类型对应的 payload 语义。
4. `analysis.security_controls`：识别过滤、鉴权、白名单和可绕过点。
5. `analysis.bypass_strategy`：生成候选绕过 payload。
6. `analysis.verification_plan`：确定成功标准和多步骤顺序。
7. `location.route/http_method/snippet`：当 `attack_surface` 不完整时兜底。

## 使用工具

### HTTP 发包工具（强制）

**所有 HTTP 请求必须使用 `{SKILL_ROOT}/scripts/http_test.py`。**

开始使用前先读取：

`{SKILL_ROOT}/references/http-test-usage.md`

后续优先复用已获取的用法信息，除非遇到新的场景或参数。

核心调用模板：

```bash
python {SKILL_ROOT}/scripts/http_test.py --url "<URL>" --method <METHOD> \
  --data '<PAYLOAD>' --headers '{"Key":"Val"}' --cookies "<COOKIE>" \
  --response-filter '<REGEX>' --response-filter-mode line \
  --response-max-lines 80 --show-command --show-summary --include-headers
```

关键规则：

- 每发一个请求都必须带 `--show-command --show-summary --include-headers`，确保输出满足 `http_interactions` 证据要求。
- 报错型、回显型、差异型检测优先使用 `--response-filter` 缩小响应范围并提取关键证据。
  可参考用法文档中的“常用过滤正则模板”表。
- 大 HTML 响应必须使用 `--response-max-lines 80` 或更小值限制输出。
- Cookie 认证使用 `--cookies "key1=val1; key2=val2"` 格式。
- JSON API 使用 `--data '{"k":"v"}'` 自动识别 Content-Type。
- 禁止使用 `curl` 或其他工具替代。

### OOB/DNS 回调验证工具

**SSRF/XXE/命令注入/JNDI/SQLi 等无回显漏洞的 OOB 验证必须使用 `{SKILL_ROOT}/scripts/dnslog.py`。**

开始 OOB 测试前先读取 `{SKILL_ROOT}/references/dnslog-usage.md` 了解完整用法和场景模板。

核心 3 步流程：

```bash
# 1. 获取域名
python {SKILL_ROOT}/scripts/dnslog.py get_domain
# → {"domain": "abc123.dnslog.cn"}

# 2. 在 payload 中嵌入域名，通过 http_test.py 发送
# payload 应携带唯一标识，DNS 记录需与时间窗口和该标识对应后才可判定 confirmed

# 3. 等待后查询记录
python {SKILL_ROOT}/scripts/dnslog.py get_records abc123.dnslog.cn 5
# → 查询到 DNS 记录后，应结合 payload 中的唯一标识和触发时间窗口进行比对；不得仅凭 record_count>0 直接判定漏洞 confirmed
```

## 执行流程

漏洞验证过程必须遵循 **漏洞攻击测试原则**。

### 固定步骤

1. 读取当前任务对应的静态参考与动态写回文件，例如：

   ```text
   workDir/static-findings/FINDING-001.json
   workDir/dynamic-findings/FINDING-001.json
   ```

2. 基于 finding 复核验证上下文：

   - `analysis.attack_surface`
   - `analysis.data_flow`
   - `analysis.sink`
   - `analysis.security_controls`
   - `analysis.verification_plan`
   - `location.route/http_method/snippet`

   不得脱离 finding 和源码证据手写猜测型 PoC。

3. 判断是否需要认证上下文。
   如需认证，从 `workDir/sessions/creds.json` 提取 Cookie 或 Token，并通过 `--cookies` 或 `--headers '{"Authorization":"Bearer ..."}'` 传入。

4. 必须使用 `http_test.py` 构造并发送真实 PoC 请求，禁止使用 `curl` 或其他工具替代。

5. 写回 finding 时，必须按下文“证据判定与回填要求”和“成功 / 失败状态写回口径”回填相关字段。

### 单轮验证流程

每一轮验证按以下顺序执行：

1. 根据 finding、源码和上一轮响应确定本轮验证策略。
2. 使用 `http_test.py` 发送请求。
3. 读取 response 或 OOB 结果，提取状态码、响应头、响应体、时间差异、重定向、错误信息或回连记录。
4. 判断是否存在实质性证据。
   不能只凭 HTTP 200、返回 `success`、无报错或页面正常判断漏洞成立。
5. 若证据充分，立即停止验证，并按下文“成功 / 失败状态写回口径”更新相关字段。
6. 若证据不足，结合响应、源码和 finding 上下文分析失败原因，并决定是否调整验证策略后重试。

### 失败后的重试要求

- 若验证不成功，应结合响应、源码、`analysis.security_controls`、`analysis.bypass_strategy` 和 finding 上下文调整验证策略后重试。
- 默认最多重试 3 轮；高价值 finding 可在遵循 **漏洞攻击测试原则** 、不造成破坏性影响的前提下扩展到最多 5 轮。
- 每次重试都必须使用新的 `http_test.py` 调用。
- 明确验证成功后应立即停止验证。
- 出现以下情况应提前停止，并记录原因：

  - 认证失效或权限不足
  - 目标不可达或网络超时
  - 环境限制导致无法继续
  - 用户跳过或测试范围不允许
  - 继续尝试可能造成破坏性影响
  - finding 与运行环境明显不匹配

### 回填要求

无论验证成功、失败，均必须遵循下文“证据判定与回填要求”和“成功 / 失败状态写回口径”完成结果回填。

## 漏洞类型到 PoC 的映射

| 漏洞类型 | 初始 payload | 必须证明 |
| --- | --- | --- |
| SQL 注入 | `'`、布尔真/假条件、时间函数 | 错误信息、布尔差异、时间差异或可提取数据 |
| 命令执行 / 命令注入 / 代码执行 | `id`、`;id`、换行分隔、编码分隔 | 响应中出现真实命令输出 |
| 任意文件创建 / 文件上传 / 任意文件写入 | 唯一 marker 文件，必要时脚本文件 | 能访问写入后的文件；RCE 还要命令输出 |
| 任意文件读取 / 目录穿越 / 本地文件包含 | `/etc/passwd`、编码穿越、Windows 文件 | 读取到系统文件或敏感文件特征 |
| SSRF / HTTP 请求伪造 | metadata、127.0.0.1、内网地址、OOB URL | 内网响应、metadata、服务指纹或 OOB 回连 |
| 越权访问 / IDOR | 当前对象 ID 与相邻对象 ID | 低权限访问到其他用户资源 |
| 跨站脚本 | 唯一 marker payload | 存储或反射后的页面响应包含唯一 payload |
| XML 注入 / XXE | 外部实体读取文件或 OOB DTD | 文件内容、解析错误或 OOB 回连 |
| 反序列化 | 安全探测 gadget 或错误触发 payload | 反序列化错误、回显、OOB 或命令输出 |

## PoC 结构要求

多步骤利用必须拆开记录，至少包含以下阶段：

1. 前置或写入动作。
2. 访问或触发动作。
3. 证明动作。

### 文件类漏洞

最低两步：

```text
step 1: 上传或写入带唯一 marker 的文件
step 2: HTTP 访问该文件，响应体出现 marker
```

### 文件写入到 RCE

最低三步：

```text
step 1: 写入可执行脚本
step 2: 访问脚本确认 marker
step 3: 传入命令并在响应中看到 uid=... 或等价命令输出
```

## 证据判定与回填要求

`poc.result="success"` 只能在最终响应足够证明漏洞真实存在时设置。HTTP 200、返回 `success`、无报错都不是充分证据。

- 如果回填的数据是说明性内容，默认回填中文。

### 必填字段

必须写入以下字段：

- `poc.steps[].request`、`poc.steps[].response`：都需要保留完整请求与响应数据。
  其中 `poc.steps[].request.raw`、`poc.steps[].response.raw` 不是必填项，但其他字段都需要根据实际请求和响应情况填写完整数据。
- `poc.evidence`：引用具体 step 和响应原文片段。
- `response._evidence_match[]`：记录 `type`、`pattern`、`strength`、`snippet`。
- `dynamic_verification.final_evidence`：记录最终证明类型和证据片段。

### http_test.py 输出到证据字段的回填映射

| `http_test.py` 输出段落 | 对应 finding 字段 | 回填方式 |
| --- | --- | --- |
| `Method: GET/POST/...` | `poc.steps[].request.method` | `"GET"` / `"POST"` 等 |
| `URL: http://...` | `poc.steps[].request.url` | 完整 URL 字符串 |
| `Headers (N total):` + 各行 `Key: Value` | `poc.steps[].request.headers` | JSON dict，例如 `{"Key":"Val",...}` |
| `Body: N bytes (mode, charset=...)` | `poc.steps[].request.body` | 摘要字符串；若超过 4096 字节，可保留关键证据片段 |
| `HTTP/1.1 NNN ...` | `poc.steps[].response.status_code` | 取 `NNN` 整数 |
| 响应头各行 `Key: Value` | `poc.steps[].response.headers` | JSON dict |
| `[body] matched N/M lines` 匹配行内容 | `response._evidence_match[].snippet` | 原文复制匹配行 |
| `----- Meta #N -----` 性能指标 | `response._evidence_match[].strength` | TTFB 或时间盲注证据 |
| `Encoding Used: xxx (source)` | `response._evidence_match[].encoding_source` | 例如 `"utf-8 (header)"` |

## 成功 / 失败状态写回口径

### 成功态

- `poc.result="success"`
- `status="CONFIRMED"`
- `finding_class="runtime_verified"`
- `dynamic_verification.state="verified"`
- `dynamic_verification.final_evidence.proof_type` 设为非 `none`
- `evidence_level` 至少提升到 `L2`；若 `response._evidence_match` 出现 `L3` 命中，则应写为 `L3`

### 重试态

- `dynamic_verification.state="in_progress"`
- `dynamic_verification.attempts[]`：为每轮记录 `attempt`、`payload_strategy`、`result`、`request_ref`、`response_ref`、`next_action`
- `attempts[].result`：按真实结果写成 `success|failure|timeout|auth_failed|blocked`

### 失败态（包含证据不足）

- 网络或超时问题：`poc.result="timeout"`，`dynamic_verification.state="failed"` 或 `blocked`
- 认证失效或登录态不足：`poc.result="auth_failed"`，`dynamic_verification.state="blocked"` 或 `failed`
- 目标主动拦截、WAF、风控或实验条件不满足，且无法绕过防护时：
  保留 `poc.result="failure"`，并将 `attempts[].result` 或 `dynamic_verification.state` 写为 `blocked`
- 用户主动跳过、环境不允许继续：`poc.result="skipped"`，`dynamic_verification.state="skipped"`
- `blocked` 不作为 `poc.result` 的取值；阻断场景应写入 `dynamic_verification.state` 或 `dynamic_verification.attempts[].result`。
- 没有 `L2` / `L3` 运行时证据时，不得升级为 `CONFIRMED`。
- 应保持或降回 `HYPOTHESIS + code_only`。
- 必须补全：
  - `failure_log[]`（此处存的是对象 / 字典项）
  - `dynamic_verification.runtime_notes`
  - `dynamic_verification.final_evidence.proof_type="none"`
