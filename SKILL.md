---
name: vibe-csa
description: "Vibe CSA (Code Security Audit)，白盒代码安全审计能力，三阶段工作流程：静态代码审计、动态漏洞验证、报告生成；AI 代码审计，采用多 Agent 智能体静态审计+动态验证模式；最终生成稳定的 HTML、Word 格式安全评估报告。触发场景：代码审计、AI 代码审计、AI 漏洞评估、VIBE-CSA 专项检测。"
metadata:
  author: helloworld
  version: "1.0.20"
  date: 2026-09-03
---
# vibe-csa: 代码安全审计三阶段协议

## 启动前快速 Git 自更新

每次调用本 skill 时，在开始正式任务前优先执行：

`python {SKILL_ROOT}/scripts/auto_update_skill.py {SKILL_ROOT} --json`

该脚本负责快速检查并同步当前 skill 项目；如果更新失败、超时、无网络、无法获取远端状态，或 `SKILL_ROOT` 目录不是 Git 仓库，直接跳过更新并继续执行用户任务，不要卡住。

如果 `git pull` 有文件冲突，脚本会自动将远端最新文件覆盖到本地冲突文件，但不会执行 `git reset --hard` 之类的全局破坏性操作。

如果自动更新结果的 `reason` 为 `updated` 或 `updated_with_conflict_resolution`，必须先重新读取主 `SKILL.md`，再继续后续步骤。


## 启动前运行子 Agent 创建脚本

开始审计前，在**当前项目目录**下，直接调用脚本`python {SKILL_ROOT}/scripts/install_sub_agents.py --provider {provider} --force` 创建 8 个 Agent：

其中包括：`1` 个 `static-code-map`、`6` 个静态漏洞审计 Agent、`1` 个 `dynamic-verifier`

`--provider` 应根据当前智能体平台选择，例如 `qoder`、`opencode`、`trae`、`claude`、`workbuddy`、`codebuddy`，也支持自定义名称。

- 命令示例：
```bash
python {SKILL_ROOT}/scripts/install_sub_agents.py --provider qoder --force
```

## 启动前创建 workDir 目录

开始新任务前，必须先检查**当前项目目录**下是否已存在 `workDir/` 目录。

如果已存在 `workDir/`，先将其重命名为 `workDir_{YYYYMMDD_HHmmss}`，其中 `YYYYMMDD_HHmmss` 为当前时间戳，例如 `workDir_20260605_143025`，用于保留旧任务数据。命令示例：
- **Windows (PowerShell)**: `Rename-Item -Path "workDir" -NewName "workDir_20260605_143025"`
- **Linux/macOS (Bash)**: `mv workDir workDir_20260605_143025`
请根据当前操作系统选择正确的命令，若无法重命名，不得删除旧目录。

旧目录重命名完成后，再创建新的空 `workDir/` 目录，确保本次新任务的中间文件、扫描结果和最终报告都写入新创建的 `workDir/` 目录。

## 三阶段简要总览

vibe-csa 使用统一 JSON 贯穿三个阶段；阶段必须严格划分，其中 Stage 2 为可选阶段。

- Stage 1 静态代码审计：先启动 `static-code-map` Agent，生成并回填 `agent-static-code-map.json`；再并发执行 6 个静态审计 Agent：`static-injection`、`static-auth`、`static-file-ssrf`、`static-deser`、`static-logic`、`static-info`，分别生成并回填 `workDir/agent-results/*.json`；最后汇总并去重生成 `workDir/static-merged.json`
- Stage 2 漏洞动态验证（可选）：基于 `workDir/static-merged.json` 生成验证队列与 finding 工作文件，最多并行创建 `5` 个 `dynamic-verifier` 子 Agent 领取任务、发送真实请求，并将运行时证据写回 finding 文件，最终生成 `workDir/dynamic-verified.json`
- Stage 3 报告生成：基于 `workDir/static-merged.json` 或 `workDir/dynamic-verified.json` 生成 HTML 和 Word 报告

允许的执行路径：

- 只做代码审计：`Stage 1 -> Stage 3`
- 代码审计 + 动态验证：`Stage 1 -> Stage 2 -> Stage 3`

```text
源码路径
  |
  v
Stage 1 静态代码审计
  输入: 源码路径
  动作: 语言识别、代码事实图谱构建、多 Agent 并行审计、去除重复漏洞项
  输出: workDir/agent-results/agent-static-code-map.json
        workDir/agent-results/agent-static-*.json
        workDir/static-merged.json
  |
  +--> 直接进入 Stage 3
  |
  v
Stage 2 漏洞动态验证（可选）
  输入: workDir/static-merged.json + 目标 URL/凭据
  动作: 生成 finding 工作文件与 dynamic-state.json，最多并行 5 个 dynamic-verifier 子 Agent 领取任务并回填真实数据
  输出: workDir/dynamic-verified.json
  |
  v
Stage 3 报告生成
  输入: workDir/static-merged.json 或 workDir/dynamic-verified.json
  输出: HTML 和 Word 报告
```


## Multi Agent 角色简介

### 静态代码审计子 Agent

主流程在后续执行过程中，通过智能体平台提供的 Multi-Agent / Subagents 能力或等效工作流能力创建以下 6 个静态代码审计子 Agent，须并行执行。

| Agent 标识名 | Agent 专家角色 | 关注点 | 创建 Agent 定义文件 |
| --- | --- | --- | --- |
| `static-code-map` | 代码事实图谱构建专家 | 在静态漏洞审计前抽取项目入口、身份权限上下文、关键业务对象、调用链、危险操作、状态变化、外部边界与安全相关配置引用，生成共享事实索引 `agent-static-code-map.json`，供后续 6 个静态漏洞审计 Agent 复用 | `{SKILL_ROOT}/references/sub_agents/static-code-map.md` |
| `static-injection` | 注入利用面审计专家 | SQL 注入、命令注入、代码注入、SSTI、表达式注入、LDAP/XPath 注入、NoSQL 注入、GraphQL 注入、ORM/HQL/JPQL 注入、Header/CRLF 注入、反射型 XSS、存储型 XSS、DOM XSS、HTTP 参数污染、SSI 注入 | `{SKILL_ROOT}/references/sub_agents/static-injection.md` |
| `static-auth` | 认证授权与接口访问控制审计专家 | 登录绕过、API 接口鉴权缺失、对象级/功能级授权缺陷、垂直/水平越权与提权、字段级授权缺陷、API 响应敏感字段越权暴露、Session/JWT/OAuth/OIDC 问题、会话固定、多租户隔离缺失、API Key/签名认证缺陷、密码重置/找回流程缺陷、短信/邮箱验证码校验缺陷、OAuth 回调校验缺陷、暴力破解、弱密码、Cookie 验证错误 | `{SKILL_ROOT}/references/sub_agents/static-auth.md` |
| `static-file-ssrf` | 请求目标与文件访问链路审计专家 | SSRF、上传、任意文件读写、任意文件创建/删除、路径穿越、文件包含、XXE、URL 校验缺陷、URL 重定向、开放重定向链入 SSRF、重定向跟随导致的 SSRF、HTTP请求走私、Host/绝对 URI 信任、Zip Slip、符号链接/临时文件风险、下载功能任意文件读取、对象存储签名 URL 滥用 | `{SKILL_ROOT}/references/sub_agents/static-file-ssrf.md` |
| `static-deser` | 反序列化与危险对象处理审计专家 | Java/PHP/Python 反序列化、JNDI、对象注入、危险 gadget 链、Fastjson/Jackson、YAML、XMLDecoder、不安全对象绑定、多态类型绑定滥用、危险 Bean/对象自动绑定、危险反射/类加载 | `{SKILL_ROOT}/references/sub_agents/static-deser.md` |
| `static-logic` | 业务逻辑与状态机安全审计专家 | 支付篡改、价格/库存/优惠券篡改、订单金额计算缺陷、状态绕过、审批流绕过、竞态条件、重放与幂等缺失、CSRF、Webhook 伪造、批量滥用、批量导入导出越权、限流/配额绕过、注册/邀请/优惠券薅羊毛、账户合并/租户切换逻辑错误。主审计路径为入口盘点、权限与对象归属检查、敏感字段可写性检查、状态机与跨动作链路检查，`sinks` 仅作辅助线索 | `{SKILL_ROOT}/references/sub_agents/static-logic.md` |
| `static-info` | 敏感信息暴露与安全配置审计专家 | 密钥泄露、硬编码凭据、弱加密、不安全随机数、错误证书校验、调试/管理接口暴露、错误信息泄露、CORS、安全响应头缺失、缓存投毒相关配置风险、CSP 缺失或配置不当、点击劫持防护缺失、Swagger/GraphQL introspection 暴露、目录索引/备份文件暴露 | `{SKILL_ROOT}/references/sub_agents/static-info.md` |

### 动态漏洞验证子 Agent

主流程在后续执行过程中，通过智能体平台提供的 Multi-Agent / Subagents 能力或等效工作流能力，按需创建 `1~5` 个 `dynamic-verifier` 动态漏洞验证 Agent，须并行执行。

| Agent 标识名 | Agent 专家角色 | 关注点 | 创建 Agent 定义文件 |
| --- | --- | --- | --- |
| `dynamic-verifier` | 运行时漏洞验证与 PoC 构造专家 | 基于 Stage 1 finding 执行真实请求验证、认证态复用、路由/参数/权限复核、PoC 构造、运行时证据提取、漏洞确认与排除、失败原因记录、`dynamic-state.json` 状态流转、`workDir/dynamic-findings/FINDING-*.json` 回填、安全边界控制；只验证已有 finding，不扩展为新的静态审计任务 | `{SKILL_ROOT}/references/sub_agents/dynamic-verifier.md` |

## 全局硬规则

1. Stage 1 的 `agent-static-code-map.json` 必须由 `static-code-map` 子 Agent 直接生成；`agent-static-*.json` 必须由对应同名静态子 Agent 直接生成。主流程只负责调度、检查、汇总与导出，禁止代写这些结果文件。
2. Stage 1 中，6 个静态审计 Agent 必须优先读取 `workDir/agent-results/agent-static-code-map.json`；若该文件缺失、为空或无效 JSON，可降级为源码直读，但必须在各自结果中记录覆盖缺口。
3. 静态审计过程中，子 Agent 发现漏洞后，生成的 JSON 文件必须包含代码级修复建议：`fix.language`、`fix.before`、`fix.after`。
4. 动态漏洞验证过程中，如果遇到登录验证码、MFA、SSO 时，只能使用 `scripts/extract_credentials.py` 让用户在浏览器中手动登录，禁止脚本猜测或破解验证码。
5. Windows / PowerShell 环境下，若需要把长中文说明、HTML、原始请求/响应报文或带大量引号、反斜杠、换行的证据回填到 JSON，`Stage 1` 优先参考 `references/json-safe-update-static.md`，`Stage 2` 优先参考 `references/json-safe-update-dynamic.md`，并通过 `scripts/json_safe_update.py` 从临时文本文件 / JSON 文件安全回填；不要在 shell 中直接拼接复杂 JSON 字符串覆盖结果文件。

## 阶段入口

### Stage 1 静态代码审计

#### Stage 1.0 构建代码事实图谱

- 在启动 6 个静态漏洞审计 Agent 前，必须先启动 `static-code-map` Agent。
- `static-code-map` 负责抽取项目入口、身份权限上下文、关键业务对象、调用链、危险操作、状态变化、外部边界与安全相关配置引用，并直接写入结果文件。
- `static-code-map` 输出：

```text
workDir/agent-results/agent-static-code-map.json
```

- `agent-static-code-map.json` 是后续静态漏洞审计 Agent 的共享事实索引，不是漏洞结果文件。
- `static-code-map` 不输出 `findings`，不生成 PoC，不设置漏洞状态，不参与 `merge_static_results.py` 的漏洞合并。
- 主流程不得根据子 Agent 摘要自行拼装或代写 `agent-static-code-map.json`。
- 如果 `agent-static-code-map.json` 生成失败、为空或覆盖不足，后续 6 个静态漏洞审计 Agent 仍可继续执行，但必须退化为源码检索与源码细读，并在各自结果的覆盖信息中记录缺口。

#### Stage 1.1 multi Agent 运行静态审计

- 在 `agent-static-code-map.json` 生成后，必须同时启动 6 个静态漏洞审计 Agent：

```text
static-injection
static-auth
static-file-ssrf
static-deser
static-logic
static-info
```

- 6 个 Agent 并发执行审计任务。
- 6 个 Agent 必须完整读取各自负责的 `{SKILL_ROOT}/references/sub_agents/{agentname}.md`。
- 每个 Agent 开始审计前，须使用 `scripts/prepare_static_aegnt_result.py` 生成自身静态审计骨架文件：

```bash
python {SKILL_ROOT}/scripts/prepare_static_aegnt_result.py {agentname}
```

- 骨架文件会保存至 `workDir/agent-results/*.json`。例如 `static-deser` 的最终文件为：

```text
workDir/agent-results/agent-static-deser.json
```

- 每个 Agent 必须优先读取：

```text
workDir/agent-results/agent-static-code-map.json
```

- 每个 Agent 应根据自身职责筛选 code map 中的 `entrypoints`、`auth_model`、`objects`、`operations`、`state_changes`、`external_boundaries`、`config_refs`，只对相关高风险路径回读源码。
- `agent-static-code-map.json` 只能作为导航和事实索引，漏洞判断必须以源码证据为准。
- 如果发现 code map 缺失或错误，应以源码为准，并在自身结果中记录补充事实或覆盖缺口。
- 每个 Agent 必须直接回填并保存自己的 `workDir/agent-results/agent-static-*.json`；主流程不得代写或汇总代写单个静态 Agent 结果文件。
- 每个 Agent 在发现首个高置信问题后，不得立即结束；必须对同模块、同入口族、同对象、同危险操作或同根因模式的相邻路径再做一轮“覆盖闭环”检查，避免只命中代表点而漏掉同类变体。
- 若 code map 已标记 `high_risk_modules` 或 `known_gaps`，相关 Agent 在结束前必须至少回读一次对应模块中的未展开入口、相邻方法或同族调用；若仍无法完成覆盖，必须在结果中明确记录缺口，而不是静默跳过。
- 对同根因的重复变体，Agent 应在“拆分为多条 finding”和“合并为一条带多位置/多入口说明的 finding”之间做显式选择；无论采用哪种方式，都必须确保影响范围被完整表达。
- 每个 Agent 需要将各自骨架文件的所有字段基于审计结果回填，不得回填虚假数据。
- `findings` 字段可结合实际漏洞审计结果扩展多条，漏洞标题、中文漏洞类型、bug 分类标签、`vuln_type` 优先从 `references/bug-categories.md` 选择。
- 每个 Agent 必须输出结构化负向结论：凡是被否证、降级或判为不可达的候选，都要写入 `exclusions[]`，字段含 `location`、`hypothesis`、`reason`、`evidence[]`、`verdict`；只写进说明文字不算完成审计。
- 每个 Agent 在成功发现漏洞后，必须在生成的 JSON 文件中包含修复建议，包括：

  - `fix.language`
  - `fix.before`
  - `fix.after`
- 每个 Agent 完成 `workDir/agent-results/*.json` 文件回填后，必须检查 JSON 格式有效。

#### Stage 1.2 合并 multi-agent 生成的结果

- 当 6 个静态漏洞审计 Agent 完成后，必须使用 `merge_static_results.py` 汇总漏洞结果，生成：

```text
workDir/static-merged.json
```

- 合并输入应为 6 个静态漏洞审计 Agent 的结果文件。
- `workDir/agent-results/agent-static-code-map.json` 是事实索引文件，不应作为漏洞 finding 文件参与合并。
- 如果当前 `merge_static_results.py` 会读取 `workDir/agent-results/*.json`，脚本应显式跳过 `agent-static-code-map.json`。

汇总脚本命令示例：

```bash
python {SKILL_ROOT}/scripts/merge_static_results.py \
  --input-dir workDir/agent-results \
  --output workDir/static-merged.json \
  --source-path {source_path} \
  --target-url {target_url}
```

若脚本合并失败，才需要对照 `references/agent-result-example.json` 与 `references/agent-result-checklist.md` 修复 6 个静态漏洞审计 Agent 的结果文件，逐个完成单文件自检后再重新执行合并。

#### Stage 1.3 复核并更新 `workDir/static-merged.json` 去除重复漏洞项

- 在 `merge_static_results.py` 完成汇总后，使用 `dedupe_static_merged.py` 复核 `workDir/static-merged.json` 中的 `findings[]`，识别重复静态漏洞。
- 脚本在写回前会先在同目录保存一份 `static-dedupe-bak.json`，再重新生成去重后的 `workDir/static-merged.json`。
- “重复漏洞”默认指：`location.file` 相同、`location.line_start` 相同、`location.line_end` 相同，且描述的是同一代码根因的 finding。
- 此类重复项只保留一条，优先保留 `confidence` 更高、`severity` 更高、证据更完整、描述更清晰的一条。

脚本命令示例：

```bash
python {SKILL_ROOT}/scripts/dedupe_static_merged.py \
  --input workDir/static-merged.json \
  --output workDir/static-merged.json
```

#### Stage 1.3.1 契约门禁（负向结论 / 结论冲突 / 入口覆盖率）

去重只解决"重复"，不解决"不可信"。合并后必须再跑一次契约门禁：

```bash
python {SKILL_ROOT}/scripts/check_static_contracts.py \
  --merged workDir/static-merged.json \
  --agent-dir workDir/agent-results \
  --code-map workDir/agent-results/agent-static-code-map.json
```

门禁检查四件事，任一失败即中止，不得进入 Stage 2/3：

1. **负向结论必须有证据**：`exclusions[]` 中每条排除都要带 `evidence[].file + line` 与非空 `reason`。只写"已排除"不写依据的，视为未审计。
2. **跨 Agent 冲突必须复验**：`contradictions[]` 中 `status="open"` 的项必须复验后改为 `resolved` 并填写 `resolution`；`--allow-open-contradictions` 仅用于草稿。
3. **finding 证据链完整**：`analysis.source/sink/data_flow/attack_surface/verification_plan` 不得为空。
4. **入口覆盖率**：`agent-static-code-map.json` 中每个 `entrypoints[].source.file` 必须出现在某个 Agent 的 `reviewed_files` 中，否则该入口视为未审计。

> 覆盖率只认显式凭证。`reviewed_files` 是"读过并给出结论"的记录，不是"被 finding 顺带提到"。
> 这条门禁专门防止"Agent 数量冒充覆盖率"。

合并脚本已把 `exclusions[]` / `contradictions[]` 作为一等字段输出，并会自动把
"某 Agent 排除、另一 Agent 立项"的同一代码位置标记为 `open` 冲突。

### Stage 2 漏洞动态验证（可选）

这是可选阶段。只有用户提供目标环境并要求动态验证时才执行。目标是把静态发现转化为可证明或可否定的运行时证据。

Stage 2 关键产物：
- `workDir/static-findings/FINDING-*.json`：Stage 2 动态验证只读的静态参考 finding 文件
- `workDir/dynamic-findings/FINDING-*.json`：单漏洞动态验证骨架与运行时证据 finding 文件
- `workDir/dynamic-state.json`：Stage 2 验证队列与轻量调度状态文件
- `workDir/dynamic-verified.json`：所有 Stage 2 finding 完成后的统一汇总结果
- 参考样例与字段说明：`{SKILL_ROOT}/references/dynamic-finding-example.md`

#### Stage 2.1 准备动态验证输入与状态文件
- 调用 `scripts/prepare_dynamic_pocs.py` 时，会在这一步同时生成 `workDir/static-findings/FINDING-*.json`、`workDir/dynamic-findings/FINDING-*.json` 和 `workDir/dynamic-state.json`
- `workDir/static-findings/FINDING-*.json` 只读，供 `dynamic-verifier` 读取静态攻击面、数据流、安全控制和验证计划；`workDir/dynamic-findings/FINDING-*.json` 只写，供 `dynamic-verifier` 回填运行时请求、响应与证据
- 根据用户指定的漏洞风险等级，按 `workDir/dynamic-state.json` 中 `findings[].severity` 对本轮验证队列进行筛选；仅修改 `dynamic-state.json` 中的 `findings[]`，移除不在本轮验证范围内的队列项，不删除对应的 `workDir/static-findings/FINDING-*.json` / `workDir/dynamic-findings/FINDING-*.json` 文件，并确保 `dynamic-state.json` 仍为合法 JSON
- 如本轮计划并行创建多个 `dynamic-verifier` 子 Agent，可在筛选后的 `findings[]` 队列项中额外写入 `assigned_slot=1|2|3|4|5` 字段，按本轮实际创建的子 Agent 数量近似平均分配任务；该字段只用于 Stage 2 子 Agent 领取各自负责的队列项，不改变 finding 文件内容。例如：`dynamic-verifier-1` 只领取 `assigned_slot=1` 的任务，`dynamic-verifier-2` 只领取 `assigned_slot=2` 的任务
- `severity` 的合法取值为 `critical|high|medium|low`，分别对应“严重|高危|中危|低危”；若用户未单独指定验证等级，则默认保留 `critical`、`high`，并可按需抽样 `medium`，通常不默认验证 `low`

```bash
python {SKILL_ROOT}/scripts/prepare_dynamic_pocs.py \
  --input workDir/static-merged.json \
  --static-output-dir workDir/static-findings \
  --dynamic-output-dir workDir/dynamic-findings \
  --target-url {target_url}
```

#### Stage 2.2 获取登录凭据（如需要）

- 若用户提供账号密码，在执行动态漏洞验证前，需要先获取到目标网站登录凭据，方便后续漏洞验证过程复用凭据。
- 若用户提供账号密码，或存在 `analysis.attack_surface.auth_required=true`，或存在 `required_role`，必须先调用 `scripts/prepare_auth_session.py` / `scripts/extract_credentials.py`，让用户在浏览器中手动登录并生成 `workDir/sessions/creds.json`。

#### Stage 2.3 启动 dynamic-verifier 动态漏洞验证 Agent

- 在 `workDir/dynamic-state.json`、对应的 `workDir/static-findings/FINDING-*.json` / `workDir/dynamic-findings/FINDING-*.json` 以及所需认证上下文准备完成后，再按照当前 Stage 2 队列中可领取的 `findings[].queue_state="pending"` finding 数量，按需同时启动 `1~5` 个 `dynamic-verifier` 动态漏洞验证 Agent。
- 多个 Agent 并发执行漏洞验证，提高漏洞验证效率；子 Agent 不按漏洞等级分组创建，而是统一从 `dynamic-state.json` 中领取任务。
- 若 Stage 2.1 已为队列项写入 `assigned_slot`，则创建子 Agent 时必须明确告知其只负责对应槽位的任务；子 Agent 仅领取 `assigned_slot` 与自身一致、且 `findings[].queue_state="pending"` 的 finding，避免并行领取同一任务。
- `dynamic-verifier` 子 Agent 应尽量通过 `dynamic-state.json`、`static-findings` 与 `dynamic-findings` 文件传递状态与结果，避免将详细验证过程、长响应内容和中间推理回灌主流程上下文。

#### Stage 2.4 子 Agent 执行动态漏洞验证

- 并行 `dynamic-verifier` 子 Agent 的任务领取、冲突规避、状态更新、漏洞验证与写回边界统一遵循 `{SKILL_ROOT}/references/sub_agents/dynamic-verifier.md`。
- 若存在 `assigned_slot`，则子 Agent 只处理分配给自身槽位的 finding；若未预分配，则退回共享队列自动领取模式。
- 并行 `dynamic-verifier` 子 Agent 需要持续从当前 Stage 2 队列中领取并处理任务，直到 `workDir/dynamic-state.json` 中本轮验证范围内不再存在可领取的 `findings[].queue_state="pending"` finding。
- `dynamic-state.json` 只用于轻量调度状态传递，不用于存储完整请求、完整响应、长证据片段或推理过程；漏洞验证时读取 `workDir/static-findings/FINDING-*.json`，并把运行时数据只写回各自的 `workDir/dynamic-findings/FINDING-*.json`。
- 允许清理测试过程中自己创建的数据、文件或记录；禁止修改原始业务数据、他人数据或生产数据；允许文件上传测试，但必须受上述边界约束。
- 无论漏洞是否利用成功，都须回填对应的 finding 文件，单个 finding 文件完成所有回填之后，需要避免存在 JSON 文件格式错误。

#### Stage 2.5 汇总结果

- 仅当 `workDir/dynamic-state.json` 中本轮验证范围内的 finding 全部进入 `queue_state="done"` 或 `queue_state="failed"`，且不存在待领取的 `queue_state="pending"` 任务后，才能统一执行最终 merge，生成 `workDir/dynamic-verified.json`。
- 脚本举例：

```bash
python {SKILL_ROOT}/scripts/verify_vuln.py --merge workDir/dynamic-findings/*.json --static-ref-dir workDir/static-findings --into workDir/dynamic-verified.json
```

#### Stage 2 硬约束

- Stage 2 只能补充运行时证据，不得重写 Stage 1 的静态基线字段结构，不得构造假数据。
- 证据不足时保留 `HYPOTHESIS`；仅在漏洞验证成功时升级为 `CONFIRMED`。
- ★ **所有动态验证 HTTP 请求必须使用 `{SKILL_ROOT}/scripts/http_test.py`**，禁止使用 curl 或其他工具替代。每个请求必须带 `--show-command --show-summary --include-headers`。详细用法见 `{SKILL_ROOT}/references/http-test-usage.md`。仅在需要浏览器渲染执行 JS 时使用浏览器自动化作为例外。
- `dynamic-state.json` 是调度状态真相源；`workDir/static-findings/FINDING-*.json` 是 Stage 2 只读静态参考；`workDir/dynamic-findings/FINDING-*.json` 是漏洞验证证据真相源；不得混用。

### Stage 3 报告生成

#### 翻译说明性内容

- 在执行 HTML / Word 报告脚本前，根据用户需求，需要额外对 `workDir/static-merged.json` 或 `workDir/dynamic-verified.json` 中的说明性文本字段的内容进行一次翻译，默认翻译为中文。
- 建议翻译的字段包括：`analysis.verification_plan.steps.action`、`poc.steps.name`、`dynamic_verification.runtime_notes`、`dynamic_verification.final_evidence.summary`、`dynamic_verification.attempts[].result`、`next_action`、`payload_strategy`、`description`、`impact`、`vuln_type`。
- 不得翻译路径、参数名、字段名、payload、状态码、URL、请求/响应原始报文、证据原文片段及其它技术性片段；翻译后必须保持原有 JSON 结构、字段名和技术语义不变，并确保文件仍为合法 JSON。

> 报告会渲染 `chains[]`（攻击链）、`exclusions[]`（负向结论）与 `contradictions[]`（跨 Agent 冲突）；
> 只列出"发现了什么"而不呈现"否证了什么"，不足以支撑审计结论。

#### 如果只执行了 Stage 1 静态审计
静态-only 报告生成示例，生成html以及word报告

```bash
python {SKILL_ROOT}/scripts/vibe_csa_html.py -i workDir/static-merged.json -o workDir/reports/vibe-csa-static-{YYYYMMDD-HHmmss}.html
python {SKILL_ROOT}/scripts/vibe_csa_report.py -i workDir/static-merged.json -o workDir/reports/vibe-csa-static-{YYYYMMDD-HHmmss}.docx
```

#### 如果执行了静态审计和动态漏洞验证

动态漏洞验证报告生成示例，生成html以及word报告

```bash
python {SKILL_ROOT}/scripts/vibe_csa_html.py -i workDir/dynamic-verified.json -o workDir/reports/vibe-csa-dynamic-{YYYYMMDD-HHmmss}.html
python {SKILL_ROOT}/scripts/vibe_csa_report.py -i workDir/dynamic-verified.json -o workDir/reports/vibe-csa-dynamic-{YYYYMMDD-HHmmss}.docx
```

## 状态文件

长任务必须维护：

```text
workDir/
  audit-state.json
  dynamic-state.json
  agent-results/
  static-merged.json
  static-findings/
  dynamic-findings/
  dynamic-verified.json
```

`audit-state.json` 至少记录：

```json
{
  "version": "vibe-csa-v1",
  "stage": "static_audit",
  "status": "in_progress",
  "output_files": [],
  "next_action": ""
}
```

`dynamic-state.json` 至少记录：

```json
{
  "version": "vibe-csa-v1",
  "stage": "dynamic_verification",
  "max_parallel": 5,
  "status": "in_progress",
  "target_url": "",
  "agents": [
    {
      "agent_id": "dynamic-verifier-1",
      "current_vuln_id": ""
    }
  ],
  "findings": [
    {
      "vuln_id": "FINDING-001",
      "severity": "high",
      "finding_file": "workDir/dynamic-findings/FINDING-001.json",
      "static_finding_file": "workDir/static-findings/FINDING-001.json",
      "assigned_slot": 1,
      "queue_state": "pending",
      "leased_by": "",
      "lease_until": "",
      "conflict_key": "",
      "last_error": ""
    }
  ]
}
```

其中 `findings[].queue_state` 建议固定为以下取值：

- `pending`：尚未被领取；`leased_by=""`，`lease_until=""`
- `running`：已被某个子 Agent 领取并正在处理；包括读取源码、准备凭据、构造 PoC、发送请求、attempt / refinement 全过程
- `done`：验证流程已结束，且 finding 文件已完成回填；是否成功利用以 `poc.result` 为准
- `failed`：本轮验证任务已结束但未能完成有效回填或无法继续推进；网络、认证、风控、前置条件不满足、用户显式跳过等情况，都统一在 `last_error` 中记录原因

## 安全规则

1. **严格限制目标域名**，不测试范围外的任何地址。
2. **不执行破坏性操作**：不删除数据、不修改业务数据、不发起 DoS。
3. **凭证安全**：如果 `sessions/*.json` 包含敏感信息，测试完成后提醒用户删除。
4. **速率控制**：请求间保持合理间隔，避免触发 WAF 或对服务造成影响。
