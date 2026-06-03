---
name: vibe-csa
description: "Vibe CSA (Code Security Audit)，白盒代码安全审计能力，三阶段工作流程：静态代码审计、动态漏洞验证、报告生成；AI 代码审计，采用多 Agent 智能体静态审计+动态验证模式；最终生成稳定的 HTML、Word 格式安全评估报告。触发场景：代码审计、AI 代码审计、AI 漏洞评估、VIBE-CSA 专项检测。"
metadata:
  author: helloworld
  version: "1.0.8"
  date: 2026-06-03
---
# vibe-csa: 代码安全审计三阶段协议

## 启动前快速 Git 自更新

每次调用本 skill 时，在开始正式任务前优先执行：

`python {SKILL_ROOT}/scripts/auto_update_skill.py {SKILL_ROOT} --json`

该脚本负责快速检查并同步当前 skill 项目；如果更新失败、超时、无网络、无法获取远端状态，或 `SKILL_ROOT` 目录不是 Git 仓库，直接跳过更新并继续执行用户任务，不要卡住。

如果 `git pull` 有文件冲突，脚本会自动将远端最新文件覆盖到本地冲突文件，但不会执行 `git reset --hard` 之类的全局破坏性操作。

如果自动更新结果的 `reason` 为 `updated` 或 `updated_with_conflict_resolution`，必须先重新读取主 `SKILL.md`，再继续后续步骤。

## 三阶段简要总览

vibe-csa 使用统一 JSON 贯穿三个阶段；阶段必须严格划分，其中 Stage 2 为可选阶段。

- Stage 1 静态代码审计：多 Agent 并行审计源码，输出 `workDir/agent-results/*.json`，再汇总生成 `workDir/static-merged.json`
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
  动作: 语言识别、Tier 分层、sink 预扫描、多 Agent 并行审计、 去除重复漏洞项
  输出: workDir/agent-results/*.json
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

## 启动协议

### 1. 定位 SKILL_ROOT

优先级：

1. 调用上下文注入的 `Base directory for this skill`
2. 当前 `SKILL.md` 所在目录
3. 搜索 `**/vibe-csa/core/pipeline.md`
4. 如果无法定位，要求用户提供路径

### 2. 必读文件

执行审计前必须读取：

| 文件 | 用途 |
| --- | --- |
| `{SKILL_ROOT}/core/pipeline.md` | 三阶段流水线、输入输出、门禁 |

进入对应阶段后，再按需读取：
- Stage 1 创建多 Agent 并行审计，读取 `{SKILL_ROOT}/core/static-multi-agent.md`
- Stage 2 创建多 Agent 并行动态验证，读取 `{SKILL_ROOT}/core/dynamic-multi-agent.md`

## 全局硬规则

1. 静态审计过程中，子agent发现漏洞后，生成的json文件一定要包含代码级别的修复建议，包括审计语言：`fix.language`、当前代码片段：`fix.before`、代码修复参考：`fix.after`。
2. 动态漏洞验证过程中，如果遇到登录验证码、MFA、SSO 时，只能使用 `scripts/extract_credentials.py` 让用户在浏览器中手动登录，禁止脚本猜测或破解验证码。

## 阶段入口

### Stage 1 静态代码审计

#### Stage 1.1 multi Agent
- **必须完整读取** `{SKILL_ROOT}/core/static-multi-agent.md` 创建多 Agent 独立分工、并发执行
- 每个 Agent 开始审计前，须使用 `scripts/prepare_static_aegnt_result.py` 生成静态审计骨架文件，脚本运行示例：`python {SKILL_ROOT}/scripts/prepare_static_aegnt_result.py {agentname}`，骨架文件会保存至 `workDir/agent-results/*.json`，比如 `static-deser` agent，生成的最终文件为 `workDir/agent-results/agent-static-deser.json`
- 铁律：每个 Agent 需要将各自的骨架文件的所有字段全部回填（需要基于审计结果回填，不得回填虚假数据）。
- `findings`字段可结合实际漏洞审计结果扩展多条，漏洞标题、中文漏洞类型、bug 分类标签、`vuln_type` 优先从 `references/bug-categories.md` 选择
- 每个 Agent 须遵循 `core/coverage-gate.md`，计算代码审计覆盖率，然后将结果更新至 `workDir/agent-results/*.json` 的 `coverage_summary`字段
- 每个 Agent 在成功发现到漏洞后，一定要在生成的json文件中包含修复建议，json字段包括审计语言：`fix.language`、当前代码片段：`fix.before`、代码修复参考：`fix.after`
- 每个 Agent 完成 `workDir/agent-results/*.json` 文件所有回填之后，需要检查避免存在json文件格式错误

#### Stage 1.2 合并multi-agent生成的结果
- 当所有第一阶段的 `multi-agent` 执行完审计任务之后，必须使用 `merge_static_results.py` 汇总 `workDir/agent-results/*.json` 生成 `workDir/static-merged.json`。
- 若脚本合并失败，才需要对照 `references/agent-result-example.json` 与 `references/agent-result-checklist.md` 修复 `workDir/agent-results/*.json`，逐个完成单文件自检后再重新执行合并。

汇总脚本命令示例：

```bash
python {SKILL_ROOT}/scripts/merge_static_results.py \
  --input-dir workDir/agent-results \
  --output workDir/static-merged.json \
  --source-path {source_path} \
  --target-url {target_url}
```

#### Stage 1.3 复核并更新 `workDir/static-merged.json` 去除重复漏洞项
- 在 `merge_static_results.py` 完成汇总后，使用 `dedupe_static_merged.py` 复核 `workDir/static-merged.json` 中的 `findings[]`，识别重复静态漏洞；脚本在写回前会先在同目录保存一份 `static-dedupe-bak.json`，再重新生成去重后的 `workDir/static-merged.json`
- “重复漏洞”默认指：`location.file` 相同、`location.line_start` 相同、`location.line_end` 相同，且描述的是同一代码根因的 finding；此类重复项只保留一条，优先保留 `confidence` 更高、`severity` 更高、证据更完整、描述更清晰的一条


脚本命令示例：

```bash
python {SKILL_ROOT}/scripts/dedupe_static_merged.py \
  --input workDir/static-merged.json \
  --output workDir/static-merged.json
```

### Stage 2 漏洞动态验证（可选）

这是可选阶段。只有用户提供目标环境并要求动态验证时才执行。目标是把静态发现转化为可证明或可否定的运行时证据。

Stage 2 关键产物：
- `workDir/findings/FINDING-*.json`：单漏洞动态验证骨架与证据 finding 文件
- `workDir/dynamic-state.json`：Stage 2 验证队列与轻量调度状态文件
- `workDir/dynamic-verified.json`：所有 Stage 2 finding 完成后的统一汇总结果

#### Stage 2.1 准备动态验证输入与状态文件
- 调用 `scripts/prepare_dynamic_pocs.py` 时，会在这一步同时生成若干条动态验证骨架文件（如： `workDir/findings/FINDING-001.json`）和 `workDir/dynamic-state.json`
- 根据用户指定的漏洞风险等级，按 `workDir/dynamic-state.json` 中 `findings[].severity` 对本轮验证队列进行筛选；仅修改 `dynamic-state.json` 中的 `findings[]`，移除不在本轮验证范围内的队列项，不删除对应的 `workDir/findings/FINDING-*.json` 文件，并确保 `dynamic-state.json` 仍为合法 JSON
- 如本轮计划并行创建多个 `dynamic-verifier` 子 Agent，可在筛选后的 `findings[]` 队列项中额外写入 `assigned_slot=1|2|3|4|5` 字段，按本轮实际创建的子 Agent 数量近似平均分配任务；该字段只用于 Stage 2 子 Agent 领取各自负责的队列项，不改变 finding 文件内容。例如：`dynamic-verifier-1` 只领取 `assigned_slot=1` 的任务，`dynamic-verifier-2` 只领取 `assigned_slot=2` 的任务
- `severity` 的合法取值为 `critical|high|medium|low`，分别对应“严重|高危|中危|低危”；若用户未单独指定验证等级，则默认保留 `critical`、`high`，并可按需抽样 `medium`，通常不默认验证 `low`

```bash
python {SKILL_ROOT}/scripts/prepare_dynamic_pocs.py \
  --input workDir/static-merged.json \
  --output-dir workDir/findings \
  --target-url {target_url}
```

#### Stage 2.2 获取登录凭据（如需要）
- 若用户提供账号密码，在执行动态漏洞验证前，需要先获取到目标网站登录凭据，方便后续漏洞验证过程，可以复用凭据
- 若用户提供账号密码，或存在 `analysis.attack_surface.auth_required=true`，或存在 `required_role`，必须先调用 `scripts/prepare_auth_session.py` / `scripts/extract_credentials.py`，让用户在浏览器中手动登录并生成 `workDir/sessions/creds.json`

#### Stage 2.3 创建并行 dynamic-verifier 子 Agent
- 在 `workDir/dynamic-state.json`、对应的 `workDir/findings/FINDING-*.json` 以及所需认证上下文准备完成后，再**必须完整读取** `{SKILL_ROOT}/core/dynamic-multi-agent.md`，按照当前 Stage 2 队列中可领取的 `findings[].queue_state="pending"` finding 数量，按需创建 `1~5` 个 `dynamic-verifier` 子 Agent 并发执行漏洞验证，提高漏洞验证效率；子 Agent 不按漏洞等级分组创建，而是统一从 `dynamic-state.json` 中领取任务
- 若 Stage 2.1 已为队列项写入 `assigned_slot`，则创建子 Agent 时必须明确告知其只负责对应槽位的任务；子 Agent 仅领取 `assigned_slot` 与自身一致、且 `findings[].queue_state="pending"` 的 finding，避免并行领取同一任务
- `dynamic-verifier` 子 Agent 应尽量通过 `dynamic-state.json` 和对应的 finding 文件传递状态与结果，避免将详细验证过程、长响应内容和中间推理回灌主流程上下文

#### Stage 2.4 子 Agent 执行动态漏洞验证
- 并行 `dynamic-verifier` 子 Agent 的任务领取、冲突规避、状态更新、漏洞验证与写回边界统一遵循 `{SKILL_ROOT}/core/dynamic-multi-agent.md`
- 若存在 `assigned_slot`，则子 Agent 只处理分配给自身槽位的 finding；若未预分配，则退回共享队列自动领取模式
- 并行 `dynamic-verifier` 子 Agent 需要持续从当前 Stage 2 队列中领取并处理任务，直到 `workDir/dynamic-state.json` 中本轮验证范围内不再存在可领取的 `findings[].queue_state="pending"` finding
- `dynamic-state.json` 只用于轻量调度状态传递，不用于存储完整请求、完整响应、长证据片段或推理过程；漏洞验证数据必须写回各自的 `workDir/findings/FINDING-*.json`
- 允许清理测试过程中自己创建的数据、文件或记录；禁止修改原始业务数据、他人数据或生产数据；允许文件上传测试，但必须受上述边界约束
- 无论漏洞是否利用成功，都须回填对应的 finding 文件，单个 finding 文件完成所有回填之后，需要避免存在 JSON 文件格式错误

#### Stage 2.5 汇总结果
- 仅当 `workDir/dynamic-state.json` 中本轮验证范围内的 finding 全部进入 `queue_state="done"` 或 `queue_state="failed"`，且不存在待领取的 `queue_state="pending"` 任务后，才能统一执行最终 merge（合并所有 finding），生成 `workDir/dynamic-verified.json`
- 脚本举例：`python {SKILL_ROOT}/scripts/verify_vuln.py --merge workDir/findings/*.json --into workDir/dynamic-verified.json`

#### 硬约束
- Stage 2 只能补充运行时证据，不得重写 Stage 1 的静态基线字段结构，不得构造假数据
- 证据不足时保留 `HYPOTHESIS`；仅在漏洞验证成功时升级为 `CONFIRMED`
- ★ **所有动态验证 HTTP 请求必须使用 `{SKILL_ROOT}/scripts/http_test.py`**（禁止使用 curl 或其他工具替代）。每个请求必须带 `--show-command --show-summary --include-headers`。详细用法见 `{SKILL_ROOT}/references/http-test-usage.md`。仅在需要浏览器渲染执行 JS 时使用浏览器自动化作为例外
- `dynamic-state.json` 是调度状态真相源；`workDir/findings/FINDING-*.json` 是漏洞验证证据真相源；不得混用

### Stage 3 报告生成

#### 翻译说明性内容
- 在执行 HTML / Word 报告脚本前，根据用户需求，需要额外对 `workDir/static-merged.json` 或 `workDir/dynamic-verified.json` 中的说明性文本字段的内容进行一次翻译，默认翻译为中文
- 建议翻译的字段包括：`analysis.verification_plan.steps.action`、`poc.steps.name`、`dynamic_verification.runtime_notes`、`dynamic_verification.final_evidence.summary`、`dynamic_verification.attempts[].result`、`next_action`、`payload_strategy`、`description`、`impact`、`vuln_type`
- 不得翻译路径、参数名、字段名、payload、状态码、URL、请求/响应原始报文、证据原文片段及其它技术性片段；翻译后必须保持原有 JSON 结构、字段名和技术语义不变，并确保文件仍为合法 JSON

#### 如果只执行了 Stage 1 静态审计
静态-only报告生成示例，生成html以及word报告

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
  file_manifest.json
  sink_hits/
  agent-results/
  static-merged.json
  findings/
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
      "finding_file": "workDir/findings/FINDING-001.json",
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

1. **严格限制目标域名**，不测试范围外的任何地址
2. **不执行破坏性操作**：不删除数据、不修改业务数据、不发起 DoS
3. **凭证安全**：如果`sessions/*.json` 包含敏感信息，测试完成后提醒用户删除
4. **速率控制**：请求间保持合理间隔，避免触发 WAF 或对服务造成影响
