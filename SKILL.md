---
name: vibe-csa
description: "白盒代码安全审计能力，三阶段工作流程：静态代码审计、动态漏洞验证、报告生成，多智能体静态审计输出统一 JSON 格式数据；动态验证将完整 HTTP 请求与响应数据写入同一份 JSON；最终可基于该 JSON 文件导出 HTML、Word 格式审计报告。触发场景：代码审计、安全评审、漏洞评估、VIBE-CSA 专项检测。"
metadata:
  author: helloworld
  version: "1.0.0"
  date: 2026-05-20
---
# vibe-csa: 代码安全审计三阶段协议

vibe-csa 使用统一 JSON 贯穿三个阶段。阶段必须严格划分，但动态验证是可选阶段：

1. **静态代码审计**：多 Agent 并行审计，每个 Agent 输出一个 JSON 文件，JSON 格式参考 `references/agent-result-example.json` 文件。
2. **漏洞动态验证（可选）**：基于静态合并 JSON 构造 PoC，对目标环境进行动态验证，并写回完整 HTTP 请求/响应。
3. **报告生成**：基于同一个 JSON 格式生成最终审计报告。

允许的执行路径：

- **只做代码审计**：Stage 1 -> Stage 3，生成静态审计最终 JSON 报告。
- **代码审计 + 动态验证**：Stage 1 -> Stage 2 -> Stage 3，生成带运行时证据的最终 JSON 报告。

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
| `{SKILL_ROOT}/core/multi-agent.md` | 多 Agent 分工、输出路径、合并规则 |

根据目标项目的语言，读取以下对应语言的知识库，方便后续开展静态审计：

| 语言 | 插件目录 |
| --- | --- |
| Java/Kotlin | `plugins/java/` |
| Python | `plugins/python/` |
| PHP | `plugins/php/` |
| 其他语言 | `plugins/_generic/` |

插件目录中优先读取 `SKILL.md`、`tier-rules.md`、`sinks.md`、`frameworks.md`。

## 三阶段总览

```text
Stage 1 静态代码审计
  输入: 源码路径
  动作: 语言识别、Tier 分层、sink 预扫描、多 Agent 并行审计
  输出: workDir/agent-results/*.json
        workDir/static-merged.json

Stage 2 漏洞动态验证（可选）
  输入: workDir/static-merged.json + 目标 URL/凭据
  动作: 为单条 finding 创建工作文件，按验证轮次生成并修正请求，由执行器发送真实请求并记录证据，必要时进入受控 refinement / bypass
  输出: workDir/dynamic-verified.json

Stage 3 报告生成
  输入: workDir/static-merged.json 或 workDir/dynamic-verified.json
  动作: 执行报告生成脚本
  输出: HTML 和 Word 报告
```

其中 Stage 1 重点约束静态 finding 结构，Stage 2 重点约束运行时证据写回与状态一致性。

## 全局硬规则

1. 静态审计阶段每个 Agent 必须把结果写入独立 JSON 文件，禁止只在对话中输出。
2. 所有阶段使用同一个 finding JSON 格式。静态-only 报告中，`poc.steps=[]`、`poc.result="pending"`、`status="HYPOTHESIS"`、`finding_class="code_only"` 是合法最终状态。
3. 静态审计过程中，子agent发现漏洞后，生成的json文件一定要包含修复内容，包括审计语言：`fix.language`、当前代码片段：`fix.before`、代码修复参考：`fix.after`。
4. 动态验证成功时，必须把完整 HTTP 请求、关键响应片段写入 `poc.steps[]`，包括结构化字段和 `request.raw`/`response.raw` 原始报文。某些漏洞需要多个步骤结合才能利用成功，可以保留多个 step。
5. `poc.steps[].response` 必须来自真实请求或验证脚本写入，禁止编造。
6. 最终 `poc.evidence` 必须引用响应原文片段，不能只写“返回成功”“存在漏洞”。
7. 没有 L2/L3 运行时证据时，`status` 必须为 `HYPOTHESIS`，`finding_class` 必须为 `code_only`；这不阻止生成代码审计最终报告。
8. 文件上传/任意文件写入必须访问到上传或写入后的文件；RCE 必须看到命令输出。
9. 遇到登录验证码、MFA、SSO 时，只能使用 `scripts/extract_credentials.py` 让用户在浏览器中手动登录，禁止脚本猜测或破解验证码。

## 阶段入口

### Stage 1 静态代码审计

#### Stage 1.1 multi Agent
- 必须根据 `{SKILL_ROOT}/core/multi-agent.md` 创建多 Agent 独立分工
- 每个 Agent 开始审计前，须使用 `scripts/prepare_static_aegnt_result.py` 生成静态审计骨架文件，脚本运行示例：`python {SKILL_ROOT}/scripts/prepare_static_aegnt_result.py agent-{agentname}.json`，骨架文件会保存至 `workDir/agent-results/*.json`，比如 `static-deser`agent，其中`agent-{agentname}.json` 为 `agent-static-deser.json`
- 铁律：每个 Agent 需要将各自的骨架文件的所有字段全部回填（需要基于审计结果回填，不得回填虚假数据），骨架文件字段意义可参考 `references/agent-result-example.json` 样例
- `findings`字段可结合实际漏洞审计结果扩展多条，漏洞标题、中文漏洞类型、bug 分类标签、`vuln_type` 优先从 `references/bug-categories.md` 选择
- 每个 Agent 须遵循 `core/coverage-gate.md`，计算代码审计覆盖率，然后将结果更新至 `workDir/agent-results/*.json` 的 `coverage_summary`字段
- 每个 Agent 在成功发现到漏洞后，一定要在生成的json文件中包含修复建议，json字段包括审计语言：`fix.language`、当前代码片段：`fix.before`、代码修复参考：`fix.after`
- 每个 Agent 完成 `workDir/agent-results/*.json` 文件所有回填之后，需要检查避免存在json文件格式错误

#### Stage 1.2 合并multi-agent生成的结果
- 当所有第一阶段的 `multi-agent` 执行完审计任务之后，必须使用 `merge_static_results.py` 汇总 `workDir/agent-results/*.json` 生成 `static-merged.json`。若脚本合并失败，必须对照 `references/agent-result-example.json` 与 `references/agent-result-checklist.md` 修复 `workDir/agent-results/*.json`，逐个完成单文件自检后再重新执行合并。

汇总脚本命令示例：

```bash
python {SKILL_ROOT}/scripts/merge_static_results.py \
  --input-dir workDir/agent-results \
  --output workDir/static-merged.json \
  --source-path {source_path} \
  --target-url {target_url}
```

### Stage 2 漏洞动态验证（可选）

这是可选阶段。只有用户提供目标环境并要求动态验证时才执行。目标是把静态发现转化为可证明或可否定的运行时证据。

#### Stage 2.1 创建 dynamic-verifier Agent
建议单独创建一个 `dynamic-verifier` Agent。它一次只处理单条 finding，不继承上个阶段静态审计对话上下文；默认只读取当前验证所需的最小工作集。

职责：
- 读取 `workDir/static-merged.json` 中待验证的 finding，更新 `workDir/findings/FINDING-xxx.poc.json`
- 基于 `analysis.attack_surface`、`analysis.data_flow`、`analysis.security_controls`、`analysis.bypass_strategy`、`analysis.verification_plan` 生成当前轮验证步骤
- 由执行器发送真实请求并写回完整 HTTP request；response 只需要保留关键信息，漏洞利用成功的证明
- 多步骤利用时只保留验证成功的 `poc.steps[]`，但这些 step 归属于同一轮验证 attempt
- 在证据不足时写入 `failure_log[]`、更新 `dynamic_verification.attempts[]`，并决定是否进入下一轮 refinement
- 允许对测试过程中自己创建的数据、自己上传的文件、自己插入的记录做删除、更新、清理操作，以便验证删除/编辑/恢复/回收类漏洞；禁止对原始业务数据、他人数据、生产数据做破坏性操作。允许上传文件进行文件上传测试。

#### Stage 2.2 必须遵守的运行方式

1. 初始化每个漏洞工作文件（finding 文件）
   - 生成 finding 文件最小骨架：可调用 `scripts/prepare_dynamic_pocs.py` 生成动态验证的骨架文件 `workDir/findings/FINDING-xxx.poc.json`，方便后续漏洞验证的结果回填

   ```bash
   python {SKILL_ROOT}/scripts/prepare_dynamic_pocs.py \
     --input workDir/static-merged.json \
     --output-dir workDir/findings
   ```

2. 获取登录凭据
   - 若用户提供账号密码，在执行动态漏洞验证前，需要先获取到目标网站登录凭据，方便后续漏洞验证过程，可以复用凭据
   - 若用户提供账号密码，或存在 `analysis.attack_surface.auth_required=true`，或存在 `required_role`，必须先调用 `scripts/prepare_auth_session.py` / `scripts/extract_credentials.py`，让用户在浏览器中手动登录并生成 `workDir/sessions/creds.json`

3. 动态漏洞验证
   - 铁律：对逐个 finding 文件进行漏洞验证与更新，完成一个再进行下一个
   - 漏洞验证须参考poc构造指导文件：`{SKILL_ROOT}/core/poc-construction.md`，验证过程，漏洞利用成功证据判断，须参考：`{SKILL_ROOT}/references/exploit-success-signatures.md`
   - 若漏洞验证失败，可参考 `{SKILL_ROOT}/pentest_skills/INDEX.md` 做定向增强，但不能虚假编造 request/response，不跳出当前 finding 范围
   - 漏洞验证成功，须回填 finding 文件，须参考 `evidence-contracts.md`：约束 request/response、`poc.evidence`、`dynamic_verification.final_evidence` 的写回方式
   - 单个 finding 文件完成所有回填之后，需要检查避免存在json文件格式错误

4. 最后，汇总所有漏洞验证结果，生成 `workDir/dynamic-verified.json`
   - 直接执行 `verify_vuln.py` 脚本汇总所有漏洞验证结果,脚本举例：`python {SKILL_ROOT}/scripts/verify_vuln.py --merge workDir/findings/*.poc.json --into workDir/dynamic-verified.json`

#### 2.3 硬约束
- Stage 2 只能补充运行时证据，不得重写 Stage 1 的静态基线字段结构
- 证据不足时保留 `HYPOTHESIS`；仅在漏洞验证成功时升级为 `CONFIRMED`
- 请求发送工具不限于某个固定命令，`curl`、统一执行器或验证脚本均可，但必须按规范回填真实请求和响应
- 本阶段阶段前，需要参考 `references/dynamic-init-example.json` 文件，修复json文件，目的是确保格式正确，不得构造假数据、新增字段！

### Stage 3 报告生成

#### 如果只执行了 Stage 1 静态审计
静态-only示例，生成html以及word报告

```bash
python {SKILL_ROOT}/scripts/vibe_csa_html.py -i workDir/static-merged.json -o workDir/reports/vibe-csa-static-{YYYYMMDD-HHmmss}.html
python {SKILL_ROOT}/scripts/vibe_csa_report.py -i workDir/static-merged.json -o workDir/reports/vibe-csa-static-{YYYYMMDD-HHmmss}.docx

```

#### 如果执行了静态审计和动态漏洞验证

动态漏洞验证示例，生成html以及word报告

```bash
python {SKILL_ROOT}/scripts/vibe_csa_html.py -i workDir/dynamic-verified.json -o workDir/reports/vibe-csa-dynamic-{YYYYMMDD-HHmmss}.html
python {SKILL_ROOT}/scripts/vibe_csa_report.py -i workDir/dynamic-verified.json -o workDir/reports/vibe-csa-dynamic-{YYYYMMDD-HHmmss}.docx
```

## 状态文件

长任务必须维护：

```text
workDir/
  audit-state.json
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

## 安全规则

1. **严格限制目标域名**，不测试范围外的任何地址
2. **不执行破坏性操作**：不删除数据、不修改业务数据、不发起 DoS
3. **凭证安全**：如果`sessions/*.json` 包含敏感信息，测试完成后提醒用户删除
4. **速率控制**：请求间保持合理间隔，避免触发 WAF 或对服务造成影响
