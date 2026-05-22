# vibe-csa v3 三阶段流水线

本流水线将旧的多阶段审计流程收敛为三个严格阶段：

1. 静态代码审计
2. 漏洞动态验证（可选）
3. 报告生成

三个阶段共用 `{SKILL_ROOT}/vibe-csa-schema.json`。任何阶段的 finding 都必须保持同一结构。

允许两条执行路径：

```text
代码审计报告路径:
Stage 1 静态代码审计 -> Stage 3 报告生成

带验证报告路径:
Stage 1 静态代码审计 -> Stage 2 漏洞动态验证 -> Stage 3 报告生成
```

Stage 2 是可选阶段。用户只要求代码审计时，不要强制动态验证；直接把 `workDir/static-merged.json` 作为最终报告输入。

## 运行模式

| 模式 | 用途 | 静态审计范围 | 动态验证要求 |
| --- | --- | --- | --- |
| `quick` | 快速检查、变更验证 | T1 + 高危 sink | 只验证 high/critical |
| `standard` | 默认日常审计 | T1+T2 + 完整 sink 预扫描 | 验证所有可验证 high/critical，抽样 medium |
| `deep` | 上线前或高敏项目 | T1+T2+T3 + 完整 Agent | 验证所有可验证 high/critical，抽样 medium，失败时必须尝试绕过 |

## Stage 1: 静态代码审计

### 输入

- 源码路径
- 扫描模式
- 可选目标 URL
- 可选凭据说明

### 步骤

1. 建立 `workDir/` 工作目录。
2. 识别语言、框架、依赖、入口文件。
3. 按插件规则生成 `file_manifest.json`：
   - T1: Controller、Route、Handler、API 入口
   - T2: Service、Middleware、Helper、Model
   - T3: Entity、DTO、Config、低风险辅助代码
   - SKIP: 第三方库、构建产物、测试样例
4. 使用 ripgrep/semgrep 生成 sink 预扫描结果到 `workDir/sink_hits/`。
5. 并行启动多个 Agent。每个 Agent 必须写入 `workDir/agent-results/{agent}.json`。
6. 调用合并脚本：

```bash
python {SKILL_ROOT}/scripts/merge_static_results.py \
  --input-dir workDir/agent-results \
  --output workDir/static-merged.json \
  --source-path {source_path} \
  --target-url {target_url}
```

### Stage 1 输出

```text
workDir/file_manifest.json
workDir/sink_hits/*.txt
workDir/agent-results/*.json
workDir/static-merged.json
```

### Stage 1 门禁

- 每个启用的 Agent 必须产生 JSON 文件。
- 所有 JSON 必须能解析。
- 合并后的 `workDir/static-merged.json` 必须符合 schema。
- 每条 finding 必须包含：
  - `location.snippet`
  - `analysis.source`
  - `analysis.sink`
  - `analysis.data_flow`
  - `analysis.attack_surface`
  - `analysis.verification_plan`
  - `static_evidence`
  - `poc.steps=[]`
  - `poc.result="pending"`

## Stage 2: 漏洞动态验证（可选）

只有满足任一条件时执行：

- 用户明确要求动态验证、PoC 验证、漏洞复现。
- 用户提供目标 URL 并要求验证运行时影响。
- 审计任务模式明确为“代码审计 + 动态验证”。

如果用户只要求代码审计，跳过 Stage 2，直接进入 Stage 3。

### 输入

- `workDir/static-merged.json`
- 目标 URL
- 可选 `workDir/sessions/creds.json`

### 步骤

1. 为每条需要验证的 finding 建立独立工作文件：

```text
workDir/findings/FINDING-001.poc.json
workDir/findings/FINDING-002.poc.json
```

2. 如无现成工作文件，可调用 PoC 准备脚本，根据静态审计结果生成最小骨架：

```bash
python {SKILL_ROOT}/scripts/prepare_dynamic_pocs.py \
  --input workDir/static-merged.json \
  --output-dir workDir/findings
```

   最小骨架要求：
   - 输出文件必须是**完整单漏洞 JSON**，后续可直接被动态验证 Agent 持续更新
   - 必须复制 Stage 1 已确认的静态字段，不得丢失 `analysis`、`static_evidence`、`remediation`、`fix`
   - 初始化阶段应保持：
     - `status="HYPOTHESIS"`
     - `evidence_level="L0"`
     - `finding_class="code_only"`
     - `dynamic_verification.state="not_started"`
     - `dynamic_verification.attempts=[]`
     - `dynamic_verification.final_evidence={"proof_type":"none","summary":"","snippets":[]}`
     - `poc.steps=[]`
     - `poc.result="pending"`
     - `poc.failure_log=[]`
   - 初始化器只能补充稳定辅助字段，如 `x_signature_type`、`x_unique_marker`
   - 初始化器不得预生成固定 payload、固定 step、伪造 attempt、伪造 request/response
   - `references/FINDING-001.poc.json` 仅作为终态结构样例；初始化结果必须与其兼容，但不能假装已经完成动态验证

3. 动态验证 Agent 一次只读取单个 finding，按 `core/poc-construction.md` 回读源码并生成当前轮验证步骤；不要依赖固定模板覆盖所有场景。
4. 一轮验证记为一个 `attempt`；同一轮内可以包含多个 `poc.steps[]`。
5. 每个 PoC step 必须写入完整 request：
   - `method`
   - `url`
   - `headers`
   - `params`
   - `body`
   - `cookies`
   - `raw`
6. 调用验证脚本或统一执行器发送请求并写入真实 response：

```bash
python {SKILL_ROOT}/scripts/verify_vuln.py \
  workDir/findings/FINDING-001.poc.json \
  --target {target_url} \
  --credentials workDir/sessions/creds.json \
  --role {role}
```

7. 多步骤利用必须记录多个 `poc.steps[]`，例如：
   - 上传/写入文件
   - 访问上传/写入后的文件
   - 触发命令执行或读取敏感数据
8. 如果响应不足以证明漏洞存在，必须回读源码，调整参数、认证上下文、前置步骤或 payload，并写入 `failure_log[]` 与 `dynamic_verification.attempts[]`。
9. 验证轮次规则：
   - `quick`：最多 2 轮，只验证 high/critical
   - `standard`：最多 3 轮，验证所有可验证 high/critical，并抽样 medium
   - `deep`：最多 5 轮，验证所有 finding；只有在已有真实 request/response 但证据不足，或已识别明确阻断点时，才允许进入受控 bypass
10. 成功时立即把单漏洞文件更新为终态：

```json
{
  "poc": {"result": "success"},
  "status": "CONFIRMED",
  "finding_class": "runtime_verified",
  "evidence_level": "L2 or L3"
}
```

11. 失败或证据不足时，单漏洞文件保持：

```json
{
  "poc": {"result": "failure"},
  "status": "HYPOTHESIS",
  "finding_class": "code_only",
  "evidence_level": "L0 or L1"
}
```

12. 合并动态验证结果：

```bash
python {SKILL_ROOT}/scripts/verify_vuln.py \
  --merge workDir/findings/*.poc.json \
  --into workDir/dynamic-verified.json
```

13. `workDir/dynamic-verified.json` 保留动态验证后的合并结果，`workDir/static-merged.json` 保持为静态审计基线。

### Stage 2 输出

```text
workDir/findings/*.poc.json
workDir/dynamic-verified.json
```

### Stage 2 证据门禁

不能只凭 HTTP 200、无报错、返回成功判断漏洞成立。
`response` 必须来自真实请求；`poc.evidence` 和 `dynamic_verification.final_evidence` 必须引用响应原文片段或命中签名。

| 漏洞类型 | 必须看到的证据 |
| --- | --- |
| 文件上传/任意文件写入 | 能访问到上传或写入后的文件，响应包含唯一 marker |
| 文件上传 RCE | 上传/写入成功、访问到文件、看到命令输出 |
| 命令执行 | 响应中出现真实命令输出，例如 `uid=...` |
| SQL 注入 | 数据差异、错误信息、时间差异或可提取数据 |
| SSRF | 内网/metadata 响应、OOB 回连、协议服务指纹 |
| IDOR | 低权限角色读取或修改到其他用户资源 |
| 存储型 XSS | 存储后再访问页面，响应包含唯一 payload |

验证成功时：

```json
{
  "poc": {"result": "success"},
  "status": "CONFIRMED",
  "finding_class": "runtime_verified",
  "evidence_level": "L2 or L3"
}
```

验证失败或证据不足时：

```json
{
  "poc": {"result": "failure"},
  "status": "HYPOTHESIS",
  "finding_class": "code_only",
  "evidence_level": "L0 or L1"
}
```

## Stage 3: 报告生成

### 输入

- 静态 only 路径：`workDir/static-merged.json`
- 带验证路径：`workDir/dynamic-verified.json`

### 执行脚本输出报告方法
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
## 状态传递

每个阶段结束更新 `workDir/audit-state.json`：

```json
{
  "version": "vibe-csa-v3",
  "stage": "static_audit",
  "status": "PASS",
  "mode": "standard",
  "output_files": [
    "workDir/static-merged.json"
  ],
  "metrics": {
    "findings": 5,
    "runtime_verified": 0,
    "code_only": 5
  },
  "next_action": "Start dynamic verification"
}
```
