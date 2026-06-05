# vibe-csa v3 三阶段流水线

本流水线将旧的多阶段审计流程收敛为三个严格阶段：

1. 静态代码审计
2. 漏洞动态验证（可选）
3. 报告生成

允许两条执行路径：

```text
代码审计报告路径:
Stage 1 静态代码审计 -> Stage 3 报告生成

带验证报告路径:
Stage 1 静态代码审计 -> Stage 2 漏洞动态验证 -> Stage 3 报告生成
```

## Stage 1: 静态代码审计

### 输入

- 源码路径
- 可选目标 URL
- 可选凭据说明

### 步骤

1. 建立 `workDir/` 工作目录。
2. 识别语言、框架、依赖、入口文件。
3. 基于 `core\static-multi-agent.md` 创建、并行启动多个 Agent，若子 Agent 已提前创建，只需并行启动 6 个子Agent
4. 每个 Agent 使用 `prepare_static_aegnt_result.py` 脚本生成骨架文件
5. 每个 Agent 基于审计结果按规范回填骨架文件 `workDir/agent-results/agent-{agentname}.json`
6. 调用脚本 `merge_static_results.py` 合并 `workDir/agent-results`
7. 使用 `dedupe_static_merged.py` 去重 `workDir/static-merged.json`


### Stage 1 输出

```text
workDir/agent-results/*.json
workDir/static-merged.json
```

### Stage 1 门禁

- 每个启用的 Agent 必须产生 JSON 文件。
- 所有 JSON 必须能解析。
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


## Stage 3: 报告生成

执行脚本输出报告方法

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
