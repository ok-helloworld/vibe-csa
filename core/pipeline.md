# vibe-csa 三阶段流水线摘要

本文件仅作为流程摘要和导航说明。
具体执行规则以 `{SKILL_ROOT}/SKILL.md` 为准。

## 执行路径

```text
代码审计报告路径:
Stage 1 静态代码审计 -> Stage 3 报告生成

带验证报告路径:
Stage 1 静态代码审计 -> Stage 2 漏洞动态验证 -> Stage 3 报告生成
```

## Stage 1: 静态代码审计

目标：基于源码生成静态漏洞发现结果。

核心流程：

```text
源码路径
  ↓
static-code-map 生成代码事实图谱
  ↓
6 个静态审计 Agent 并行审计
  ↓
合并静态结果
  ↓
去重
  ↓
workDir/static-merged.json
```

关键产物：

```text
workDir/agent-results/agent-static-code-map.json
workDir/agent-results/agent-static-injection.json
workDir/agent-results/agent-static-auth.json
workDir/agent-results/agent-static-file-ssrf.json
workDir/agent-results/agent-static-deser.json
workDir/agent-results/agent-static-logic.json
workDir/agent-results/agent-static-info.json
workDir/static-merged.json
```

说明：

- `agent-static-code-map.json` 是代码事实索引，不是漏洞结果文件。
- 6 个静态审计 Agent 应优先读取 `agent-static-code-map.json`，再按需回读源码。
- `agent-static-code-map.json` 不参与漏洞合并。
- 静态发现默认是代码级假设，运行时确认只在 Stage 2 完成。

## Stage 2: 漏洞动态验证（可选）

只有用户明确要求动态验证，或提供目标环境并要求验证运行时影响时执行。

核心流程：

```text
workDir/static-merged.json
  ↓
生成动态验证任务
  ↓
dynamic-verifier 并行验证
  ↓
写回运行时证据
  ↓
workDir/dynamic-verified.json
```

关键产物：

```text
workDir/static-findings/FINDING-*.json
workDir/dynamic-findings/FINDING-*.json
workDir/dynamic-state.json
workDir/dynamic-verified.json
```

说明：

- Stage 2 只验证 Stage 1 已发现的 finding。
- 不扩展新的静态审计任务。
- 证据不足时保持 `HYPOTHESIS`。
- 只有真实运行时证据充分时才升级为 `CONFIRMED`。

## Stage 3: 报告生成

根据执行路径选择报告输入：

```text
仅静态审计:
workDir/static-merged.json

静态审计 + 动态验证:
workDir/dynamic-verified.json
```

输出 HTML 和 Word 报告。

## 状态文件

长任务通过以下文件传递状态：

```text
workDir/audit-state.json
workDir/dynamic-state.json
```

`audit-state.json` 记录当前阶段、状态、关键输出和下一步动作。
`dynamic-state.json` 仅在 Stage 2 使用，用于动态验证任务调度。
