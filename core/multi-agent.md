# vibe-csa 多智能体索引

该文件现已改为一个轻量级索引。详细规则已按阶段拆分，以便职责划分更加清晰。

## 文档

- Stage 1 静态审计：`{SKILL_ROOT}/core/static-multi-agent.md`
- Stage 2 动态验证：`{SKILL_ROOT}/core/dynamic-multi-agent.md`

## 何时阅读

- 当创建或运行 Stage 1 静态 Agent、生成 `workDir/agent-results/*.json`，或合并到 `workDir/static-merged.json` 时，请阅读 `static-multi-agent.md`。
- 当创建或运行 Stage 2 的 `dynamic-verifier` Agent、从 `workDir/dynamic-state.json` 领取任务，读取 `workDir/static-findings/FINDING-*.json`，或写入 `workDir/dynamic-findings/FINDING-*.json` 时，请阅读 `dynamic-multi-agent.md`。
