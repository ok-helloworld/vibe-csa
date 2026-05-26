# Agent Result Checklist

Stage 1 合并失败时，先回到 `workDir/agent-results/*.json` 排查，不要直接跳到后续阶段。

## 快速检查

- 顶层必须只有：`schema_version`、`audit.stage="static_audit"`、`findings[]`
- 每条 finding 必须保留静态结论：`status="HYPOTHESIS"`、`finding_class="code_only"`、`poc.steps=[]`、`poc.result="pending"`
- `confidence` 只能是：`high`、`medium`、`low`
- `location` 必须有：`file`、`line_start`、`snippet`
- `analysis` 必须有：`source`、`sink`、`data_flow`、`attack_surface`、`preconditions`、`security_controls`、`bypass_strategy`、`verification_plan`
- `static_evidence` 必须有：`evidence_refs`、`anti_false_positive`
- `remediation` 和 `fix` 不能为空对象

## 常见失败

- `path=...`：先对照 `vibe-csa-schema.json`
- `Additional properties are not allowed`：删除旧字段，或改写到标准字段
- `required property`：补齐必填字段
- `enum` 不匹配：检查 `severity`、`confidence`、`category`、`status`、`finding_class`
- `status=CONFIRMED` / `runtime_verified`：静态阶段禁止，必须改回 `HYPOTHESIS` / `code_only`

## 参考

- `references/agent-result-example.json`
- `core/static-multi-agent.md`
- `vibe-csa-schema.json`
- `scripts/merge_static_results.py`
