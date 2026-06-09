# 质量检查器

每个 Stage 完成后，必须执行对应的质量检查。本文件只定义三阶段检查口径；若与旧 `Phase` 术语冲突，以 `core/pipeline.md` 为准。

## Stage 1 检查

### 1. 输入与覆盖

- [ ] `audit-metrics.json` 存在且包含 `language`、`total_files`、`total_loc`、`ealoc`
- [ ] EALOC > 0
- [ ] T1 文件列表非空
- [ ] 语言检测结果与实际文件扩展名一致
- [ ] T1 覆盖率 = 100%
- [ ] 未覆盖文件清单完整列出
- [ ] 如门禁失败，已回到 Stage 1 静态审计补扫

### 2. 静态发现质量

- [ ] `scenario-tags.json` 存在，所有 T1 入口都有场景标签
- [ ] `dependency-security.md` 存在，包含构建文件解析结果
- [ ] 框架检测正确，无虚构框架名称
- [ ] 每条 finding 都包含 file:line 引用
- [ ] 未发现虚构的代码路径或函数调用
- [ ] 每个启用 Agent 都生成了 JSON 结果文件
- [ ] 合并后的 `workDir/static-merged.json` 通过 schema 校验
- [ ] 每条 finding 都包含 `analysis.source`、`analysis.sink`、`analysis.data_flow`、`analysis.attack_surface`、`analysis.verification_plan`
- [ ] `poc.steps=[]` 且 `poc.result="pending"` 仅作为静态占位，不含伪造 response
- [ ] 已执行反幻觉规则 10/11，配置类问题未被误标为高置信漏洞

## Stage 2 检查（可选）

### 1. 动态验证过程

- [ ] 每个待验证 finding 都有独立的 `workDir/static-findings/FINDING-*.json` 与 `workDir/dynamic-findings/FINDING-*.json`（例如 `FINDING-001.json`）
- [ ] 每轮验证都写入真实 request/response 或明确的失败轨迹
- [ ] 多步骤漏洞保留完整 `poc.steps[]`
- [ ] `dynamic_verification.attempts[]` 与实际验证轮次一致
- [ ] 对 401/403/WAF/验证码等阻断情况有明确记录

### 2. 证据与结论

- [ ] 每个 `poc.result="success"` 的 finding 都命中 L2 或 L3 证据标准
- [ ] 禁止仅凭 HTTP 200/302/500 状态码标记 success
- [ ] `poc.evidence` 引用 response.body 中可直接证明漏洞存在的原文片段
- [ ] `poc.result="failure"` 的 finding 包含 `poc.failure_log[]` 或等价失败轨迹
- [ ] 不存在仅靠 L0/L1 证据却升级为 `CONFIRMED` 的情况
- [ ] 文件上传 / 任意文件写入类 finding 已按 `core/upload-verification.md` 完成访问或执行验证
- [ ] 受控 refinement / bypass 只在基线响应已落盘且证据不足时触发

## Stage 3 检查

- [ ] `vibe-csa-{timestamp}.json` 存在且通过 Schema 验证
- [ ] 审计概要、漏洞统计、语言/框架信息完整
- [ ] 每个 `CONFIRMED` finding 满足 `core/evidence-contracts.md`
- [ ] 每个 `HYPOTHESIS` finding 包含不确定因素说明
- [ ] 所有代码引用均来自 Read 输出
- [ ] 所有 file:line 引用可追溯到实际文件
- [ ] DKTSS 与严重程度字段完整
- [ ] 未出现未替换的占位符

## 失败处理

质量检查失败时：
1. 列出不通过的检查项
2. 修复对应问题
3. 重新执行检查
4. 最多重试 2 次，超过后在最终报告中标注“质量检查未完全通过”
