# vibe-csa 静态多 Agent 方案

本文档定义了 vibe-csa 使用的 Stage 1 静态审计 agent 拆分方案。

在拆分 Stage 1 工作之前，先识别项目语言，并读取对应插件目录中的静态审计规则：

| 语言 | 插件目录 |
| --- | --- |
| Java/Kotlin | `plugins/java/` |
| Python | `plugins/python/` |
| PHP | `plugins/php/` |
| 其他 | `plugins/_generic/` |

在选定的插件目录中，先读取 `SKILL.md`、`tier-rules.md`、`sinks.md` 和 `frameworks.md`。

## 阶段边界

| 阶段 | Agent 职责 | 输出 |
| --- | --- | --- |
| Stage 1 静态审计 | 并行的领域 agent 检查源代码 | `workDir/agent-results/*.json`|

静态 agent 绝不能写入运行时响应。Stage 1 finding 必须保持静态-only 初始状态：`status="HYPOTHESIS"`、`finding_class="code_only"`、`poc.steps=[]`、`poc.result="pending"`。

## Stage 1 Agent 拆分

| Agent | 领域 | 关注点 |
| --- | --- | --- |
| `static-injection` | 注入类 | SQL 注入、命令注入、代码注入、SSTI、表达式注入、LDAP/XPath 注入 |
| `static-auth` | 认证与授权 | 登录绕过、IDOR、权限提升、Session/JWT/OAuth 问题 |
| `static-file-ssrf` | 请求伪造与文件访问 | SSRF、上传、任意文件读写、路径穿越、文件包含、XXE |
| `static-deser` | 反序列化 | Java/PHP/Python 反序列化、JNDI、对象注入、危险 gadget 链 |
| `static-logic` | 业务逻辑 | 支付篡改、状态绕过、竞态条件、CSRF、Webhook 伪造、批量滥用 |
| `static-info` | 信息泄露与密码学 | 密钥泄露、弱加密、调试接口、错误信息泄露、CORS、安全响应头 |

较小项目也应至少启动 4 个 agent。标准模式和深度模式通常应启动全部 6 个。


## 每个 Agent 必须遵守的共同规则

### 生成静态骨架

在开始审计前，每个静态 agent 必须先使用 `{SKILL_ROOT}/scripts/prepare_static_aegnt_result.py` 生成自己的静态审计骨架文件。

示例：

```bash
python {SKILL_ROOT}/scripts/prepare_static_aegnt_result.py {agentname}
```

具体示例：

```bash
python {SKILL_ROOT}/scripts/prepare_static_aegnt_result.py static-deser
```

骨架文件会写入：

```text
workDir/agent-results/agent-{agentname}.json
```

例如，`static-deser` agent 会写入：

```text
workDir/agent-results/agent-static-deser.json
```

### 回填数据

须遵循：

- 铁律：每个 Agent 需要将各自的骨架文件的所有字段全部回填（除了 Stage 2 需要漏洞动态验证的数据）
- 铁律：需要基于审计结果回填，不得回填虚假数据
- 骨架文件字段和占位值可参考样例 `references/agent-result-example.json`
- `findings` 可根据真实审计结果包含一条或多条项目
- 每个 Agent 在成功发现到漏洞后，一定要在生成的json文件中包含修复建议，json字段包括审计语言：`fix.language`、当前代码片段：`fix.before`、代码修复参考：`fix.after`
- 每个 Agent 须遵循 `core/coverage-gate.md`，计算代码审计覆盖率，然后将结果更新至 `workDir/agent-results/*.json` 的 `coverage_summary`字段
- 当真实发现拆分为多个项目时，保留中文标题、中文 `vuln_type`、漏洞分类标签，并优先使用 `{SKILL_ROOT}/references/bug-categories.md` 中的 `vuln_type` 值
- 回填说明性文本字段（如：`description`、`impact`），默认回填为中文，但不得翻译路径、参数名、字段名、URL 中的技术片段
- 回写完成后，确保最终 JSON 文件在语法上仍然有效


静态 agent 不得：

- 填写 `poc.steps[].response`
- 将纯代码发现标记为 `CONFIRMED`
- 将 `finding_class` 设为 `runtime_verified`
- 在没有运行时证据的情况下虚构 `evidence_level=L2/L3`
- 直接编写最终报告


重复项处理：

| 条件 | 处理方式 |
| --- | --- |
| 相同 `file + line_start + vuln_type` | 视为重复项，保留置信度更高的项目，并合并 evidence refs / reviewed files |
| 相同 `file + line_start` 但 `vuln_type` 不同 | 两者都保留 |
| 相同 `file + vuln_type` 且行号接近 | 两者都保留为相关发现 |
| 不同 agent 给出不同解读 | 两者都保留，交由报告读者或 Stage 2 决定 |

