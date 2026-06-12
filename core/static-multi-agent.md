# vibe-csa 静态多 Agent 方案

本文档定义了 vibe-csa 使用的 Stage 1 静态审计 agent 拆分方案。

Stage 1 开始前，主流程必须先识别项目语言，并选择对应静态审计插件目录：

| 语言 | 插件目录 | 入口文件 |
| --- | --- | --- |
| Java/Kotlin | `{SKILL_ROOT}/plugins/java/` | `{SKILL_ROOT}/plugins/java/SKILL.md` |
| Python | `{SKILL_ROOT}/plugins/python/` | `{SKILL_ROOT}/plugins/python/SKILL.md` |
| PHP | `{SKILL_ROOT}/plugins/php/` | `{SKILL_ROOT}/plugins/php/SKILL.md` |
| Go | `{SKILL_ROOT}/plugins/go/` | `{SKILL_ROOT}/plugins/go/SKILL.md` |
| 其他 | `{SKILL_ROOT}/plugins/_generic/` | `{SKILL_ROOT}/plugins/_generic/SKILL.md` |

静态子 Agent 开始审计前，子 Agent 应基于”自身角色“与”关注点“，参考静态审计插件目录中的 `SKILL.md` 文件开展审计，但不得将其视为封闭枚举清单，仍需结合实际代码进行独立判断。

若环境缺少 `ripgrep`，可使用 `Grep` 作为等价文本检索工具；若环境缺少 `semgrep`，则退化为 `Grep` 预筛选结合源码细读的分析路径。

## 阶段边界

| 阶段 | Agent 职责 | 回填骨架文件 |
| --- | --- | --- |
| Stage 1 静态审计 | 并行的领域 agent 检查源代码 | `workDir/agent-results/*.json`|

静态 agent 绝不能写入运行时响应。Stage 1 finding 必须保持静态-only 初始状态：`status="HYPOTHESIS"`、`finding_class="code_only"`、`poc.steps=[]`、`poc.result="pending"`。

## Stage 1 Agent 拆分（须严格遵守以下角色分配）

以下定义 Stage 1 各静态 Agent 的角色分配；每个 Agent 的 **必须遵守** 的三阶段规则见下文。

| Agent 标识名 | Agent 专家角色 | 关注点 |
| --- | --- | --- |
| `static-injection` | 注入利用面审计专家 | SQL 注入、命令注入、代码注入、SSTI、表达式注入、LDAP/XPath 注入、NoSQL 注入、GraphQL 注入、ORM/HQL/JPQL 注入、Header/CRLF 注入、反射型 XSS、存储型 XSS、DOM XSS、HTTP 参数污染、SSI 注入 |
| `static-auth` | 认证授权与接口访问控制审计专家 | 登录绕过、API 接口鉴权缺失、对象级/功能级授权缺陷、垂直/水平越权与提权、字段级授权缺陷、API 响应敏感字段越权暴露、Session/JWT/OAuth/OIDC 问题、会话固定、多租户隔离缺失、API Key/签名认证缺陷、密码重置/找回流程缺陷、短信/邮箱验证码校验缺陷、OAuth 回调校验缺陷、暴力破解、弱密码、Cookie 验证错误 |
| `static-file-ssrf` | 请求目标与文件访问链路审计专家 | SSRF、上传、任意文件读写、任意文件创建/删除、路径穿越、文件包含、XXE、URL 校验缺陷、URL 重定向、开放重定向链入 SSRF、重定向跟随导致的 SSRF、HTTP请求走私、Host/绝对 URI 信任、Zip Slip、符号链接/临时文件风险、下载功能任意文件读取、对象存储签名 URL 滥用 |
| `static-deser` | 反序列化与危险对象处理审计专家 | Java/PHP/Python 反序列化、JNDI、对象注入、危险 gadget 链、Fastjson/Jackson、YAML、XMLDecoder、不安全对象绑定、多态类型绑定滥用、危险 Bean/对象自动绑定、危险反射/类加载 |
| `static-logic` | 业务逻辑与状态机安全审计专家 | 支付篡改、价格/库存/优惠券篡改、订单金额计算缺陷、状态绕过、审批流绕过、竞态条件、重放与幂等缺失、CSRF、Webhook 伪造、批量滥用、批量导入导出越权、限流/配额绕过、注册/邀请/优惠券薅羊毛、账户合并/租户切换逻辑错误。主审计路径为入口盘点、权限与对象归属检查、敏感字段可写性检查、状态机与跨动作链路检查，`sinks` 仅作辅助线索 |
| `static-info` | 敏感信息暴露与安全配置审计专家 | 密钥泄露、硬编码凭据、弱加密、不安全随机数、错误证书校验、调试/管理接口暴露、错误信息泄露、CORS、安全响应头缺失、缓存投毒相关配置风险、CSP 缺失或配置不当、点击劫持防护缺失、Swagger/GraphQL introspection 暴露、目录索引/备份文件暴露


## 每个 Agent **必须遵守** 的四阶段规则

### 阶段1：生成静态骨架文件

**必须遵循**：在开始审计前，每个静态 agent 必须先使用 `{SKILL_ROOT}/scripts/prepare_static_aegnt_result.py` 生成自己的静态审计骨架文件。

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

### 阶段2：读取 code map

优先读取：

```text
workDir/agent-results/agent-static-code-map.json
```

重点关注：

- `summary.config_files`
- `config_refs`
- `external_boundaries`
- `entrypoints`
- `operations`
- `coverage.high_risk_modules`
- `coverage.known_gaps`

如果文件存在，应先基于 code map 筛选审计目标，避免从零扫描全仓库。

如果 code map 不存在、为空或明显不完整，则退化为源码检索与源码细读，并在结果中记录覆盖缺口。


### 阶段3：回填静态骨架文件

**必须遵循**：

- 铁律：每个 Agent 需要将各自的骨架文件的所有字段全部回填（除了 Stage 2 需要漏洞动态验证的数据）
- 铁律：需要基于审计结果回填，不得回填虚假数据
- 骨架文件字段和占位值可参考样例 `references/agent-result-example.json`
- `findings` 可根据真实审计结果包含一条或多条项目
- 每个 Agent 在成功发现到漏洞后，一定要在生成的json文件中包含修复建议，json字段包括审计语言：`fix.language`、当前代码片段：`fix.before`、代码修复参考：`fix.after`
- 每个 Agent 须参考 `core/coverage-gate.md` 记录各自可确认的覆盖信息；如无法准确汇总全局覆盖率，不要臆造最终 `coverage_summary`，最终汇总值由汇总阶段统一生成
- 当真实发现拆分为多个项目时，保留中文标题、中文 `vuln_type`、漏洞分类标签，并优先使用 `{SKILL_ROOT}/references/bug-categories.md` 中的 `vuln_type` 值
- `title` 漏洞标题里不要有漏洞编号，优先使用“漏洞类型 + 关键对象/位置”的短语结构，长度尽量控制在 24 个汉字以内
- 回填说明性文本字段（如：`title`、`description`、`impact`），默认回填为中文，但不得翻译路径、参数名、字段名、URL 中的技术片段
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

### 阶段4：最终格式校验

**必须遵循**：每个 Agent 骨架文件完成所有静态审计、所有回填之后，须参考样例 `references/agent-result-example.json`，对各自的骨架文件进行严格的格式校验，须校验层级关系是否正确、所有字段是否符合样例 JSON 格式。

