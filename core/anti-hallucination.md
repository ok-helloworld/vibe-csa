# 反幻觉 13 铁律（v3）

LLM 在代码审计中容易" hallucinate"——编造不存在的代码路径、错误引用不存在的函数、虚构调用链。以下 **13 条**铁律防止此类问题（前 9 条是核心反幻觉，10-12 是误报过滤，13 是实质性证据强制）。

> 规则 1/2/3/7/8/10/11/13 失败 → **强制 HYPOTHESIS**（含规则 13 的"无运行时签名命中" → `x_finding_class="code_only"`）；规则 4/5/9/12 失败 → 仅 `evidence_level` 降一档；规则 6 (CVE 联网) 失败 → 不降级，仅打 `CVE_UNVERIFIED` 标。详见 `core/pipeline.md` Step V-1 分级处理表。

## 规则 1：文件存在性验证

分析任何文件前，必须用 Read 工具确认文件实际存在。不能基于文件名推断内容。

**错误示例**："`UserService.java` 中存在 SQL 注入"——但从未读过该文件。
**正确做法**：先用 Read 读取 `UserService.java`，确认内容后再分析。

## 规则 2：代码必须来自 Read 输出

报告中引用的代码片段必须来自 Read 工具的实际输出。不能根据文件名或函数名推测代码内容。

**错误示例**："代码为 `SELECT * FROM users WHERE id = ${id}`"——如果 Read 输出中不是这段代码，不能这样写。
**正确做法**：引用 Read 输出中的实际代码，保留原始格式和行号。

## 规则 3：调用链每跳必须有 file:line 标注

调用链中的每一步跳转都必须标注具体文件和行号。

**错误示例**："Controller → Service → DAO → SQL"
**正确做法**："`UserController.java:45` → `UserService.getUser() at UserService.java:112` → `UserDao.findById() at UserDao.java:67` → `SELECT * FROM users WHERE id = ${id}`"

## 规则 4：不确定标记 HYPOTHESIS

当无法完全确认一个漏洞时，标记为 HYPOTHESIS 而非 CONFIRMED。绝不为了"凑数"将可疑发现标为 CONFIRMED。

HYPOTHESIS 必须附带：
- 不确定因素说明
- 需要人工验证的具体步骤
- 如果确认利用需要的额外条件

## 规则 5：宁可漏报，不可误报

当证据不足以确认漏洞时，选择不报告。误报会损害报告可信度，漏报的风险低于误报。

**例外**：如果存在强烈可疑信号但证据链不完整，标记为 HYPOTHESIS。

## 规则 6：CVE 必须联网核实

报告中提到的任何 CVE 编号必须通过 WebSearch 或 WebFetch 联网核实。不能基于记忆或推测引用 CVE。

核实内容：
- CVE 编号是否存在
- 影响的组件版本是否匹配
- 漏洞类型描述是否与当前发现一致

## 规则 7：行号必须用 Read 验证

报告中引用的所有行号必须通过 Read 工具验证。不能基于 grep/ripgrep 的搜索结果直接引用行号（搜索结果行号可能因上下文扩展而不准确）。

## 规则 8：继承链验证

在声明任何"覆盖（override）"、"绕过（bypass）"、"防护被禁用"之前，必须验证类继承关系实际存在。

**真实案例教训**：某审计报告中声称"4个 Controller 覆盖了 BaseController 的批量分配保护"，但实际这 4 个 Controller 根本没有继承 BaseController。

**正确做法**：
1. 用 Read 读取子类文件，确认 `extends` 或 `implements` 语句
2. 用 Read 读取父类文件，确认被覆盖的方法确实存在
3. 确认方法签名（参数类型、返回类型）匹配覆盖关系

## 规则 9：反确认偏误

LLM 在找到第一个漏洞后，容易"确认偏误"——倾向于在后续文件中发现类似漏洞，即使证据不足。这会导致批量误报。

**表现**：
- 在 A 文件中发现 SQL 注入后，认为 B、C、D 文件也存在同样问题
- 仅因为"模式相似"就标记 CONFIRMED，忽略 B 文件中的防护代码
- 对不相似的代码强加相同的漏洞解释

**正确做法**：
1. 每个发现独立审计，不因"A 文件有漏洞"降低对"B 文件"的证据要求
2. 显式寻找**反向证据**：主动搜索该文件中**存在**的安全控制（防护中间件、参数化查询、输入验证），而非仅搜索漏洞信号
3. 如果找不到该漏洞的完整证据链，标记为 HYPOTHESIS 或放弃

**检查方法**：每标记 3 个同类漏洞后，停下来问自己："如果这个文件是安全的，我会怎么知道？"然后实际去寻找安全证据。

## 规则 10：配置项不是漏洞（误报过滤）

以下类型**不得标记为 CONFIRMED**，最多标记为 LOW/INFO 或直接省略：

- **缺少 HTTP 安全响应头**（X-Frame-Options/CSP/HSTS/X-Content-Type-Options）：属于加固建议，不是可利用漏洞。攻击者不能仅凭缺少头部就实现攻击。
- **"可能"的暴力破解**（缺少频率限制）：除非存在可预测的凭证（默认密码、弱密码策略），否则属于加固建议。
- **"弱"加密算法**（MD5/SHA1）：除非存在具体的密码哈希泄露途径（如下载数据库文件），否则单独报告加密算法弱点价值有限。
- **非密码学安全的随机数**（mt_rand/rand）：除非能展示具体的预测攻击（如重置令牌预测），否则属于理论风险。
- **"可能"的信息泄露**（phpinfo/错误报告）：除非确认生产环境可访问，否则不应标记高于 LOW。

**例外**：以上配置问题如果作为利用链的一部分（如缺少 CSP 使 XSS 利用更容易），可以在对应漏洞的 `remediation` 中提及，但不作为独立漏洞报告。

## 规则 11：漏洞成立条件分层评级（v2，更换旧的 5/5 AND）

每个漏洞类型在 `references/vulnerability-conditions.md` 中定义为 **MUST**（白盒可验证的核心三要素：入口 → 数据流 → Sink 执行）+ **WEIGHTED**（辅助条件，如过滤/Gadget/回显/环境）。

**评级算法**：

```
1. 逐条核验 MUST 与 WEIGHTED 条件，每条必须在源码中给出 file:line 证据，缺失记 null
2. let MUST_PASS    = 通过 MUST 数 / MUST 总数
   let WEIGHT_SCORE = 通过 WEIGHTED 数 / WEIGHTED 总数

3. 分级：
   MUST_PASS < 100%               → 撤回 finding（不写报告）
   MUST_PASS = 100% + WEIGHT ≥80% → status=CONFIRMED,   evidence_level=L3
   MUST_PASS = 100% + WEIGHT 50-80% → status=HYPOTHESIS, evidence_level=L2 (STRONG)
   MUST_PASS = 100% + WEIGHT <50% → status=HYPOTHESIS,  evidence_level=L1 (WEAK)
```

**关键区别于旧版**：

- 旧版"5 条 AND"会因为"DB 账号权限"/"SSRF 绕过可能"等**白盒不可验证**的条件，把 70-80% 真实漏洞错杀为 HYPOTHESIS
- 新版把这些不可验证条件移到 WEIGHTED 层，并允许通过 Stage 2 远程验证升级
- Stage 2 验证 `poc.result=success` 后，HYPOTHESIS+L2 **自动升级**为 CONFIRMED+L3
- Stage 2 受控 refinement / bypass 成功后，HYPOTHESIS+L1 **自动升级**为 CONFIRMED+L3

**高频伪阳模式**（满足 MUST 但应整体撤回，详见 vulnerability-conditions.md 末尾表）：

| 漏洞类型 | 撤回情形 |
|----------|---------|
| SQL 注入 | ORM 内部已参数化（如 `select().where()` 仅传值） |
| RCE | `subprocess.run(['cmd', arg], shell=False)` 且 arg 经白名单 |
| SSRF | 仅允许已知域名白名单且解析后比对 IP 段 |
| XSS | Jinja2 默认转义未关闭 + 未用 `\|safe` |

每条 finding 必须在 `evidence_refs` 中列出每条 MUST/WEIGHTED 的 `file:line`，缺失条件标注 `null` 或 `verified-in-phase-4`。

## 规则 12：PoC 证据阶梯 + 签名自动匹配（v3 强化）

PoC 验证结果必须基于**响应体中可直接证明漏洞存在的具体内容**

| 证据等级 | 标准 | 自动判定方式 |
|----------|------|--------------|
| **L3: 漏洞直接输出** | 响应体含命令输出、文件内容、数据库数据 | `_evidence_match` 中存在 `strength=L3` 命中 |
| **L2: 漏洞间接确认** | 响应体含预期业务数据变化、payload 回显 | `_evidence_match` 中仅 `strength=L2` 命中 |
| **L1: 行为推断** | 仅 HTTP 状态码变化 / 重定向 / 响应长度差异 | `_evidence_match` 为空，但请求触达目标 |
| **L0: 源码推断** | 仅源码分析，未远程验证 | 无 `poc.steps` 或 result=skipped |

**LLM 撰写约束**：
- 撰写 `poc.evidence` 必须引用 `_evidence_match[i].snippet` 的具体字符串（如 "snippet `root:x:0:0:root:/root:/bin/bash`"）
- 不允许写"返回成功"、"看到敏感数据"、"利用成功"这类模糊描述
- L1/L0 证据下声称漏洞成立 → 强制 HYPOTHESIS + `x_finding_class="code_only"`

## 规则 13：实质性证据强制（v3 新增）

> 用户明确要求："不要说代码层面有，但是又利用不成功"。

| 场景 | 处理 |
|------|------|
| 代码层 MUST 全过 + Stage 2 无签名命中 | **HYPOTHESIS + `x_finding_class="code_only"`**，绝不 CONFIRMED |
| 文件上传响应 200 但未 GET 访问验证 | `poc.result=failure`，进入 Stage 2 受控绕过枚举 |
| 路径遍历返回 200 但响应不含系统文件签名 | `poc.result=failure`，重新探索（编码绕过 / 大小写 / Null 截断） |
| 命令注入响应里只有"OK"但无命令输出 | `poc.result=failure`，尝试盲注 + OOB（DNS/HTTP 回调） |
| 上传 RCE 仅有 step1（上传），无 step2（访问）+ step3（命令回显） | consistency_checks **BLOCKING** |

**报告呈现**：所有 finding 都写 `x_finding_class`：
- `"runtime_verified"`：有签名命中，确认可远程利用
- `"code_only"`：仅源码层证据，未通过远程验证

`audit.summary.x_runtime_verified` 与 `x_code_only` 计数显示在报告头部。读者一眼能看出"哪些是真验过的，哪些只是审计员推断"。
