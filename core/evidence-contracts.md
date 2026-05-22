# 证据契约（Evidence Contracts）

继承自 PHP-Code-Audit-Skill 的 EVID_* 机制并泛化到所有语言。核心思想：每种漏洞类型定义必需的证据点，缺少证据时强制降级。

## 证据点命名

```
EVID_{VULN_TYPE}_{EVIDENCE_KIND}
```

通用证据点类型：
- `EVID_*_EXEC_POINT`：危险函数执行点（file:line）
- `EVID_*_PARAM_SOURCE`：用户参数入口点（file:line + 参数名）
- `EVID_*_SINK_CALL`：最终 Sink 调用（file:line + 函数调用代码）
- `EVID_*_DATA_FLOW`：数据流中间转换点（file:line + 变量变换）
- `EVID_*_NO_SANITIZE`：缺失的清洗/验证逻辑证明
- `EVID_*_BRANCH_CONDITION`：控制流分支条件（file:line + 条件表达式）

## 各漏洞类型必需证据点

### SQL 注入（SQLI）
| 证据点 ID | 说明 |
|-----------|------|
| `EVID_SQL_EXEC_POINT` | SQL 执行位置 |
| `EVID_SQL_STRING_CONSTRUCTION` | SQL 字符串拼接/构造方式 |
| `EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT` | 用户参数流入 SQL 片段的追踪 |
| `EVID_SQL_NO_PARAMETERIZED` | 未使用参数化查询的证明 |

### 远程代码执行（RCE）
| 证据点 ID | 说明 |
|-----------|------|
| `EVID_RCE_EXEC_POINT` | 代码执行函数调用点 |
| `EVID_RCE_PARAM_SOURCE` | 用户可控参数入口 |
| `EVID_RCE_NO_SANITIZE` | 缺失输入清洗的证明 |
| `EVID_RCE_DATA_FLOW` | 参数从入口到执行点的完整数据流 |

### SSRF
| 证据点 ID | 说明 |
|-----------|------|
| `EVID_SSRF_REQUEST_POINT` | HTTP 请求发出点 |
| `EVID_SSRF_URL_SOURCE` | URL 参数来源 |
| `EVID_SSRF_NO_VALIDATION` | 缺失 URL 校验的证明 |
| `EVID_SSRF_REDIRECT_FLOW` | URL 从入口到请求点的数据流 |

### 文件操作（File Read/Write/Upload）
| 证据点 ID | 说明 |
|-----------|------|
| `EVID_FILE_OP_POINT` | 文件操作执行点 |
| `EVID_FILE_PATH_SOURCE` | 文件路径参数来源 |
| `EVID_FILE_NO_PATH_VALIDATION` | 缺失路径校验的证明 |
| `EVID_FILE_DATA_FLOW` | 路径参数从入口到操作点的数据流 |
| `EVID_FILE_WEB_ROOT` | 操作目录是否在 Web 根目录下（上传/写入时） |
| `EVID_FILE_OVERWRITE_RISK` | 文件覆盖风险评估（写入/上传时） |

### XXE
| 证据点 ID | 说明 |
|-----------|------|
| `EVID_XXE_PARSER_POINT` | XML 解析器调用点 |
| `EVID_XXE_XML_SOURCE` | XML 输入来源 |
| `EVID_XXE_NO_SECURITY_CONFIG` | 未禁用外部实体/DOCTYPE 的证明 |
| `EVID_XXE_USER_CONTROLLABLE` | XML 内容用户可控的证明 |

### 反序列化（Deserialization）
| 证据点 ID | 说明 |
|-----------|------|
| `EVID_DESER_CALL_POINT` | 反序列化函数调用点 |
| `EVID_DESER_DATA_SOURCE` | 序列化数据来源 |
| `EVID_DESER_NO_TYPE_FILTER` | 缺失类型过滤/白名单的证明 |
| `EVID_DESER_GADGET_AVAIL` | 可利用 Gadget 链存在性评估 |

### 认证/授权绕过（Auth Bypass）
| 证据点 ID | 说明 |
|-----------|------|
| `EVID_AUTH_ENTRY_POINT` | 请求入口点 |
| `EVID_AUTH_MISSING_CHECK` | 缺失认证/授权检查的证明 |
| `EVID_AUTH_BYPASS_METHOD` | 绕过方式描述 |
| `EVID_AUTH_NO_FALLBACK` | 无其他层级防护的证明 |

### CSRF
| 证据点 ID | 说明 |
|-----------|------|
| `EVID_CSRF_STATE_CHANGING` | 操作为状态变更的证明 |
| `EVID_CSRF_NO_TOKEN` | 缺失 CSRF Token 校验 |
| `EVID_CSRF_NO_ORIGIN_CHECK` | 缺失 Origin/Referer 校验 |
| `EVID_CSRF_COOKIE_BASED` | 基于 Cookie 认证（非 Token）的证明 |
| `EVID_CSRF_USER_ACTION` | 用户触发方式描述 |

## 证据契约执行规则

### 规则 1：证据引用强制
每条漏洞发现必须在"证据引用"章节中列出对应 EVID_* ID 及其 file:line 引用。

### 规则 2：缺失证据降级
如果任何必需证据点无法定位到具体 file:line，该漏洞状态**必须**降级为 `待验证（HYPOTHESIS）`。禁止在证据不足时声称 `已确认可利用（CONFIRMED）`。

### 规则 3：证据降级规则
```
所有必需证据齐全 + 数据流完整 → CONFIRMED
缺少 1-2 个非关键证据 → HYPOTHESIS（待验证）
缺少关键证据（无 Sink 执行点/无参数流入） → 不报告
```

### 规则 4：追踪完整性分级
| 等级 | 说明 |
|------|------|
| FULL | 所有 EVID_* 证据点均有 file:line，数据流无断裂 |
| PARTIAL | 部分证据点缺失或数据流有断裂，但核心 Sink 已确认 |
| UNRESOLVED | 核心证据缺失（无 Sink 执行点或无参数流入） |

### 规则 5：静态证据替代
当未执行完整数据流追踪时，允许用 `file:line + 代码片段` 作为静态证据替代。该发现仍使用相同 EVID_* ID，但标记为"Trace 未执行"，状态自动为 HYPOTHESIS。

## Sink Slot 类型分类

Sink Slot 描述危险函数中**用户可控参数的具体角色**。同一个 Sink 函数在不同上下文中风险不同——参数在 SQL 查询的值位置比在标识符位置更危险。理解 Sink Slot 帮助精确评估漏洞可利用性。

### Slot 分类

| Slot 类型 | 说明 | 危险等级 | 示例 |
|-----------|------|----------|------|
| **SQL-val** | 参数作为 SQL 值 | 高 | `WHERE id = ${userInput}` |
| **SQL-ident** | 参数作为 SQL 标识符（表名/列名/ORDER BY） | 中 | `ORDER BY ${userInput}` |
| **SQL-clause** | 参数作为 SQL 子句（WHERE/SET） | 极高 | `WHERE ${userInput}` |
| **CMD-argument** | 参数作为命令参数 | 高 | `exec('rm ' + userInput)` |
| **CMD-option** | 参数作为命令选项/标志 | 中 | `exec('ls ' + userInput)` |
| **CMD-shell** | 参数作为 Shell 元字符 | 极高 | `exec(userInput)` 整个 shell |
| **FILE-path** | 参数作为文件路径 | 高 | `open(userInput)` |
| **FILE-name** | 参数作为文件名（路径已固定） | 低 | `open('/safe/dir/' + userInput)` |
| **FILE-ext** | 参数作为文件扩展名 | 中 | `open(base + '.' + userInput)` |
| **URL-full** | 参数作为完整 URL | 高 | `requests.get(userInput)` |
| **URL-domain** | 参数作为域名 | 中 | `requests.get('https://' + userInput)` |
| **URL-param** | 参数作为 URL 参数值 | 低 | `requests.get(url + '?q=' + userInput)` |
| **XML-content** | 参数作为 XML 内容 | 高 | `parseXML(userInput)` |
| **XML-config** | 参数作为 XML 解析器配置 | 中 | `parser.setFeature(userInput)` |
| **EXPR-full** | 参数作为完整表达式 | 极高 | `eval(userInput)` |
| **EXPR-partial** | 参数作为表达式片段 | 高 | `eval('x = ' + userInput)` |
| **TEMPLATE-content** | 参数作为模板内容 | 高 | `Template(userInput)` |
| **TEMPLATE-var** | 参数作为模板变量值 | 低 | `render('Hello {{name}}', {'name': userInput})` |
| **HEADER-value** | 参数作为 HTTP 头值 | 中 | `response.setHeader('X-Redirect', userInput)` |
| **COOKIE-value** | 参数作为 Cookie 值 | 低 | `setCookie('session', userInput)` |

### Slot 使用规则

1. **审计时标注 Slot 类型**：每条发现必须标注涉及的 Sink Slot 类型
2. **Slot 决定危险等级**：相同函数不同 Slot 风险不同
   - `ORDER BY ${userInput}`（SQL-ident）→ 不可直接 UNION 注入，但仍可能布尔注入
   - `WHERE id = ${userInput}`（SQL-val）→ 直接注入
   - `WHERE ${userInput}`（SQL-clause）→ 最危险，可完全控制 WHERE 条件
3. **Slot 影响 PoC 构造**：不同 Slot 需要不同的利用方式
4. **多 Slot 组合**：一个漏洞可能涉及多个 Slot，按最危险的标注

### 报告中的呈现

在漏洞详情中添加 Slot 信息：

```
**Sink Slot**：SQL-val（参数作为 SQL 值）
**Slot 危险等级**：高 — 可直接进行 UNION 注入
**Slot 影响**：参数位于 WHERE 值位置，可通过 ' OR 1=1-- 注入
```
