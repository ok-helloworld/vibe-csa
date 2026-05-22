# 报告格式

vibe-csa 的标准输出为 `vibe-csa-{YYYYMMDD-HHmmss}.json`，结构如下。文件名中的时间戳为 `generate_report.py` 执行时刻。

## 整体结构

```
root
├── audit        审计元信息
└── findings[]   漏洞条目列表
```

## 一、audit — 审计元信息

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `audit_id` | string | ✅ | 审计任务唯一编号，格式 `AUDIT-YYYY-NNN` |
| `title` | string | ✅ | 审计报告标题 |
| `repository` | string | ✅ | 被审计代码仓库地址 |
| `audit_date.start` | string | ✅ | 审计开始日期 `YYYY-MM-DD` |
| `audit_date.end` | string | ✅ | 审计结束日期 `YYYY-MM-DD` |
| `language` | string[] | ✅ | 项目使用的编程语言列表 |
| `summary.total` | number | ✅ | 漏洞总数 |
| `summary.critical` | number | ✅ | 严重级别数量 |
| `summary.high` | number | ✅ | 高危级别数量 |
| `summary.medium` | number | ✅ | 中危级别数量 |
| `summary.low` | number | ✅ | 低危级别数量 |
| `summary.fixed` | number | ✅ | 已修复数量 |
| `summary.open` | number | ✅ | 待修复数量 |

## 二、findings[] — 漏洞条目

### 2.1 基础信息

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `vuln_id` | string | ✅ | 漏洞唯一编号，格式 `FINDING-NNN` |
| `title` | string | ✅ | 漏洞标题，格式"漏洞类型 —— 具体位置" |
| `severity` | enum | ✅ | `critical` / `high` / `medium` / `low` |
| `status` | enum | ✅ | `CONFIRMED`（证据完整可利用）/ `HYPOTHESIS`（证据不足待验证）；Stage 1 先给静态结论，Stage 2 可基于运行时证据升级 |
| `dktss_score` | number | ✅ | DKTSS 评分 0-10；在 Stage 3 汇总前必须完成填写 |
| `attack_path` | object | ❌ | 攻击路径 4 维评分，含 `total`（0-12）、`level`（P0-P3）及各维分解 |
| `sink_slot` | string | ❌ | Sink Slot 类型（SQL-val / CMD-argument / FILE-path 等），仅 Sink 驱动发现填写 |
| `tracking_completeness` | enum | ❌ | `FULL` / `PARTIAL` / `UNRESOLVED`，数据流追踪完整性 |
| `evidence_refs` | object | ❌ | EVID_* 证据点引用，键为证据点 ID，值为 `file:line` |
| `description` | string | ✅ | 漏洞描述，说明成因、触发条件和潜在危害 |

### 2.2 location — 代码位置

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `file` | string | ✅ | 文件路径（相对仓库根目录） |
| `line_start` | number | ✅ | 起始行号 |
| `line_end` | number | ❌ | 结束行号，单行漏洞可省略 |
| `function` | string | ❌ | 函数或方法名 |
| `snippet` | string | ✅ | 关键漏洞代码片段（1-3 行） |

### 2.3 data_flow[] — 污点传播链

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `step` | number | ✅ | 步骤序号，从 1 开始 |
| `type` | enum | ✅ | `source` / `propagation` / `sink` |
| `desc` | string | ✅ | 该节点行为描述 |
| `location` | string | ✅ | 代码位置 `文件路径:行号` |

简单漏洞（如硬编码密钥、不安全配置）可省略 data_flow。

### 2.4 poc — 利用请求与响应

每个 poc 包含多步骤的 `steps[]` 数组，记录从初始请求到最终验证的完整过程。

**poc.steps[] — 请求响应步骤**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `poc.steps[].step` | number | ✅ | 步骤序号，从 1 开始 |
| `poc.steps[].request.method` | string | ✅ | HTTP 方法 |
| `poc.steps[].request.url` | string | ✅ | 完整请求地址 |
| `poc.steps[].request.headers` | object | ❌ | 请求头 |
| `poc.steps[].request.params` | object | ❌ | URL 查询参数 |
| `poc.steps[].request.body` | object | ❌ | 请求体 |
| `poc.steps[].request.cookies` | object | ❌ | Cookie |
| `poc.steps[].request.raw` | string | 动态阶段必填 | 原始 HTTP 请求报文 |
| `poc.steps[].response.status` | number | ✅ | 响应状态码 |
| `poc.steps[].response.headers` | object | ❌ | 响应头 |
| `poc.steps[].response.raw` | string | 动态阶段必填 | 原始 HTTP 响应报文 |
| `poc.steps[].response.body` | string | ✅ | 响应体关键片段（截断至 4096 字符） |

**poc 顶层字段**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `poc.result` | enum | ✅ | `success` / `failure` / `timeout` / `skipped` |
| `poc.evidence` | string | ✅ | 证据说明（响应中哪里证明了漏洞存在） |

**⚠️ PoC 数据真实性铁律（绝对不可违反）**：

1. `poc.steps[].response` 中的 status、headers、body **必须来自 verify_vuln.py 脚本的实际写入**，禁止 LLM 预填、推断或补全任何响应字段
2. 调用脚本之前，`poc.steps[n]` 只写 `request`，**response 字段必须留空**
3. 调用脚本之后，必须 Read `vibe-csa-draft.json` 读取脚本写入的真实响应，再进行下一步判断
4. `poc.evidence` 必须引用 response.body 中能**直接证明漏洞存在**的具体内容原文（如 `"response body 第2行出现 'root:x:0:0:root:/root:/bin/bash'，确认路径穿越读取到 /etc/passwd"`），不得仅写"响应成功"或"HTTP 200"，不得包含对未见响应的推断
5. `poc.result = "success"` 的判定标准：response.body 中能找到与漏洞类型对应的直接证据（数据泄露内容/payload执行结果/其他用户数据/命令输出等），仅凭状态码不可判定成功
6. 多步骤漏洞每步记录为一个 step；响应 body 过长时截取能证明漏洞的关键部分（最多 4096 字符）

**POC steps 与 response 按 result 的强制要求**：

| poc.result | steps 最少数量 | 每个 step 的 request | 每个 step 的 response | failure_log |
|------------|:-----------:|:-------------------:|:---------------------:|:-----------:|
| `success` | ≥ 1 | ✅ 必填（method + url） | ✅ **必填**（status + body） | 不需要 |
| `failure` | ≥ 1 | ✅ 必填（method + url） | ✅ **必填**（status + body） | ✅ **必填** |
| `timeout` | ≥ 1 | ✅ 必填（method + url） | 可选 | 建议填写 |
| `skipped` | 可为空 | 如有 step 则必填 | 无需填写 | 不需要 |
| `auth_failed` | 建议 ≥ 1 | 建议填写认证探测 request | 建议填写 | 不需要 |

> **关键**：除 `skipped` 外，所有 result 都必须包含完整的 HTTP 请求和响应。`generate_report.py` 的 consistency_checks 会将这些作为 **BLOCKING errors** 拦截，缺失时报告生成失败。

### 2.5 remediation — 整改建议

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `short_term` | string | ✅ | 临时缓解措施 |
| `long_term` | string | ✅ | 根本修复方案 |

### 2.6 fix — 修复示例

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `language` | string | ✅ | 代码语言（语法高亮用） |
| `before` | string | ✅ | 存在漏洞的原始代码 |
| `after` | string | ✅ | 仅修复后的代码片段 |

## 三、severity 枚举

| 值 | 含义 | 典型示例 |
|----|------|----------|
| `critical` | 严重，可直接导致系统沦陷或大规模数据泄露 | SQL 注入、RCE |
| `high` | 高危，危害范围广或可被低成本利用 | 存储型 XSS、任意文件读取 |
| `medium` | 中危，需一定条件才能利用，或危害范围有限 | 越权访问（IDOR）、CSRF |
| `low` | 低危，利用条件苛刻或危害轻微 | 信息泄露、不安全的响应头 |

## 四、完整示例

```json
{
  "audit": {
    "audit_id": "AUDIT-2025-001",
    "title": "XX 支付服务安全审计报告",
    "repository": "https://github.com/org/payment-service",
    "audit_date": {
      "start": "2025-05-01",
      "end": "2025-05-15"
    },
    "language": ["Python", "JavaScript"],
    "summary": {
      "total": 3,
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0,
      "fixed": 0,
      "open": 3
    }
  },
  "findings": [
    {
      "vuln_id": "FINDING-001",
      "title": "SQL 注入 —— 用户查询接口未参数化",
      "severity": "critical",
      "description": "用户输入的 name 参数未经过滤直接拼接进 SQL 语句，攻击者可构造恶意参数绕过认证、读取或篡改全库数据。",
      "location": {
        "file": "src/user/repository.py",
        "line_start": 87,
        "line_end": 92,
        "function": "get_user_by_name",
        "snippet": "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\""
      },
      "data_flow": [
        { "step": 1, "type": "source",      "desc": "HTTP GET /api/user?name= 接收用户输入", "location": "api/user.py:34" },
        { "step": 2, "type": "propagation", "desc": "username 未做任何过滤直接向下传递",     "location": "src/user/service.py:56" },
        { "step": 3, "type": "sink",        "desc": "字符串拼接后执行 SQL 查询",             "location": "src/user/repository.py:89" }
      ],
      "poc": {
        "steps": [
          {
            "step": 1,
            "request": {
              "method": "GET",
              "url": "https://staging.example.com/api/user",
              "headers": { "Authorization": "Bearer <token>" },
              "params": { "name": "' OR '1'='1" }
            },
            "response": {
              "status": 200,
              "body": "[{\"id\":1,\"name\":\"admin\",\"email\":\"admin@example.com\"}]"
            }
          }
        ],
        "result": "success",
        "evidence": "返回全量用户记录，注入成功绕过 WHERE 条件"
      },
      "remediation": {
        "short_term": "在 API 网关添加 WAF 规则，拦截 name 参数中包含单引号、注释符（--、#）的请求。",
        "long_term": "全面替换字符串拼接 SQL 为参数化查询，或统一使用 ORM 层操作数据库。"
      },
      "fix": {
        "language": "python",
        "before": "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"",
        "after": "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (username,))"
      }
    },
    {
      "vuln_id": "FINDING-002",
      "title": "存储型 XSS —— 评论内容未转义直接渲染",
      "severity": "high",
      "description": "用户提交的评论内容存入数据库后，前端直接以 innerHTML 方式渲染，攻击者可注入恶意脚本，在其他用户浏览时执行，用于窃取 Cookie、劫持会话。",
      "location": {
        "file": "src/components/CommentList.jsx",
        "line_start": 42,
        "line_end": 42,
        "function": "renderComment",
        "snippet": "commentEl.innerHTML = comment.content"
      },
      "data_flow": [
        { "step": 1, "type": "source",      "desc": "POST /api/comment 接收 content 字段",  "location": "api/comment.py:18" },
        { "step": 2, "type": "propagation", "desc": "content 未过滤写入数据库",              "location": "src/comment/repository.py:31" },
        { "step": 3, "type": "propagation", "desc": "从数据库读出后直接赋值给前端变量",       "location": "src/components/CommentList.jsx:35" },
        { "step": 4, "type": "sink",        "desc": "innerHTML 直接将内容注入 DOM",          "location": "src/components/CommentList.jsx:42" }
      ],
      "poc": {
        "steps": [
          {
            "step": 1,
            "request": {
              "method": "POST",
              "url": "https://staging.example.com/api/comment",
              "headers": {
                "Authorization": "Bearer <token>",
                "Content-Type": "application/json"
              },
              "body": { "content": "<script>alert(1)</script>" }
            },
            "response": {
              "status": 201,
              "body": "{\"id\": 88, \"content\": \"<script>alert(1)</script>\"}"
            }
          },
          {
            "step": 2,
            "request": {
              "method": "GET",
              "url": "https://staging.example.com/comments/88"
            },
            "response": {
              "status": 200,
              "body": "<html><body>...<div id='comment-88'><script>alert(1)</script></div>...</body></html>"
            }
          }
        ],
        "result": "success",
        "evidence": "步骤 2 返回的评论页面中脚本未转义直接渲染，确认存储型 XSS"
      },
      "remediation": {
        "short_term": "在后端入库前对 content 字段做 HTML 实体编码（htmlspecialchars），阻断存储阶段。",
        "long_term": "前端统一使用 textContent 替代 innerHTML；引入 DOMPurify 对富文本内容进行白名单过滤；后端增加 Content-Security-Policy 响应头限制脚本来源。"
      },
      "fix": {
        "language": "javascript",
        "before": "commentEl.innerHTML = comment.content",
        "after": "commentEl.textContent = comment.content"
      }
    },
    {
      "vuln_id": "FINDING-003",
      "title": "越权访问 —— 订单接口未校验用户归属",
      "severity": "medium",
      "description": "获取订单详情接口仅校验了 Token 合法性，未验证订单是否属于当前登录用户，任意已登录用户可通过遍历 order_id 访问他人订单数据（IDOR）。",
      "location": {
        "file": "src/order/service.py",
        "line_start": 61,
        "line_end": 68,
        "function": "get_order_detail",
        "snippet": "order = db.query(Order).filter(Order.id == order_id).first()"
      },
      "data_flow": [
        { "step": 1, "type": "source",      "desc": "GET /api/order/{order_id} 接收路径参数", "location": "api/order.py:22" },
        { "step": 2, "type": "propagation", "desc": "order_id 直接传入 service 层，无归属校验", "location": "src/order/service.py:61" },
        { "step": 3, "type": "sink",        "desc": "直接按 id 查库并返回订单详情",            "location": "src/order/service.py:64" }
      ],
      "poc": {
        "steps": [
          {
            "step": 1,
            "request": {
              "method": "GET",
              "url": "https://staging.example.com/api/order/10086",
              "headers": { "Authorization": "Bearer <攻击者自身合法token>" },
              "params": {}
            },
            "response": {
              "status": 200,
              "body": "{\"order_id\":10086,\"user_id\":999,\"amount\":3200,\"items\":[...]}"
            }
          }
        ],
        "result": "success",
        "evidence": "攻击者 user_id 为 1，成功获取 user_id=999 的订单详情，确认越权"
      },
      "remediation": {
        "short_term": "在现有查询结果返回前，加一层用户归属断言：若 order.user_id != current_user.id 则返回 403。",
        "long_term": "在 service 层统一封装带用户上下文的查询方法，所有涉及用户资源的查询必须将 current_user_id 作为强制过滤条件，从查询层面杜绝越权，不依赖事后校验。"
      },
      "fix": {
        "language": "python",
        "before": "order = db.query(Order).filter(Order.id == order_id).first()",
        "after": "order = db.query(Order).filter(Order.id == order_id, Order.user_id == current_user.id).first()"
      }
    }
  ]
}
```

## 五、格式规则

- `location.snippet` 只包含 1-3 行核心代码，不大段复制
- `poc.steps[].response` 只记录 verify_vuln.py 写入的原始数据（status/headers/body），**禁止任何 LLM 生成内容**
- `poc.steps[].response.body` 只截取能证明漏洞的关键片段（最多 4096 字符）
- `poc.result` 必须有值（success/failure/timeout/skipped/auth_failed）
- `poc.evidence` 在顶层引用真实响应中的证据字段，说明漏洞如何被确认
- `data_flow` 对简单漏洞（硬编码密钥、不安全配置）可省略
- 所有日期使用 `YYYY-MM-DD` 格式
- 漏洞按 severity 降序排列（critical → high → medium → low）

## 六、报告生成与验证（强制流程）

**最终报告必须通过 `generate_report.py` 生成，写入当前工作目录，文件名格式 `vibe-csa-{YYYYMMDD-HHmmss}.json`。禁止 LLM 直接用 Write 工具写最终报告。**

### 标准生成流程

**Step 1**：LLM 将全部审计结果写入草稿文件 `vibe-csa-draft.json`（无需填写 summary，脚本自动计算）

**Step 2**：运行生成脚本

```bash
python {SKILL_ROOT}/scripts/generate_report.py --input vibe-csa-draft.json
```

脚本自动执行：
- 计算 summary 统计（total / critical / high / medium / low / fixed / open）
- findings 按 severity 降序排列
- 原子写入 `./vibe-csa-{YYYYMMDD-HHmmss}.json`（当前工作目录，时间戳为生成时刻）

**Step 3**：根据输出决策

| 脚本输出 | 处理 |
|---------|------|
| 成功摘要（含时间戳文件路径） | 报告完成，读取输出确认 findings 数量和路径 |
| `[FAIL] Schema 校验失败` | 按错误路径修正草稿，重新运行，最多 3 轮 |
| `[WARN] 一致性检查` | 评估是否需要补充数据（不阻止生成） |

**Step 4（可选验证）**：

```bash
python {SKILL_ROOT}/scripts/validate_report.py vibe-csa-{timestamp}.json
```

输出 `{"status": "PASS"}` 表示通过。

### 3 轮重试后仍失败

在对话中标注 `VALIDATION_FAILED`，列出未修复的错误，输出草稿供用户检查。
