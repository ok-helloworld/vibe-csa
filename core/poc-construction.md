# Stage 2 PoC 构造协议

动态验证 Agent 必须先从静态审计 JSON 推导 PoC，再发送请求。禁止脱离审计结果手写猜测型 PoC。

## 输入字段优先级

PoC 构造按以下字段取证：

1. `analysis.attack_surface`：路由、HTTP 方法、参数、认证角色、Content-Type。
2. `analysis.data_flow`：确认 source 参数如何到达 sink。
3. `analysis.sink`：确定漏洞类型对应的 payload 语义。
4. `analysis.security_controls`：识别过滤、鉴权、白名单和可绕过点。
5. `analysis.bypass_strategy`：生成候选绕过 payload。
6. `analysis.verification_plan`：确定成功标准和多步骤顺序。
7. `location.route/http_method/snippet`：当 attack_surface 不完整时兜底。

## 固定步骤

1. 动态验证 Agent 读取 `workDir/findings/FINDING-xxx.poc.json`。
2. 回读源码，确认自动生成的 `poc.steps[].request` 是否匹配真实路由和参数。
3. 必要时只修改 request、extract、payload，不写 response。
4. 调用 `verify_vuln.py` 发送请求并写入真实 response。
5. 分析 response：
   - 证据充分：设置 `poc.result="success"`、`status="CONFIRMED"`、`finding_class="runtime_verified"`。
   - 证据不足：根据源码和响应补充下一步 request 或写入 `failure_log[]`。
   - 失败：保留请求、响应和失败原因，不删除尝试过程。

## 漏洞类型到 PoC 的映射

| 漏洞类型 | 初始 payload | 必须证明 |
| --- | --- | --- |
| SQL 注入 | `'`、布尔真/假条件、时间函数 | 错误信息、布尔差异、时间差异或可提取数据 |
| 命令执行/命令注入/代码执行 | `id`、`;id`、换行分隔、编码分隔 | 响应中出现真实命令输出 |
| 任意文件创建/文件上传/任意文件写入 | 唯一 marker 文件，必要时脚本文件 | 能访问写入后的文件；RCE 还要命令输出 |
| 任意文件读取/目录穿越/本地文件包含 | `/etc/passwd`、编码穿越、Windows 文件 | 读取到系统文件或敏感文件特征 |
| SSRF/HTTP 请求伪造 | metadata、127.0.0.1、内网地址、OOB URL | 内网响应、metadata、服务指纹或 OOB 回连 |
| 越权访问/IDOR | 当前对象 ID 与相邻对象 ID | 低权限访问到其他用户资源 |
| 跨站脚本 | 唯一 marker payload | 存储/反射后的页面响应包含唯一 payload |
| XML 注入/XXE | 外部实体读取文件或 OOB DTD | 文件内容、解析错误或 OOB 回连 |
| 反序列化 | 安全探测 gadget 或错误触发 payload | 反序列化错误、回显、OOB 或命令输出 |

## 绕过生成规则

动态验证 Agent 只能在已识别到过滤或安全控制后使用绕过 payload。绕过策略来自 `analysis.security_controls` 和 `analysis.bypass_strategy`。

常见绕过：

| 控制 | 候选绕过 |
| --- | --- |
| 后缀黑名单 | 双后缀、大小写、解析差异、可上传文本但由后续流程复制解析 |
| 路径清理 | URL 编码、双重编码、混合分隔符、符号链接、规范化前后差异 |
| 命令过滤 | 分隔符变体、换行、环境变量、空格替代、编码 |
| SSRF 过滤 | 十进制/八进制 IP、IPv6、DNS rebinding、跳转、协议变形 |
| SQL 关键字过滤 | 大小写、注释、编码、函数等价替换 |
| 鉴权控制 | 角色切换、对象 ID 替换、隐藏参数、批量接口 |

## 多步骤 PoC 要求

多步骤利用必须拆开记录：

1. 前置或写入动作。
2. 访问或触发动作。
3. 证明动作。

文件类漏洞最低两步：

```text
step 1: 上传或写入带唯一 marker 的文件
step 2: HTTP 访问该文件，响应体出现 marker
```

文件写入到 RCE 最低三步：

```text
step 1: 写入可执行脚本
step 2: 访问脚本确认 marker
step 3: 传入命令并在响应中看到 uid=... 或等价命令输出
```


## 证据判定

`poc.result="success"` 只能在最终响应足够证明漏洞真实存在时设置。HTTP 200、返回 `success`、无报错都不是充分证据。

必须写入：

- `poc.evidence`：引用具体 step 和响应原文片段。
- `response._evidence_match[]`：记录 `type/pattern/strength/snippet`。
- `dynamic_verification.final_evidence`：记录最终证明类型和证据片段。

没有 L2/L3 证据时保持：

```json
{
  "status": "HYPOTHESIS",
  "finding_class": "code_only",
  "poc": {
    "result": "failure"
  }
}
```