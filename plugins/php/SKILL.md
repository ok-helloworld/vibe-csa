---
name: vibe-csa-php
description: PHP 代码审计插件。支持 Laravel, Symfony, ThinkPHP, WordPress, CodeIgniter, Yii2 框架。包含分层规则、危险模式、Semgrep 规则。
---

# PHP 审计插件

## 语言检测

项目包含以下任一特征时识别为 PHP：
- 存在 `.php` 文件
- 存在 `composer.json`
- 存在 `wp-config.php`（WordPress）或 `artisan`（Laravel）

## 分层规则

加载 `tier-rules.md` 进行文件分类：
- **T1**: Controllers/Routes/Handlers（入口点）
- **T2**: Models/Services/Repositories/Middleware（业务逻辑）
- **T3**: Entities/DTOs/Requests（数据结构）
- **SKIP**: vendor/、tests/、storage/、node_modules/

## Layer 1 预扫描

### P0（Critical）危险模式

| 模式 | 漏洞类型 |
|------|----------|
| `eval\s*\(` | 代码执行 |
| `assert\s*\(` | 代码执行（PHP 7 前） |
| `preg_replace.*\/e` | 代码执行 |
| `create_function\s*\(` | 代码执行 |
| `system\s*\(` | 命令执行 |
| `passthru\s*\(` | 命令执行 |
| `exec\s*\(` | 命令执行 |
| `shell_exec\s*\(` | 命令执行 |
| `` `[^`]+` `` | 命令执行（反引号） |
| `proc_open\s*\(` | 命令执行 |
| `unserialize\s*\(` | 反序列化 |
| `phar://` | Phar 反序列化 |

### P1（High）危险模式

| 模式 | 漏洞类型 |
|------|----------|
| `->query\s*\(` (字符串拼接) | SQL 注入 |
| `->exec\s*\(` (字符串拼接) | SQL 注入 |
| `mysqli_query\s*\(` (字符串拼接) | SQL 注入 |
| `DB::raw\s*\(` | SQL 注入 |
| `whereRaw\|orderByRaw` | SQL 注入 |
| `file_get_contents\s*\(` | 文件读取/SSRF |
| `curl_exec\s*\(` | SSRF |
| `CURLOPT_URL` | SSRF |
| `fopen\s*\(` | 文件操作 |
| `fsockopen\s*\(` | SSRF |
| `file_put_contents\s*\(` | 文件写入 |
| `move_uploaded_file\s*\(` | 文件上传 |
| `unlink\s*\(` | 文件删除 |
| `include\s+\$\|require\s+\$` | 文件包含 |
| `simplexml_load_string` | XXE |
| `SimpleXMLElement` | XXE |
| `loadXML\s*\(` | XXE |
| `ldap_search\s*\(` | LDAP 注入 |

### P2（Medium）危险模式

| 模式 | 漏洞类型 |
|------|----------|
| `echo\s+\$\|print\s+\$` | XSS |
| `<?=\s*\$` | XSS |
| `header\s*\(.*Location` | 开放重定向 |
| `md5\s*\(` (密码场景) | 弱哈希 |
| `sha1\s*\(` (密码场景) | 弱哈希 |
| `rand\s*\(` (安全场景) | 不安全随机数 |
| `display_errors.*On` | 错误暴露 |
| `Access-Control-Allow-Origin.*\*` | CORS 配置 |

## 框架专项

加载 `frameworks.md` 获取框架专属审计指南：
- Laravel（路由、Eloquent、Blade、中间件、CSRF）
- Symfony（路由、Doctrine、Twig、Security 组件）
- ThinkPHP（路由、Query Builder、模型）
- WordPress（钩子、$wpdb、Nonce、权限检查）
- CodeIgniter（路由、Query Builder）
- Yii2（路由、Query Builder、ActiveRecord）

## Semgrep 规则

加载 `semgrep/` 目录下的所有 YAML 规则：
- `php-rce.yaml` — eval/assert/preg_replace_e/system/passthru/exec
- `php-sqli.yaml` — PDO/mysqli/DB::raw/whereRaw
- `php-ssrf.yaml` — file_get_contents/curl/fopen/fsockopen
- `php-file.yaml` — file_put_contents/include/require/move_uploaded_file/unlink
- `php-deser.yaml` — unserialize/phar://
- `php-xxe.yaml` — SimpleXML/DOMDocument
- `php-auth.yaml` — 认证绕过、权限检查缺失、md5 密码、LDAP
- `php-misc.yaml` — XSS、CSRF、开放重定向、CRLF、Session、配置

## 双轨审计

### Sink 驱动
从 `sinks.md` 中的危险函数出发，向上追溯变量来源。PHP 特有的超全局变量（`$_GET`、`$_POST`、`$_REQUEST`、`$_FILES`、`$_COOKIE`）是主要污染源。

### 控制驱动
从 T1 Controller/Route 出发，向下追踪安全控制：
1. 是否有认证中间件（Laravel `auth`、Symfony `IsGranted`、WordPress `current_user_can`）
2. 是否有输入验证（Laravel `$request->validate()`、Symfony Form）
3. 是否有输出编码（Blade `{{ }}` 默认转义、Twig `{{ }}` 默认转义）
4. 是否有 CSRF 保护（Laravel VerifyCsrfToken、Symfony 表单自动 CSRF）

## 证据契约

PHP 审计继承核心的 EVID_* 证据契约机制。每个漏洞发现必须引用对应的证据点 ID 和 file:line。证据不足时强制降级为 HYPOTHESIS。

## 漏洞编号规则

```
{C/H/M/L}-{TYPE}-{SEQ}
```
- TYPE: SQL=SQL注入, RCE=远程代码执行, SSRF=SSRF, FILE=文件操作, XXE=XXE, AUTH=认证绕过, XSS=XSS, DESER=反序列化, REDIR=开放重定向, CRLF=CRLF注入, CSRF=CSRF, CRYPTO=加密弱点, CONFIG=配置问题

## 输出格式

所有发现写入 `{output_path}/findings-raw.md`，每条包含：
- 漏洞编号
- 类型
- 严重程度
- 位置（file:line）
- 简要描述
- 危险函数/模式
- Track 来源（Sink 驱动 / 控制驱动）
- EVID_* 证据引用

## 能力基线检查

以下 24 项是 PHP 项目审计的最低能力基线。每项必须在审计过程中被验证（PASS/FAIL/SKIP），确保无盲区：

### RCE 检测
- [ ] `eval()` / `assert()` 用户输入
- [ ] `preg_replace` with `/e` 修饰符
- [ ] `create_function()` 用户可控代码
- [ ] `system()` / `passthru()` / `exec()` / `shell_exec()` 用户可控参数
- [ ] `` `反引号` `` 用户输入
- [ ] `proc_open()` / `popen()` 用户可控

### 反序列化检测
- [ ] `unserialize()` 用户输入
- [ ] `phar://` 协议触发反序列化
- [ ] `maybe_unserialize()` 用户输入

### SQL 注入检测
- [ ] `PDO->query()` / `->exec()` 字符串拼接
- [ ] `mysqli_query()` 字符串拼接
- [ ] Laravel `DB::raw()` / `whereRaw()` / `orderByRaw()`
- [ ] WordPress `$wpdb->query()` 未参数化
- [ ] ThinkPHP `->where()` / `->order()` 原始字符串

### SSRF 检测
- [ ] `file_get_contents()` 用户可控 URL
- [ ] `curl_setopt(CURLOPT_URL)` 用户可控
- [ ] `fopen()` 用户可控 URL
- [ ] `fsockopen()` 用户可控
- [ ] `SoapClient` 用户可控 WSDL

### 文件安全
- [ ] `file_put_contents()` 用户可控路径
- [ ] `include` / `require` 用户可控文件包含
- [ ] `readfile()` / `fread()` 用户可控路径
- [ ] `move_uploaded_file()` 无类型/路径校验
- [ ] `unlink()` / `rmdir()` 用户可控

### XXE 检测
- [ ] `simplexml_load_string()` 用户输入
- [ ] `SimpleXMLElement` 用户输入
- [ ] `DOMDocument->loadXML()` / `->load()`

### XSS 检测
- [ ] `echo` / `print` 直接输出用户输入
- [ ] `<?= $var ?>` 未转义
- [ ] Laravel `{!! !!}` 未转义 Blade 输出

### 认证/授权
- [ ] LDAP `ldap_search()` / `ldap_bind()` 注入
- [ ] `md5()` / `sha1()` 密码哈希
- [ ] `rand()` 安全场景（应用 `random_int()`）
- [ ] 路由无认证中间件
- [ ] IDOR 无所有权验证

### 配置安全
- [ ] `display_errors = On` 生产环境
- [ ] `Access-Control-Allow-Origin: *`
- [ ] Session 配置不安全（cookie HttpOnly/Secure）
- [ ] `header()` 重定向用户可控 URL
- [ ] `header()` CRLF 注入
