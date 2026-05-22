# PHP 危险函数目录（Sinks）

按漏洞类型分类。每条包含：函数签名、风险等级、grep 搜索模式、对应的 Semgrep 规则类别。

## RCE（远程代码执行）

### 代码执行
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `eval($user_input)` | Critical | `eval\s*\(` | php-rce.yaml |
| `assert($user_input)` (PHP 7 前) | Critical | `assert\s*\(` | php-rce.yaml |
| `preg_replace('/pattern/e', ...)` | Critical | `preg_replace.*\/e` | php-rce.yaml |
| `create_function($code)` | Critical | `create_function\s*\(` | php-rce.yaml |

### 命令执行
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `system($user_input)` | Critical | `system\s*\(` | php-rce.yaml |
| `passthru($user_input)` | Critical | `passthru\s*\(` | php-rce.yaml |
| `exec($user_input)` | Critical | `exec\s*\(` | php-rce.yaml |
| `shell_exec($user_input)` | Critical | `shell_exec\s*\(` | php-rce.yaml |
| `popen($user_input, 'r')` | Critical | `popen\s*\(` | php-rce.yaml |
| `proc_open($cmd, ...)` | Critical | `proc_open\s*\(` | php-rce.yaml |
| `` `$user_input` `` (反引号) | Critical | `` `[^`]+` `` | php-rce.yaml |

### 反序列化
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `unserialize($user_input)` | Critical | `unserialize\s*\(` | php-deser.yaml |
| `Phar::` 反序列化（`phar://`） | Critical | `phar://` | php-deser.yaml |

## SQL 注入

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `PDO::query($sql)` (字符串拼接) | High | `->query\s*\(` | php-sqli.yaml |
| `PDO::exec($sql)` (字符串拼接) | High | `->exec\s*\(` | php-sqli.yaml |
| `mysqli_query($conn, $sql)` (字符串拼接) | High | `mysqli_query\s*\(` | php-sqli.yaml |
| `$wpdb->query($sql)` (WordPress) | High | `->query\s*\(` | php-sqli.yaml |
| `$wpdb->get_results($sql)` (WordPress) | High | `->get_results\s*\(` | php-sqli.yaml |
| Laravel `DB::select(DB::raw(...))` | High | `DB::raw\s*\(` | php-sqli.yaml |
| Laravel `whereRaw()` / `orderByRaw()` 用户可控 | High | `whereRaw\|orderByRaw` | php-sqli.yaml |
| ThinkPHP `query()` / `execute()` 原始 SQL | High | `->query\s*\(` | php-sqli.yaml |
| Yii2 `createCommand($sql)` 字符串拼接 | High | `createCommand\s*\(` | php-sqli.yaml |
| Doctrine `createQuery($dql)` 字符串拼接 | High | `createQuery\s*\(` | php-sqli.yaml |

## SSRF

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `file_get_contents($user_url)` | High | `file_get_contents\s*\(` | php-ssrf.yaml |
| `curl_exec($ch)` (URL 用户可控) | High | `curl_exec\s*\(` | php-ssrf.yaml |
| `curl_setopt($ch, CURLOPT_URL, $url)` | High | `CURLOPT_URL` | php-ssrf.yaml |
| `fopen($user_url, 'r')` | High | `fopen\s*\(` | php-ssrf.yaml |
| `fsockopen($host, ...)` | High | `fsockopen\s*\(` | php-ssrf.yaml |
| `SoapClient($wsdl)` (WSDL 用户可控) | High | `SoapClient\s*\(` | php-ssrf.yaml |

## 文件操作

### 文件读取
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `file_get_contents($user_path)` | High | `file_get_contents\s*\(` | php-file.yaml |
| `readfile($user_path)` | High | `readfile\s*\(` | php-file.yaml |
| `include $user_path` / `require $user_path` | High | `include\s+\$\|require\s+\$` | php-file.yaml |
| `include_once` / `require_once` 用户可控 | High | `include_once\s+\$\|require_once\s+\$` | php-file.yaml |
| `fopen($user_path, 'r')` | High | `fopen\s*\(` | php-file.yaml |

### 文件写入
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `file_put_contents($user_path, ...)` | High | `file_put_contents\s*\(` | php-file.yaml |
| `fopen($user_path, 'w')` | High | `fopen\s*\(.*'w'` | php-file.yaml |
| `fwrite($handle, $data)` | High | `fwrite\s*\(` | php-file.yaml |
| `move_uploaded_file($tmp, $user_path)` | High | `move_uploaded_file\s*\(` | php-file.yaml |

### 文件上传
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `move_uploaded_file($tmp, $dest)` | High | `move_uploaded_file` | php-file.yaml |
| Laravel `Storage::put($path, ...)` | High | `Storage::put` | php-file.yaml |
| Symfony `$file->move($dir, $name)` | High | `->move\s*\(` | php-file.yaml |
| 上传文件名直接使用 `$_FILES['file']['name']` | High | `$_FILES.*\['name'\]` | php-file.yaml |

### 文件删除
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `unlink($user_path)` | High | `unlink\s*\(` | php-file.yaml |
| `rmdir($user_path)` | High | `rmdir\s*\(` | php-file.yaml |

## XXE

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `simplexml_load_string($xml)` | High | `simplexml_load_string` | php-xxe.yaml |
| `SimpleXMLElement($xml)` | High | `SimpleXMLElement` | php-xxe.yaml |
| `DOMDocument::loadXML($xml)` | High | `loadXML\s*\(` | php-xxe.yaml |
| `XMLReader::XML($xml)` | High | `XMLReader` | php-xxe.yaml |

## LDAP 注入

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `ldap_search($conn, $dn, $filter)` (filter 用户可控) | High | `ldap_search\s*\(` | php-auth.yaml |
| `ldap_bind($conn, $dn, $pass)` (dn 用户可控) | High | `ldap_bind\s*\(` | php-auth.yaml |

## XSS

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `echo $user_input` / `print $user_input` | Medium | `echo\s+\$\|print\s+\$` | php-misc.yaml |
| `<?= $user_input ?>` | Medium | `<?=\s*\$` | php-misc.yaml |
| Laravel `!!$user_input !!` (Blade 未转义) | Medium | `!!\s*\$` | php-misc.yaml |
| `htmlspecialchars` 未使用或参数错误 | Medium | `htmlspecialchars` | php-misc.yaml |

## 开放重定向

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `header("Location: " . $user_url)` | Medium | `header\s*\(.*Location` | php-misc.yaml |
| Laravel `redirect($user_url)` | Medium | `redirect\s*\(` | php-misc.yaml |
| Symfony `$this->redirect($user_url)` | Medium | `->redirect\s*\(` | php-misc.yaml |

## CRLF 注入

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `header($user_input)` (包含 `\r\n`) | Medium | `header\s*\(` | php-misc.yaml |

## 认证/授权

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| 路由缺少认证中间件 | Medium | 路由定义无 `auth`/`middleware` | php-auth.yaml |
| `session_regenerate_id()` 未调用 | Low | `session_start` | php-auth.yaml |
| `password_hash` 使用 MD5/SHA1 | Medium | `password_hash.*PASSWORD_DEFAULT` | php-auth.yaml |

## 加密弱点

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `md5($password)` | Medium | `md5\s*\(` | php-auth.yaml |
| `sha1($password)` | Medium | `sha1\s*\(` | php-auth.yaml |
| `openssl_encrypt(..., 'DES'/'ECB')` | Medium | `openssl_encrypt` | php-auth.yaml |
| `rand()` 用于安全场景 | Low | `rand\s*\(` (应为 `random_int`) | php-auth.yaml |

## 配置问题

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `ini_set('display_errors', 'On')` | Medium | `display_errors.*On` | php-misc.yaml |
| `error_reporting(E_ALL)` 生产环境 | Medium | `error_reporting` | php-misc.yaml |
| CORS `Access-Control-Allow-Origin: *` | Medium | `Access-Control-Allow-Origin.*\*` | php-misc.yaml |

## P1.1 现代攻击面补全（v2）

> 以下条目在 v1 中遗漏，已新增对应 Semgrep 规则或建议人工 grep。

### RCE 补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `include($PATH)` / `require($PATH)` 动态 | High | `(include\|require)(_once)?\s*\(?\s*\$` | 已新增 `php-rce-include-dynamic` |
| `call_user_func($FN, ...)` 动态回调 | High | `call_user_func\(\s*\$` | 已新增 `php-rce-call-user-func` |
| `call_user_func_array($FN, ...)` | High | `call_user_func_array\(\s*\$` | 同上 |
| `class_exists($CLS)` + autoload | Medium | `class_exists\(\s*\$` | 已新增 `php-rce-class-exists-autoload` |
| `new $CLS(...)` 动态类实例化 | Medium | `new\s+\$` | autoloader 触发链 |
| `method_exists($OBJ, $METHOD)` 反射调用 | Medium | `method_exists\(.*\$` | 反射触发危险方法 |

### 反序列化补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `Symfony Serializer::deserialize($X, $CLS, ...)` | High | `->deserialize\(` | 已新增 `php-deser-004-symfony-serializer` |
| `compact()` + `extract()` 链式 | Medium | `compact\(.*extract\(` | 变量覆盖→ POI |
| `__toString()` 触发链 | Medium | `__toString\s*\(\)` | 反序列化 magic method |
| 自定义 `__wakeup` 含敏感操作 | Medium | `__wakeup\s*\(\)` | unserialize 自动调用 |
| `unserialize($X, ['allowed_classes' => false])` | INFO（安全） | `allowed_classes.*false` | 已新增 `php-deser-005-unserialize-allowed-classes` |

### SQL 注入补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| Doctrine `$QB->where($SQL . $VAR)` | High | `->where\(.*\.` | 已新增 `php-sqli-009-doctrine-where-concat` |
| Yii2 `createCommand($SQL)` 变量 | High | `->createCommand\(\s*\$` | 已新增 `php-sqli-010-yii2-raw` |
| WordPress `$wpdb->query($SQL)` 无 prepare | High | `\$wpdb->\(query\|get_results\)\(\s*\$` | 已升级到 ERROR |

### SSRF 补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `stream_context_create()` + `fopen()` / `file_get_contents()` | High | `stream_context_create` | 自定义协议 / Host header 注入 |
| `fsockopen($HOST, ...)` | Medium | `fsockopen\(\s*\$` | 低级 socket 连接 |
| `SoapClient($WSDL, ...)` 动态 WSDL | Medium | `new SoapClient\(\s*\$` | WSDL 缓存本地包含 + SSRF |
| `stream_get_contents()` + 用户路径 | Medium | `stream_get_contents\(` | 配合 wrapper |
| `curl_setopt(..., CURLOPT_URL, $URL)` 动态 | Medium | `CURLOPT_URL` | URL 用户可控 |

### 文件 / 上传补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `glob($PATTERN)` 用户可控 pattern | Low | `glob\(\s*\$` | 路径枚举 |
| `move_uploaded_file($_FILES['x']['tmp_name'], $DEST)` 路径用户可控 | High | `move_uploaded_file\(.*\$` | 上传到任意路径 |
| `file_put_contents($USER_PATH, ...)` | High | `file_put_contents\(\s*\$` | 任意文件写 |

### 现代 Web 攻击面

| 攻击面 | 关注点 | 备注 |
|--------|--------|------|
| Laravel Policy::authorize() | 自定义 Policy 逻辑漏洞 | php-auth.yaml 待补 |
| WordPress 插件钩子 | `add_filter('sanitize_file_name', ...)` 篡改 | php-misc.yaml 待补 |
| Symfony Security Voter | 自定义 Voter 权限逻辑 | php-auth.yaml 待补 |
| Composer auto-loaded packages | vendor/ 内被注册路由的第三方包 | tier-rules 已注释 |

