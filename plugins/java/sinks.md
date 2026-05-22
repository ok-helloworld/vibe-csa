# Java 危险函数目录（Sinks）

按漏洞类型分类。每条包含：函数签名、风险等级、grep 搜索模式、对应的 Semgrep 规则类别。

## RCE（远程代码执行）

### 反序列化
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `ObjectInputStream.readObject()` | Critical | `readObject\(` | java-rce.yaml |
| `ObjectMapper.readValue()` (Jackson) | Critical | `readValue\(` | java-rce.yaml |
| `JSON.parseObject()` / `JSON.parse()` (Fastjson) | Critical | `JSON\.parse` | java-rce.yaml |
| `XStream.fromXML()` | Critical | `fromXML\(` | java-rce.yaml |
| `Yaml.load()` (SnakeYAML) | Critical | `Yaml\.load` | java-rce.yaml |
| `XMLDecoder.readObject()` | Critical | `XMLDecoder` | java-rce.yaml |
| `HessianInput.readObject()` | Critical | `HessianInput` | java-rce.yaml |

### SSTI（服务端模板注入）
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `Velocity.evaluate()` | Critical | `Velocity\.evaluate` | java-rce.yaml |
| `Template.process()` (FreeMarker) | Critical | `Template.*process` | java-rce.yaml |
| `Thymeleaf` 用户可控模板 | Critical | `SpringTemplateEngine` | java-rce.yaml |

### 表达式注入
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `SpelExpressionParser.parseExpression()` | Critical | `parseExpression\(` | java-rce.yaml |
| `OgnlUtil.getValue()` / `Ognl.parseExpression()` | Critical | `Ognl\.` | java-rce.yaml |
| `MVEL.eval()` / `MVEL.executeExpression()` | Critical | `MVEL\.` | java-rce.yaml |
| `GroovyShell.evaluate()` | Critical | `GroovyShell` | java-rce.yaml |

### JNDI 注入
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `InitialContext.lookup()` | Critical | `InitialContext.*lookup` | java-rce.yaml |
| `JndiTemplate.lookup()` | Critical | `JndiTemplate.*lookup` | java-rce.yaml |

### 命令执行
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `Runtime.getRuntime().exec()` | Critical | `Runtime.*exec` | java-rce.yaml |
| `ProcessBuilder.start()` | Critical | `ProcessBuilder` | java-rce.yaml |
| `ScriptEngine.eval()` | Critical | `ScriptEngine.*eval` | java-rce.yaml |

## SQL 注入

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `Statement.executeQuery(sql)` (JDBC) | High | `Statement\..*execute` | java-sqli.yaml |
| `PreparedStatement` 字符串拼接 | High | `prepareStatement.*\+` | java-sqli.yaml |
| MyBatis `${}` 占位符 | High | `\$\{[^}]+\}` | java-sqli.yaml |
| MyBatis `ORDER BY ${}` | High | `ORDER BY.*\$` | java-sqli.yaml |
| `Session.createQuery()` 字符串拼接 (Hibernate) | High | `createQuery.*\+` | java-sqli.yaml |
| `EntityManager.createNativeQuery()` 字符串拼接 | High | `createNativeQuery.*\+` | java-sqli.yaml |
| JPA `@Query` 中的 SpEL 注入 | High | `@Query.*#\{` | java-sqli.yaml |

## SSRF

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `HttpURLConnection` (URL 用户可控) | High | `new URL\(` | java-ssrf.yaml |
| `HttpClient.execute()` (URI 用户可控) | High | `HttpClient.*execute` | java-ssrf.yaml |
| `RestTemplate.getForObject()` (URL 用户可控) | High | `RestTemplate.*getForObject` | java-ssrf.yaml |
| `OkHttpClient.newCall()` (URL 用户可控) | High | `OkHttpClient` | java-ssrf.yaml |
| `WebRequest` / `URI.create()` 用户可控 | High | `URI\.create\(` | java-ssrf.yaml |

## 文件操作

### 文件读取
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `new FileInputStream(path)` | High | `FileInputStream` | java-file.yaml |
| `Files.readAllBytes(path)` | High | `Files\.readAllBytes` | java-file.yaml |
| `Files.readAllLines(path)` | High | `Files\.readAllLines` | java-file.yaml |
| `BufferedReader` / `Scanner` (path 用户可控) | High | `new BufferedReader\|new Scanner` | java-file.yaml |

### 文件写入
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `new FileOutputStream(path)` | High | `FileOutputStream` | java-file.yaml |
| `Files.write(path)` | High | `Files\.write` | java-file.yaml |
| `FileWriter` | High | `FileWriter` | java-file.yaml |

### 文件上传
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `MultipartFile.transferTo()` | High | `transferTo` | java-file.yaml |
| `FileItem.write()` (Commons FileUpload) | High | `FileItem.*write` | java-file.yaml |
| 上传文件名直接使用用户输入 | High | `getOriginalFilename` | java-file.yaml |

### 路径遍历
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `new File(userInput)` | High | `new File\(` | java-file.yaml |
| `Paths.get(userInput)` | High | `Paths\.get\(` | java-file.yaml |

## XXE

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `SAXParserFactory` 未禁用 XXE | High | `SAXParserFactory` | java-misc.yaml |
| `DocumentBuilderFactory` 未禁用 XXE | High | `DocumentBuilderFactory` | java-misc.yaml |
| `XMLReader` 未禁用 XXE | High | `XMLReader` | java-misc.yaml |
| `SAXBuilder` (JDOM2) 未禁用 XXE | High | `SAXBuilder` | java-misc.yaml |
| `SAXReader` (dom4j) 未禁用 XXE | High | `SAXReader` | java-misc.yaml |

## LDAP 注入

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `DirContext.search()` (filter 用户可控) | High | `DirContext.*search` | java-misc.yaml |
| `LdapTemplate.search()` (filter 用户可控) | High | `LdapTemplate.*search` | java-misc.yaml |

## 认证/授权

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| URI 解析绕过（分号、路径规范化） | High | `getPath\(\)` | java-misc.yaml |
| 缺少 `@PreAuthorize` 的敏感端点 | Medium | `@RequestMapping` (无 `@PreAuthorize`) | java-misc.yaml |
| `SecurityContextHolder` 使用不当 | Medium | `SecurityContextHolder` | java-misc.yaml |

## 加密弱点

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `MessageDigest.getInstance("MD5"/"SHA-1")` | Medium | `MD5\|SHA-1` | java-crypto.yaml |
| `Cipher.getInstance("DES"/"ECB")` | Medium | `DES\|ECB` | java-crypto.yaml |
| 硬编码密钥/密码 | Medium | `password\s*=\s*"[^"]+"\|key\s*=\s*"[^"]+"` | java-crypto.yaml |
| `SecureRandom` 使用不当 | Low | `SecureRandom` | java-crypto.yaml |

## XSS

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `HttpServletResponse.getWriter().write(userInput)` | Medium | `getWriter.*write` | java-misc.yaml |
| `HttpServletRequest` 参数直接输出 | Medium | `getParameter` + `write\|print` | java-misc.yaml |

## 开放重定向

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `HttpServletResponse.sendRedirect(userInput)` | Medium | `sendRedirect` | java-misc.yaml |
| `Response.redirect()` | Medium | `redirect.*user` | java-misc.yaml |

## P1.1 现代攻击面补全（v2）

> 以下条目在 v1 中遗漏，已新增对应 Semgrep 规则或建议人工 grep。

### 反序列化补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `ObjectStreamClass.forClass()` | High | `ObjectStreamClass\.forClass` | 动态类加载，可被链式利用 |
| `Kryo.readObject()` | High | `Kryo\(\)\.readObject\|kryo\.readObject` | Kryo 无类型注册时存在 |
| `Protobuf` 自定义 oneof 反射 | Medium | `parseFrom\(` 配合自定义 Resolver | 罕见但存在 |
| `ScriptEngineManager.getEngineByName()` | High | `ScriptEngineManager\|getEngineByName` | JavaScript/JS 引擎可执行任意代码 |
| `SnakeYAML.load(stream)` | High | `Yaml\.\(load\|loadAll\)\(` | 已新增 `java-snakeyaml-load` |

### SSRF 补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `new Socket($HOST, $PORT)` | Medium | `new Socket\(` / `new java\.net\.Socket\(` | 已新增 `java-ssrf-socket` |
| `System.setProperty("http.proxyHost", ...)` | High | `proxyHost\|proxyPort` | 已新增 `java-ssrf-proxy-config` |
| `HttpServer.createHttpServer()` 反向代理转发 | Medium | `HttpServer\.create` | 反代场景注意 host header 注入 |
| Dubbo `ReferenceConfig.setUrl($URL)` | Medium | `setUrl\(` | 动态注册中心地址 |

### 表达式/模板注入补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `@Value("#{T(Runtime)...}")` | High | `@Value\(.*T\s*\(.*Runtime` | 已新增 `java-spel-annotation-value` |
| `GroovyShell().evaluate($SCRIPT)` | High | `GroovyShell.*evaluate` | 已新增 `java-groovy-shell-eval` |
| `PebbleEngine.render($TPL)` | Medium | `PebbleEngine` | Pebble 模板 SSTI |
| Spring `@RequestMapping("/${prop}")` 动态路由 | Low | `RequestMapping.*\$\{` | 配置注入到路由 |

### SQL 注入补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `Connection.prepareStatement($SQL + ...)` | High | `prepareStatement\(.*\+` | 已新增 `java-sqli-prepared-statement-concat` |
| Spring Data `@Query` + SpEL `:#{#x}` | Medium | `@Query.*:#\{#` | 已新增 `java-sqli-spring-query-spel` |
| Criteria API 动态列名 `root.get(colName)` | Medium | `root\.get\(.*[^"]\)` | colName 用户可控时 |
| MyBatis `<if test="...">` 动态 SQL 中变量未参数化 | Medium | MyBatis XML | 仍需 grep XML |

### Log4Shell 类型

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `Logger.info("$user_data: {}", value)` | High (在 log4j ≤2.16) | `LOGGER\.\(info\|warn\|error\|debug\)\(.*\$` | 已新增 `java-log4j-jndi-sink`（INFO 级提醒） |

