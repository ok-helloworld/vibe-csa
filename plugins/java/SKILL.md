---
name: vibe-csa-java
description: Java/Kotlin 代码审计插件。支持 Spring, Struts2, Jersey, Dubbo, gRPC, Play 框架。包含分层规则、危险模式、Semgrep 规则、反编译策略。
---

# Java/Kotlin 审计插件

## 语言检测

项目包含以下任一特征时识别为 Java：
- 存在 `.java` 或 `.kt` 文件
- 存在 `pom.xml` 或 `build.gradle`
- 存在 `WEB-INF/` 目录

## 分层规则

加载 `tier-rules.md` 进行文件分类：
- **T1**: Controllers、Filters、Interceptors、Servlets、Actions（入口点）
- **T2**: Services、DAOs、Repositories、Utils、Config（业务逻辑）
- **T3**: Entities、VOs、DTOs、Beans（数据结构）
- **SKIP**: 第三方库、测试代码、生成代码

## Layer 1 预扫描

### P0（Critical）危险模式

| 模式 | 漏洞类型 |
|------|----------|
| `readObject\(` | 反序列化 |
| `JSON\.parse(Object|)` | Fastjson 反序列化 |
| `fromXML\(` | XStream 反序列化 |
| `Yaml\.load` | SnakeYAML 反序列化 |
| `XMLDecoder` | XMLDecoder 反序列化 |
| `Runtime.*exec` | 命令执行 |
| `ProcessBuilder` | 命令执行 |
| `ScriptEngine.*eval` | 脚本引擎 RCE |
| `Velocity\.evaluate` | SSTI |
| `Template.*process` | FreeMarker SSTI |
| `parseExpression\(` | SpEL 注入 |
| `Ognl\.` | OGNL 注入 |
| `MVEL\.` | MVEL 注入 |
| `GroovyShell` | Groovy RCE |
| `InitialContext.*lookup` | JNDI 注入 |
| `HessianInput` | Hessian 反序列化 |

### P1（High）危险模式

| 模式 | 漏洞类型 |
|------|----------|
| `Statement\..*execute` | SQL 注入 |
| `prepareStatement.*\+` | SQL 注入（字符串拼接） |
| `\$\{[^}]+\}` | MyBatis SQL 注入 |
| `createQuery.*\+` | Hibernate SQL 注入 |
| `new URL\(` | SSRF |
| `HttpClient.*execute` | SSRF |
| `RestTemplate` | SSRF |
| `FileInputStream` / `FileOutputStream` | 文件操作 |
| `Files\.(readAllBytes|readAllLines|write)` | 文件操作 |
| `transferTo` | 文件上传 |
| `getOriginalFilename` | 文件上传 |
| `new File\(` | 路径遍历 |
| `Paths\.get\(` | 路径遍历 |
| `SAXParserFactory` | XXE |
| `DocumentBuilderFactory` | XXE |
| `XMLReader` | XXE |
| `SAXBuilder` | XXE |
| `SAXReader` | XXE |
| `DirContext.*search` | LDAP 注入 |
| `LdapTemplate.*search` | LDAP 注入 |

### P2（Medium）危险模式

| 模式 | 漏洞类型 |
|------|----------|
| `MD5` / `SHA-1` | 弱哈希 |
| `DES` / `ECB` | 弱加密 |
| `password\s*=\s*"[^"]+"` | 硬编码密钥 |
| `sendRedirect` | 开放重定向 |
| `getWriter.*write` | XSS |
| `SecurityContextHolder` | 认证配置 |
| `@RequestMapping` 无 `@PreAuthorize` | 认证缺失 |

## 框架专项

加载 `frameworks.md` 获取框架专属审计指南：
- Spring MVC / Spring Boot（注解路由、参数绑定、安全机制）
- Struts2（OGNL、Interceptor、通配符映射）
- Jersey/JAX-RS（注解路由、参数绑定）
- Dubbo（反序列化、泛化调用）
- gRPC（反序列化、TLS）
- Play Framework（Twirl 模板、路由文件）

## Semgrep 规则

加载 `semgrep/` 目录下的所有 YAML 规则：
- `java-rce.yaml` — 21 条：反序列化、SSTI、表达式注入、JNDI、RCE
- `java-sqli.yaml` — 12 条：SQL 注入、MyBatis、JPA/HQL
- `java-ssrf.yaml` — 8 条：SSRF
- `java-file.yaml` — 14 条：路径遍历、文件上传、文件读写
- `java-crypto.yaml` — 8 条：弱加密、弱哈希、不安全随机数、硬编码密钥
- `java-misc.yaml` — 56 条：XXE、XSS、认证、Session、日志、重定向、LDAP
- `java-config.yaml` — 95 条：Log4j2、Spring Security、Shiro、Fastjson 等组件配置
- `java-microservice.yaml` — 16 条：Feign、Gateway、Dubbo、gRPC、NoSQL
- `java-api-security.yaml` — 14 条：API 安全、输入验证、敏感数据
- `java-emerging.yaml` — 14 条：LLM/AI、GraphQL、Kotlin、Java 21、并发

## 反编译策略

如项目包含 `.class` 或 `.jar` 文件且无对应源码，加载 `decompile.md` 使用 CFR 反编译器。

## 双轨审计

### Sink 驱动
从 `sinks.md` 中的危险函数出发，向上追溯参数来源，追踪是否用户可控。

### 控制驱动
从 T1 Controller/Route 出发，向下追踪安全控制：
1. 是否有认证拦截器（Filter/Interceptor/Spring Security）
2. 是否有参数校验（`@Valid`、`BindingResult`）
3. 是否有输出编码（JSP `<c:out>`、Thymeleaf `th:text`）
4. 是否有 CSRF 保护

## 漏洞编号规则

```
{C/H/M/L}-{TYPE}-{SEQ}
```
- 前缀：C=Critical, H=High, M=Medium, L=Low
- TYPE: SQL=SQL注入, RCE=远程代码执行, SSRF=SSRF, FILE=文件操作, XXE=XXE, AUTH=认证绕过, XSS=XSS, DESER=反序列化, SSTI=SSTI, CRYPTO=加密弱点, REDIR=开放重定向, CONFIG=配置问题
- SEQ: 三位序号，如 001、002

## 输出格式

所有发现写入 `{output_path}/findings-raw.md`，每条包含：
- 漏洞编号
- 类型
- 严重程度
- 位置（file:line）
- 简要描述
- 危险函数/模式
- Track 来源（Sink 驱动 / 控制驱动）

## 能力基线检查

以下 24 项是 Java 项目审计的最低能力基线。每项必须在审计过程中被验证（PASS/FAIL/SKIP），确保无盲区：

### 反序列化检测
- [ ] `ObjectInputStream.readObject()` 无类型过滤
- [ ] `ObjectInputStream.readUnshared()` 无白名单
- [ ] Fastjson `JSON.parseObject()` 开启 autotype
- [ ] XStream `fromXML()` 未配置安全类型
- [ ] SnakeYAML `Yaml.load()` 无 SafeConstructor
- [ ] Jackson `enableDefaultTyping()` 启用多态类型
- [ ] Hessian/Burlap 反序列化无类型过滤
- [ ] XMLDecoder 解析用户输入

### 注入检测
- [ ] SQL 字符串拼接（Statement/MyBatis `${}`）
- [ ] SpEL/OGNL/MVEL/Groovy 表达式注入
- [ ] SSTI（Velocity/FreeMarker/Thymeleaf/Twirl）
- [ ] LDAP 注入（DirContext.search）

### RCE 检测
- [ ] `Runtime.exec()` 用户可控参数
- [ ] `ProcessBuilder` 用户可控参数
- [ ] `ScriptEngine.eval()` 用户输入

### SSRF 检测
- [ ] `new URL()` 用户可控
- [ ] `HttpClient/RestTemplate/OkHttp` 用户可控 URL
- [ ] JNDI `InitialContext.lookup()` 用户可控

### 文件安全
- [ ] `new File()` / `Paths.get()` 路径遍历
- [ ] 文件上传无类型/大小校验
- [ ] `transferTo()` 路径覆盖

### 加密安全
- [ ] MD5/SHA-1 用于密码/签名
- [ ] DES/3DES/ECB 加密
- [ ] 硬编码密码/密钥
- [ ] `SecureRandom` 未使用

### XSS/重定向
- [ ] `response.getWriter().write()` 用户输出未编码
- [ ] `sendRedirect()` 用户可控 URL

### 认证配置
- [ ] `@RequestMapping` 无 `@PreAuthorize`
- [ ] Spring Security 配置宽松
- [ ] Session 管理不安全

### 日志/配置
- [ ] Log4j2 JNDI Lookup 开启
- [ ] Shiro 反序列化
- [ ] 日志中记录敏感数据（密码/Token）
