---
name: vibe-csa-go
description: Go 代码安全审计插件。支持 net/http、Gin、Echo、Chi、Fiber、Gorilla Mux、Beego、gRPC，并提供分层规则、危险函数目录和 Semgrep 规则。
---

# Go 安全审计插件

## 语言检测

项目包含以下任一特征时识别为 Go：

- 存在 `.go` 文件
- 存在 `go.mod`、`go.work` 或 `go.sum`
- 存在 `cmd/*/main.go`

通过 `go.mod` 的 `module` 行识别项目模块名。审计时排除标准库、模块缓存、`vendor/` 和生成代码。

## 分层规则

加载 `tier-rules.md` 进行文件分类：

- **T1**：HTTP/RPC handlers、路由注册、中间件、Webhook、GraphQL resolver
- **T2**：Service、UseCase、Repository、Store、Client、Worker、模板和资源加载
- **T3**：DTO、Model、Entity、Schema、纯配置结构
- **SKIP**：测试、mock、vendor、生成代码、protobuf 生成文件

## Layer 1 预扫描

### P0（Critical）候选

| 模式 | 漏洞类型 |
|------|----------|
| `exec.Command` / `exec.CommandContext` | 命令注入 |
| `template.New(...).Parse(userInput)` | SSTI / 模板注入 |
| `plugin.Open(userPath)` | 动态插件加载 |
| `db.Query(fmt.Sprintf(...))` | SQL 注入 |
| `db.Exec("..." + input)` | SQL 注入 |
| `gorm.Raw` / `gorm.Exec` 拼接 SQL | SQL 注入 |

### P1（High）候选

| 模式 | 漏洞类型 |
|------|----------|
| `http.Get` / `http.NewRequest` / `Client.Do` | SSRF |
| `net.Dial` / `grpc.Dial` | SSRF / 内网访问 |
| `os.Open` / `os.ReadFile` / `http.ServeFile` | 路径遍历 / 文件读取 |
| `os.Create` / `os.WriteFile` / `io.Copy` | 任意文件写入 |
| `FormFile` / `MultipartForm` | 不安全文件上传 |
| `archive/zip` 解压到可控路径 | Zip Slip |
| `gob.Decoder.Decode` | 不可信数据解码 |
| `template.HTML` / `template.JS` | XSS 绕过 |
| `http.Redirect` / 框架 Redirect | 开放重定向 |

### P2（Medium）候选

| 模式 | 漏洞类型 |
|------|----------|
| `md5.New` / `sha1.New` | 弱哈希 |
| `math/rand` 用于 token、密码或 nonce | 不安全随机数 |
| `tls.Config{InsecureSkipVerify: true}` | TLS 校验禁用 |
| `MinVersion: tls.VersionTLS10/11` | 弱 TLS |
| `gin.SetMode(gin.DebugMode)` | 调试配置 |
| `pprof` 暴露 | 调试接口暴露 |
| 硬编码 token、secret、password | 凭据泄露 |

## 框架专项

加载 `frameworks.md`：

- net/http：`HandleFunc`、`ServeMux`、`ServeHTTP`
- Gin：路由组、中间件、`ShouldBind`、文件上传
- Echo：路由组、`Bind`、middleware
- Chi：`Route`、`Mount`、中间件继承范围
- Fiber：路由、`BodyParser`、静态文件与代理
- Gorilla Mux：`HandleFunc`、`Methods`、子路由
- Beego：Controller、Router、Filter
- gRPC：服务注册、interceptor、metadata、反射服务

## Semgrep 规则

加载 `semgrep/` 下全部 YAML：

- `go-rce.yaml`：命令执行、动态模板和插件加载
- `go-sqli.yaml`：database/sql、sqlx、GORM 原始 SQL
- `go-ssrf.yaml`：HTTP、底层网络连接和 gRPC 目标
- `go-file.yaml`：文件读写、上传、路径遍历和 Zip Slip
- `go-deser.yaml`：gob、YAML、mapstructure 等不可信解码候选
- `go-crypto.yaml`：弱哈希、弱 TLS、不安全随机数
- `go-config.yaml`：TLS、CORS、pprof、调试模式和硬编码凭据
- `go-misc.yaml`：XSS 绕过、开放重定向、Header 注入和 JWT 候选

Semgrep 命中只表示候选。必须继续确认：

1. 参数是否来自请求、消息队列、RPC metadata、数据库或可写配置
2. 是否存在 allowlist、规范化、参数化查询或固定映射
3. 防护是否在所有分支和所有路由组生效
4. sink 是否实际可达，而非测试、示例或死代码

## 双轨审计

### Sink 驱动

从 `sinks.md` 的危险函数反向追踪输入：

- HTTP：`r.URL.Query()`、`r.FormValue()`、`json.Decoder`
- Gin：`c.Query()`、`c.Param()`、`c.PostForm()`、`c.ShouldBind*()`
- Echo：`c.QueryParam()`、`c.Param()`、`c.FormValue()`、`c.Bind()`
- Fiber：`c.Query()`、`c.Params()`、`c.FormValue()`、`c.BodyParser()`
- gRPC：请求 message、incoming metadata、透传 header
- 间接来源：数据库字段、环境变量、配置中心、消息队列和对象存储 metadata

Go 的 `exec.Command(name, args...)` 不经过 shell 时通常不会解释 `;`、`|` 等元字符，但仍需检查：

- 可执行文件名是否可控
- 是否显式调用 `sh -c`、`bash -c`、`cmd /C` 或 PowerShell
- 参数是否导致目标程序自身的参数注入
- 工作目录、环境变量或 `PATH` 是否可控

对配置驱动的模板、资源、插件和文件消费链，不得停在 grep 命中。必须追踪配置值或数据库值是否进入 `ParseFiles`、`ExecuteTemplate`、`plugin.Open`、文件系统或动态路由。

### 控制驱动

从 T1 路由和 RPC 方法向下检查：

1. 认证中间件或 interceptor 是否覆盖该入口
2. 是否校验对象所有权、租户和角色
3. `ShouldBind` / `Bind` / `BodyParser` 后是否执行语义校验
4. 是否设置 body 大小、上传大小、超时和限流
5. 输出是否经过 `html/template` 转义，是否滥用 `template.HTML`
6. 状态变更接口是否具备 CSRF 或等价的来源约束

## Go 专项审计要点

### 并发和状态

- 检查共享 map、缓存、余额、库存和幂等键是否正确加锁
- 检查“先检查后更新”是否可被并发绕过
- 检查 goroutine 是否捕获并长期使用请求对象、敏感值或已关闭资源
- 检查 context 取消和 deadline 是否向数据库、HTTP、gRPC 调用传递

### HTTP 客户端

- 自定义 `Transport.DialContext` 是否阻止 loopback、link-local、私网和重绑定
- 重定向后的目标是否重新校验
- 是否设置连接、TLS handshake、response header 和整体请求超时
- 是否限制响应体大小并及时关闭 `resp.Body`

### 文件系统

- `filepath.Clean` 本身不是根目录约束
- `filepath.Join(base, userPath)` 后必须验证结果仍在可信根目录内
- 防止绝对路径、`..`、符号链接和 Windows volume 路径逃逸
- 解压 zip/tar 时逐个校验目标路径

### 数据库

- `database/sql` 占位符必须匹配驱动：`?`、`$1`、`@p1`
- 表名、列名和排序字段不能通过普通占位符绑定，必须使用固定 allowlist 映射
- GORM 的 `Raw`、`Exec`、`Where(string)`、`Order`、`Select` 需检查字符串来源

## 漏洞编号规则

```text
{C/H/M/L}-{TYPE}-{SEQ}
```

- TYPE：`SQL`、`RCE`、`SSRF`、`FILE`、`AUTH`、`XSS`、`DESER`、`SSTI`、`CRYPTO`、`REDIR`、`CONFIG`、`RACE`
- SEQ：三位序号，例如 `001`

## 输出格式

所有发现写入 `{output_path}/findings-raw.md`，每条包含：

- 漏洞编号、类型、严重程度
- `file:line`
- 输入源、传播路径和危险 sink
- 框架与路由 / RPC 方法
- 已确认的防护及其缺口
- Track 来源（Sink 驱动 / 控制驱动）
- EVID_* 证据引用

## 能力基线检查

### 命令与模板

- [ ] `exec.Command` / `CommandContext` 的程序名和参数来源
- [ ] `sh -c` / `bash -c` / `cmd /C` / PowerShell 调用
- [ ] 动态 `template.Parse` / `ParseFiles` / `ExecuteTemplate`
- [ ] `plugin.Open` 路径及插件文件写入链

### 注入

- [ ] `database/sql` 字符串拼接、`fmt.Sprintf` 和动态标识符
- [ ] sqlx `Select/Get/Queryx` 原始 SQL
- [ ] GORM `Raw/Exec/Where/Order/Select`
- [ ] Header、CRLF、日志和 GraphQL 注入候选

### SSRF

- [ ] `http.Get/Post/NewRequest` 用户可控 URL
- [ ] `Client.Do` 的 Request URL 来源
- [ ] `net.Dial` / `grpc.Dial` 用户可控目标
- [ ] 重定向、DNS 重绑定、代理和私网地址绕过
- [ ] 客户端超时和响应体大小限制

### 文件

- [ ] `os.Open/ReadFile/ServeFile` 路径约束
- [ ] `os.Create/WriteFile/Rename/Remove` 路径约束
- [ ] 上传文件名、大小、类型和存储目录
- [ ] zip/tar 解压路径和符号链接
- [ ] 上传或写入结果是否被模板、插件、静态文件或执行机制二次消费

### 认证与配置

- [ ] 路由组和子路由的认证中间件覆盖
- [ ] gRPC unary/stream interceptor 覆盖
- [ ] IDOR、租户隔离和字段级授权
- [ ] CORS、CSRF、Cookie、JWT 和 session 配置
- [ ] `InsecureSkipVerify`、弱 TLS、pprof 和调试接口
- [ ] 硬编码凭据、弱哈希和 `math/rand` 安全用途

### 并发与资源

- [ ] 共享状态竞态和 TOCTOU
- [ ] context deadline / cancellation 传播
- [ ] HTTP Server 的读写超时和 Header 限制
- [ ] goroutine、连接、文件和 response body 泄漏
