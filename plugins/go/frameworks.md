# Go 框架专项

## 框架探测

```bash
rg -tgo -n '"net/http"|http\.HandleFunc|http\.NewServeMux' --no-heading
rg -tgo -n 'github\.com/gin-gonic/gin|gin\.(Default|New)' --no-heading
rg -tgo -n 'github\.com/labstack/echo|echo\.New' --no-heading
rg -tgo -n 'github\.com/go-chi/chi|chi\.NewRouter' --no-heading
rg -tgo -n 'github\.com/gofiber/fiber|fiber\.New' --no-heading
rg -tgo -n 'github\.com/gorilla/mux|mux\.NewRouter' --no-heading
rg -tgo -n 'github\.com/beego/beego|beego\.Router' --no-heading
rg -tgo -n 'google\.golang\.org/grpc|grpc\.NewServer' --no-heading
```

同时读取 `go.mod`，确认框架、中间件、ORM、JWT 和序列化库的真实依赖。

## net/http

### 路由提取

```bash
rg -tgo -n '(http\.|ServeMux\.)Handle(Func)?\(' --no-heading
rg -tgo -n 'func\s+\([^)]*\)\s*ServeHTTP\(' --no-heading
```

### 输入来源

- `r.URL.Query().Get()`
- `r.FormValue()`、`r.PostFormValue()`、`r.MultipartReader()`
- `json.NewDecoder(r.Body).Decode()`
- `mux.Vars(r)` 或框架上下文中的 path 参数
- `r.Header.Get()`、Cookie、TLS client certificate

### 安全检查

- `http.Server` 是否设置 `ReadHeaderTimeout`、`ReadTimeout`、`WriteTimeout`、`IdleTimeout`
- 请求体是否使用 `http.MaxBytesReader` 或 `io.LimitReader`
- `ServeFile` / `FileServer` 的根目录和路径规范化
- `Redirect` 的目标是否固定或 allowlist
- Cookie 是否设置 `Secure`、`HttpOnly`、`SameSite`
- 状态变更接口的 CSRF 防护

## Gin

### 路由提取

```bash
rg -tgo -n '\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Any)\(' --no-heading
rg -tgo -n '\.Group\(|\.Use\(' --no-heading
```

### 输入与绑定

- `c.Param()`、`c.Query()`、`c.PostForm()`、`c.GetHeader()`
- `c.ShouldBind()`、`ShouldBindJSON()`、`BindJSON()`
- `c.FormFile()`、`c.MultipartForm()`

### 常见风险

- 路由组在 `.Use(Auth())` 之前注册
- 仅依赖 binding tag，缺少对象所有权和业务语义校验
- `c.File()` / `c.FileAttachment()` 使用用户路径
- `c.Redirect()` 使用用户 URL
- `c.HTML()` 配合 `template.HTML` 绕过转义
- `gin.Default()` 的日志记录敏感 query/header
- 生产环境启用 `gin.DebugMode`

## Echo

### 路由提取

```bash
rg -tgo -n '\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Any|Group)\(' --no-heading
rg -tgo -n '\.Use\(|\.Pre\(' --no-heading
```

### 输入与绑定

- `c.Param()`、`c.QueryParam()`、`c.FormValue()`
- `c.Bind()`、`c.Validate()`
- `c.FormFile()`、`c.MultipartForm()`

### 常见风险

- `Bind()` 可绑定未预期字段，需使用专用 DTO
- `Static()` / `File()` 根目录或路径可控
- `Redirect()` 目标可控
- JWT、CSRF、CORS middleware 的注册顺序或 skipper 范围错误
- 自定义 HTTPErrorHandler 泄露堆栈或内部错误

## Chi

### 路由提取

```bash
rg -tgo -n '\.(Get|Post|Put|Delete|Patch|Options|Head|Method|Handle|Route|Mount)\(' --no-heading
rg -tgo -n '\.(Use|With|Group)\(' --no-heading
```

### 常见风险

- `With(authMiddleware)` 只覆盖链式声明，兄弟路由未受保护
- `Mount()` 的子 router 未继承预期 middleware
- `chi.URLParam()` 直接用于数据库对象查询或文件路径
- 路由参数转换后缺少租户 / 所有权校验

## Fiber

### 路由提取

```bash
rg -tgo -n '\.(Get|Post|Put|Delete|Patch|Options|Head|All|Group|Use)\(' --no-heading
```

### 输入与绑定

- `c.Params()`、`c.Query()`、`c.FormValue()`
- `c.Body()`、`c.BodyParser()`
- `c.FormFile()`、`c.MultipartForm()`

### 常见风险

- fasthttp 对象只在请求生命周期内有效，异步 goroutine 使用需复制
- `SendFile()`、`Download()` 路径可控
- proxy middleware 的目标 URL 可控
- `Immutable`、body limit、header limit 和 trusted proxy 配置不当
- CORS wildcard 与 credential 组合

## Gorilla Mux

### 路由提取

```bash
rg -tgo -n '\.Handle(Func)?\(|\.Methods\(|\.PathPrefix\(|\.Subrouter\(' --no-heading
```

### 常见风险

- `mux.Vars(r)` 中的对象 ID 未做所有权校验
- `PathPrefix` + `FileServer` 暴露非预期目录
- `Use()` 注册位置导致部分子路由缺少认证
- `Queries()` / `Headers()` 仅用于匹配，不等价于输入校验

## Beego

### 路由提取

```bash
rg -tgo -n 'beego\.(Router|Include|InsertFilter)|web\.(Router|Include|InsertFilter)' --no-heading
rg -tgo -n 'func\s+\([^)]*\*.*Controller\)\s+(Get|Post|Put|Delete|Patch)\(' --no-heading
```

### 常见风险

- Controller 自动参数映射和未限制字段绑定
- Filter pattern 未覆盖所有 namespace
- `Ctx.Input.Param`、`GetString`、`GetFile` 进入 SQL、路径或 URL
- session、XSRF、directory index 和错误页配置不当

## gRPC

### 服务提取

```bash
rg -tgo -n 'Register[A-Za-z0-9_]+Server\(' --no-heading
rg -tgo -n 'grpc\.(UnaryInterceptor|StreamInterceptor|ChainUnaryInterceptor|ChainStreamInterceptor)' --no-heading
rg -tgo -n 'reflection\.Register\(' --no-heading
```

### 输入来源

- RPC request message
- `metadata.FromIncomingContext`
- peer 地址和 TLS identity
- stream 中的每条 message

### 常见风险

- 只配置 unary interceptor，stream RPC 无认证
- interceptor 仅认证但不做方法级授权
- reflection 和 health service 对不可信网络暴露
- message 大小和并发 stream 未限制
- `grpc.Dial` 目标由用户或配置写接口控制
- 错误详情泄露内部路径、SQL 或敏感对象

## ORM 与数据库

### database/sql 与 sqlx

- 安全：固定 SQL + driver 占位符参数
- 风险：字符串拼接、`fmt.Sprintf`、用户控制表名 / 列名 / 排序方向
- sqlx 的 `In()` 只处理值列表，不应把用户输入当 SQL 片段

### GORM

- `Where("id = ?", id)` 通常安全
- `Raw`、`Exec`、`Where(string)`、`Order`、`Select`、`Group` 的动态字符串需审计
- `db.First(&obj, userInput)` 在特定重载和类型下需确认生成 SQL
- Model 自动绑定后检查 mass assignment 和敏感字段覆盖

## 认证中间件覆盖方法

1. 枚举所有路由 / RPC 方法
2. 记录 router group、subrouter、middleware 和 interceptor 的注册顺序
3. 将每个入口映射到实际生效的认证、授权、限流和审计日志
4. 特别检查 health、metrics、debug、admin、internal、webhook、upload 和 callback
5. 不把“存在认证中间件”当作“所有入口已认证”的证据
