# Go 危险函数目录（Sinks）

Semgrep 和 ripgrep 命中仅用于定位候选，必须结合输入来源、数据流和防护确认。

## 命令执行与动态代码

| Sink | 风险 | 搜索模式 | Semgrep |
|------|------|----------|---------|
| `exec.Command(name, args...)` | Critical | `exec\.Command\(` | go-rce.yaml |
| `exec.CommandContext(ctx, name, args...)` | Critical | `exec\.CommandContext\(` | go-rce.yaml |
| `sh -c` / `bash -c` / `cmd /C` / PowerShell | Critical | `"(sh|bash|cmd|powershell)"` | go-rce.yaml |
| `template.New(...).Parse(input)` | Critical | `\.Parse\(` | go-rce.yaml |
| `template.ParseFiles(paths...)` | High | `template\.ParseFiles\(` | go-rce.yaml |
| `plugin.Open(path)` | Critical | `plugin\.Open\(` | go-rce.yaml |

`exec.Command` 不自动经过 shell。仅当程序名、shell command、参数语义、环境、工作目录或 PATH 可被攻击者影响时确认漏洞。

## SQL 注入

| Sink | 风险 | 搜索模式 | Semgrep |
|------|------|----------|---------|
| `db.Query/QueryRow/Exec` | High | `\.(Query|QueryRow|Exec)(Context)?\(` | go-sqli.yaml |
| `fmt.Sprintf` 构造 SQL | High | `fmt\.Sprintf\(` | go-sqli.yaml |
| sqlx `Select/Get/Queryx/NamedExec` | High | `\.(Select|Get|Queryx|NamedExec)\(` | go-sqli.yaml |
| GORM `Raw/Exec` | High | `\.(Raw|Exec)\(` | go-sqli.yaml |
| GORM `Where/Order/Select/Group` 动态字符串 | High | `\.(Where|Order|Select|Group)\(` | go-sqli.yaml |

正确做法：

- 值使用 driver 占位符
- 表名、列名、排序字段使用固定 allowlist 映射
- 不把用户字符串直接作为 GORM clause

## SSRF 与网络访问

| Sink | 风险 | 搜索模式 | Semgrep |
|------|------|----------|---------|
| `http.Get/Post/Head` | High | `http\.(Get|Post|Head)\(` | go-ssrf.yaml |
| `http.NewRequest/NewRequestWithContext` | High | `http\.NewRequest` | go-ssrf.yaml |
| `client.Do(req)` | High | `\.Do\(` | go-ssrf.yaml |
| `net.Dial/DialTimeout` | High | `net\.Dial` | go-ssrf.yaml |
| `net.Dialer.DialContext` | High | `DialContext\(` | go-ssrf.yaml |
| `grpc.Dial/DialContext/NewClient` | High | `grpc\.(Dial|NewClient)` | go-ssrf.yaml |
| `httputil.NewSingleHostReverseProxy` | High | `NewSingleHostReverseProxy` | go-ssrf.yaml |

确认要点：

- 解析 URL 后校验 scheme、hostname、port
- DNS 解析结果阻止 loopback、private、link-local、multicast 和 unspecified
- 每次重定向重新校验
- 禁止通过用户控制 proxy
- 设置超时、响应体上限和连接上限

## 文件读取、写入与上传

### 读取

| Sink | 风险 | 搜索模式 | Semgrep |
|------|------|----------|---------|
| `os.Open/OpenFile` | High | `os\.Open(File)?\(` | go-file.yaml |
| `os.ReadFile` | High | `os\.ReadFile\(` | go-file.yaml |
| `http.ServeFile` | High | `http\.ServeFile\(` | go-file.yaml |
| `gin.Context.File/FileAttachment` | High | `\.(File|FileAttachment)\(` | go-file.yaml |
| `fiber.Ctx.SendFile/Download` | High | `\.(SendFile|Download)\(` | go-file.yaml |

### 写入

| Sink | 风险 | 搜索模式 | Semgrep |
|------|------|----------|---------|
| `os.Create/OpenFile/WriteFile` | High | `os\.(Create|OpenFile|WriteFile)\(` | go-file.yaml |
| `io.Copy(dst, src)` | High | `io\.Copy\(` | go-file.yaml |
| `os.Rename/Remove/RemoveAll` | High | `os\.(Rename|Remove|RemoveAll)\(` | go-file.yaml |

### 上传

| Source / Sink | 风险 | 搜索模式 |
|---------------|------|----------|
| `r.FormFile()` | High | `\.FormFile\(` |
| Gin / Echo / Fiber `FormFile()` | High | `\.FormFile\(` |
| `multipart.FileHeader.Filename` | High | `\.Filename` |
| 上传流复制到 `os.Create` | High | `io\.Copy` |

上传检查：

- 不直接使用客户端文件名
- 使用服务端生成的随机名
- 限制 body 和单文件大小
- 校验实际内容、扩展名和用途
- 上传目录不可执行，且不被模板、插件或静态路由意外消费

### 路径约束

`filepath.Clean`、`filepath.Base`、`filepath.Join` 单独使用都不能证明路径安全。推荐：

1. 固定可信根目录并取绝对路径
2. 对候选路径求绝对路径 / EvalSymlinks
3. 使用 `filepath.Rel(root, target)`
4. 拒绝 `..`、绝对逃逸、volume 变化和符号链接越界

## 归档解压

| Sink | 风险 | 搜索模式 |
|------|------|----------|
| `zip.File.Open` + `filepath.Join(dest, file.Name)` | Critical | `archive/zip|filepath\.Join` |
| `tar.Reader.Next` + 文件写入 | Critical | `archive/tar|Next\(\)` |

逐个 entry 校验路径。额外检查符号链接、硬链接、绝对路径、Windows drive / UNC 路径和解压总大小。

## 反序列化与对象绑定

| Sink | 风险 | 搜索模式 | Semgrep |
|------|------|----------|---------|
| `gob.Decoder.Decode` | High | `gob\.NewDecoder|\.Decode\(` | go-deser.yaml |
| `yaml.Unmarshal` / Decoder.Decode | Medium | `yaml\.(Unmarshal|NewDecoder)` | go-deser.yaml |
| `mapstructure.Decode` | Medium | `mapstructure\.Decode` | go-deser.yaml |
| `json.Decoder.Decode` 到宽泛 map/interface | Medium | `json\.NewDecoder` | go-deser.yaml |

Go 的 JSON/YAML 解码通常不是传统 gadget RCE。只有在后续触发动态类型、命令、模板、路径、SQL、插件或危险业务字段时升级严重性。

检查：

- 请求 DTO 是否专用，避免直接绑定持久化 model
- 是否拒绝未知字段
- 数字溢出、递归深度、集合大小和内存消耗
- 类型断言失败、默认值绕过和敏感字段 mass assignment

## 模板与 XSS

| Sink | 风险 | 搜索模式 | Semgrep |
|------|------|----------|---------|
| `template.HTML(input)` | High | `template\.HTML\(` | go-misc.yaml |
| `template.JS(input)` | High | `template\.JS\(` | go-misc.yaml |
| `template.URL(input)` | High | `template\.URL\(` | go-misc.yaml |
| `text/template` 输出 HTML | High | `"text/template"` | go-rce.yaml |
| 动态解析模板源码 | Critical | `\.Parse\(` | go-rce.yaml |

优先使用 `html/template`。只有确认输入可信时才使用 typed safe string。

## 开放重定向与 Header 注入

| Sink | 风险 | 搜索模式 | Semgrep |
|------|------|----------|---------|
| `http.Redirect(w, r, target, code)` | Medium | `http\.Redirect\(` | go-misc.yaml |
| Gin / Echo / Fiber Redirect | Medium | `\.Redirect\(` | go-misc.yaml |
| `Header().Set/Add` | Medium | `Header\(\)\.(Set|Add)` | go-misc.yaml |

重定向目标使用站内相对路径或可信 host allowlist。Header 值拒绝 CR/LF，并检查反向代理对重复 header 的处理。

## 认证、JWT 与 Cookie

| 候选点 | 风险 | 搜索模式 |
|--------|------|----------|
| 路由未经过 auth middleware | High | 路由表与 `.Use()` 对比 |
| gRPC 缺少 unary / stream interceptor | High | `grpc\.NewServer` |
| JWT 解析未固定算法 | High | `jwt\.(Parse|ParseWithClaims)` |
| JWT 使用 `WithoutClaimsValidation` | High | `WithoutClaimsValidation` |
| Cookie 缺少安全属性 | Medium | `http\.SetCookie` |

JWT 必须校验签名算法、issuer、audience、expiry、not-before 和 key selection。不能仅以解析成功作为认证成功。

## 加密与 TLS

| Sink | 风险 | 搜索模式 | Semgrep |
|------|------|----------|---------|
| `crypto/md5` / `crypto/sha1` | Medium | `"crypto/(md5|sha1)"` | go-crypto.yaml |
| `des.NewCipher` / 3DES | Medium | `des\.New` | go-crypto.yaml |
| `math/rand` 用于 secret | Medium | `"math/rand"` | go-crypto.yaml |
| `InsecureSkipVerify: true` | High | `InsecureSkipVerify` | go-config.yaml |
| TLS 1.0 / 1.1 | Medium | `VersionTLS1[01]` | go-crypto.yaml |

密码使用 Argon2id、bcrypt 或 scrypt。token、nonce 和 session ID 使用 `crypto/rand`。

## 配置与调试接口

| 候选点 | 风险 | 搜索模式 | Semgrep |
|--------|------|----------|---------|
| `net/http/pprof` 暴露 | High | `net/http/pprof` | go-config.yaml |
| `reflection.Register` 对外开放 | Medium | `reflection\.Register` | go-config.yaml |
| Gin DebugMode | Medium | `gin\.DebugMode` | go-config.yaml |
| CORS `AllowAllOrigins` / wildcard | Medium | `AllowAllOrigins|AllowedOrigins` | go-config.yaml |
| 硬编码 secret / token / password | High | `(?i)(secret|token|password)` | go-config.yaml |

## 并发与资源安全

无统一 Semgrep sink，需源码审查：

- map、slice、缓存和全局状态的并发读写
- 余额、库存、配额和幂等键的事务 / 锁
- goroutine 泄漏、无界 channel、无界 worker
- `resp.Body`、Rows、文件和连接是否关闭
- context 是否传入 SQL、HTTP 和 gRPC
- 超时、请求体大小、压缩炸弹和解压总量限制
