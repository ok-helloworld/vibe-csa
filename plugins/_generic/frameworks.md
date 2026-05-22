# Generic 框架探测与路由提取

> 无框架字典，靠 ripgrep 关键字探测 + 路由提取命令。覆盖 Go/Node/TS/Ruby/Rust/C# 常见框架的最小可用集。

## 1. 框架探测命令（在项目根执行）

```bash
# Go
rg -t go -l 'gin\.Default|gin\.New|github.com/gin-gonic/gin' && echo "==> Gin"
rg -t go -l 'echo\.New|github.com/labstack/echo' && echo "==> Echo"
rg -t go -l 'chi\.NewRouter|github.com/go-chi/chi' && echo "==> Chi"
rg -t go -l 'fiber\.New|github.com/gofiber/fiber' && echo "==> Fiber"
rg -t go -l 'mux\.NewRouter|gorilla/mux' && echo "==> Gorilla Mux"
rg -t go -l 'http\.HandleFunc|http\.Handle' && echo "==> net/http (stdlib)"
rg -t go -l 'grpc\.NewServer|google.golang.org/grpc' && echo "==> gRPC"

# Node / TypeScript
rg -tjs -tts -l 'express\(\)|require\(.express.\)' && echo "==> Express"
rg -tjs -tts -l 'koa\(\)|new Koa\(\)' && echo "==> Koa"
rg -tjs -tts -l 'fastify\(\)|require\(.fastify.\)' && echo "==> Fastify"
rg -tjs -tts -l 'NestFactory|@nestjs/core' && echo "==> NestJS"
rg -tjs -tts -l 'next/server|getServerSideProps' && echo "==> Next.js"
rg -tjs -tts -l '@hapi/hapi|hapi\.server' && echo "==> Hapi"

# Ruby
rg -trb -l 'class.*<.*ApplicationController|Rails.application' && echo "==> Rails"
rg -trb -l 'class.*<.*Sinatra::Base|Sinatra::Application' && echo "==> Sinatra"
rg -trb -l 'Grape::API' && echo "==> Grape"

# C# / .NET
rg -tcs -l 'WebApplication\.CreateBuilder|MapControllers' && echo "==> ASP.NET Core (minimal/MVC)"
rg -tcs -l '\[ApiController\]|HttpGet\(|HttpPost\(' && echo "==> ASP.NET Web API"
rg -tcs -l 'using Nancy|class.*: NancyModule' && echo "==> NancyFx"

# Rust
rg -trs -l 'actix_web::|HttpServer::new' && echo "==> actix-web"
rg -trs -l 'axum::|Router::new\(\)' && echo "==> Axum"
rg -trs -l 'rocket::|#\[rocket::main\]' && echo "==> Rocket"
rg -trs -l 'warp::Filter' && echo "==> Warp"
```

## 2. 路由提取（按框架）

### Go

| 框架 | 路由提取命令 |
|------|-------------|
| net/http (stdlib) | `rg -t go -n 'http\.HandleFunc\(\|mux\.Handle\(' --no-heading` |
| Gin | `rg -t go -n 'router\.(GET\|POST\|PUT\|DELETE\|PATCH\|Any)\(' --no-heading` |
| Echo | `rg -t go -n 'e\.(GET\|POST\|PUT\|DELETE\|PATCH\|Any)\(' --no-heading` |
| Chi | `rg -t go -n 'r\.(Get\|Post\|Put\|Delete\|Method)\(' --no-heading` |
| Fiber | `rg -t go -n 'app\.(Get\|Post\|Put\|Delete\|All)\(' --no-heading` |
| Gorilla Mux | `rg -t go -n 'r\.HandleFunc\(.+\)\.Methods\(' --no-heading` |

### Node / TypeScript

| 框架 | 路由提取命令 |
|------|-------------|
| Express | `rg -tjs -tts -n '(app\|router)\.(get\|post\|put\|delete\|patch\|all)\(' --no-heading` |
| Koa | `rg -tjs -tts -n 'router\.(get\|post\|put\|delete)\(' --no-heading` |
| Fastify | `rg -tjs -tts -n 'fastify\.(get\|post\|put\|delete)\(\|fastify\.route\(' --no-heading` |
| NestJS | `rg -tjs -tts -n '@(Get\|Post\|Put\|Delete\|Patch\|All)\(' --no-heading` |
| Next.js API | `find pages/api app/api -type f -name '*.ts' -o -name '*.js' -o -name '*.tsx'` |

### Ruby

| 框架 | 路由提取 |
|------|---------|
| Rails | Read `config/routes.rb` 或 `rg -trb -n 'class.+ApplicationController\|def (index\|show\|create\|update\|destroy)'` |
| Sinatra | `rg -trb -n '\b(get\|post\|put\|delete\|patch)\s+[\x27"]/'` |
| Grape | `rg -trb -n 'class.+Grape::API\|(get\|post\|put\|delete)\s+[\x27"]'` |

### C# / .NET

| 框架 | 路由提取 |
|------|---------|
| ASP.NET Core MVC | `rg -tcs -n '\[Route\(\|\[HttpGet\|\[HttpPost\|\[HttpPut\|\[HttpDelete\]'` |
| Minimal API | `rg -tcs -n 'app\.Map(Get\|Post\|Put\|Delete)\('` |
| MVC Controllers | `rg -tcs -n 'public class \w+Controller\s*:\s*ControllerBase\|: Controller\b'` |

### Rust

| 框架 | 路由提取 |
|------|---------|
| actix-web | `rg -trs -n '#\[(get\|post\|put\|delete)\(\|HttpServer::new\|\.route\('` |
| Axum | `rg -trs -n 'Router::new\(\)\|\.route\(' --no-heading` |
| Rocket | `rg -trs -n '#\[(get\|post\|put\|delete)\(\|mount\(' --no-heading` |

## 3. 中间件 / 认证检查

各框架通用的认证关键字：

```bash
# 找到所有 use(middleware) / Use(...) / before_action 调用
rg -n '(app\.use\(|router\.Use\(|before_action|UseAuthentication|UseAuthorization|@UseGuards|requires_auth|RequireAuth|middleware!)' \
   --no-heading
```

LLM 应交叉对比"路由列表"和"中间件应用范围"——某些路由可能漏掉认证中间件，构成 Auth Bypass。

## 4. 参数绑定方式

| 框架 | 参数来源 | 典型代码 |
|------|---------|---------|
| Go Gin | `c.Query() / c.PostForm() / c.BindJSON()` | 配合 `binding:"required"` tag |
| Go Echo | `c.QueryParam() / c.FormValue() / c.Bind()` | |
| Go net/http | `r.URL.Query() / r.FormValue() / json.NewDecoder(r.Body).Decode()` | 无自动 binding |
| Express | `req.query / req.params / req.body`（body 需 body-parser）| |
| Fastify | `req.query / req.params / req.body`（自动 schema 验证可选） | |
| NestJS | `@Query() @Param() @Body()` 参数装饰器 | 配合 class-validator |
| Rails | `params[:key]`（strong_params 推荐） | |
| ASP.NET Core | `[FromQuery] [FromBody] [FromRoute]` | 模型绑定 |
| actix-web | `web::Query<T>` / `web::Json<T>` / `web::Path<T>` | |

## 5. 内置安全特性（用于反幻觉规则 5：宁可漏报不可误报）

LLM 在判定漏洞前必须确认目标框架是否已内置防护：

| 框架 | 内置防护（默认启用） |
|------|---------------------|
| Rails | CSRF Token（protect_from_forgery）/ ORM 参数化 / SafeBuffer XSS |
| NestJS | class-validator 自动验证 / 内置 CSP 守卫（配置后）|
| Django / Flask | （走 plugins/python，本插件不涉及） |
| ASP.NET Core | EF Core 参数化 / antiforgery token / IIS request filtering |
| Gin / Echo | **几乎无内置防护**——路径遍历/SSRF/CSRF 全靠开发者主动写 |
| Express | **几乎无内置防护**——同上 |

> 这是 Go 和裸 Node 项目漏洞密度高于 Rails/ASP.NET 的根本原因。Stage 1 多 Agent 静态审计在 Go/Express 项目上应预期更多发现。

## 6. 框架未识别时

如果上述探测全部 miss（自研框架 / 老框架 / 微服务网关），LLM 按以下顺序 fallback：

1. `rg -n 'route\|handler\|controller\|endpoint' -g '*.{go,js,ts,rb,cs,rs}' --no-heading | head -50` 找命名约定
2. Read 项目根 README / docs / 启动脚本（cmd/main.go、index.js、Program.cs）找 entry point
3. 从 entry point 顺源码追踪 router 初始化逻辑，反向找出所有路由注册点
4. 把所有找到的"接受 HTTP 请求且会读 body/query/params 的函数"全部列为 T1

如果连 entry point 都找不到 → 报告中标注 `x_framework = "unidentified"`，审计仍继续但 LLM 必须警告"框架识别失败可能漏报入口点"。
