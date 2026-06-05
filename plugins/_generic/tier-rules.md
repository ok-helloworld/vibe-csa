# Generic 启发式 Tier 分类

> 不依赖任何特定语言语法，靠路径/文件名/内容关键字三层匹配。准确度低于完整插件，但保证 EALOC 能算出来、入口点能枚举出来。

## 1. 文件扩展名 → 候选语言

按扩展名归类（仅用于"算 LOC"，不影响 Tier 分类）：

| 扩展名 | 语言 |
|--------|------|
| `.go` | Go |
| `.js` `.jsx` `.mjs` `.cjs` | JavaScript |
| `.ts` `.tsx` | TypeScript |
| `.rb` | Ruby |
| `.rs` | Rust |
| `.cs` | C# |
| `.kt` `.kts`（无 build.gradle.kts 父项目时） | Kotlin Native |
| `.scala` | Scala |
| `.swift` | Swift |
| `.dart` | Dart |
| `.c` `.cc` `.cpp` `.cxx` `.h` `.hpp` | C/C++ |
| `.lua` | Lua |
| `.pl` `.pm` | Perl |

可同时存在多语言；按 LOC 占比最高的语言决定 `audit.language[0]`。

## 2. T1（入口点）识别——三层匹配，命中任一即归 T1

### 层 A：路径关键字（最高优先级）

文件路径含以下任一目录/前缀关键字（不区分大小写）：

```
controllers/  controller/  handlers/  handler/  routes/  route/  routers/  router/
api/  apis/  endpoints/  endpoint/  resources/  views/  view/  pages/  page/
http/  rest/  graphql/  rpc/  grpc/  webhooks/  webhook/  middleware/  middlewares/
actions/  action/  app/  cmd/  bin/  main/
```

**注意**：路径含 `test/`、`tests/`、`__tests__/`、`spec/`、`fixtures/`、`testdata/`、`mock/` 一律 SKIP。

### 层 B：文件名后缀

文件名匹配以下后缀（不含路径，扩展名前的部分）：

```
*Controller*    *Handler*    *Route*    *Router*    *Endpoint*
*View*          *Page*       *Resource* *Api*       *Action*
*_handler.*     *_route.*    *_controller.*         *.handler.*
main.*          index.*      server.*   app.*       router.*
```

### 层 C：内容关键字（用 ripgrep 在文件首 100 行内匹配）

| 语言 | 关键字 |
|------|--------|
| Go | `func (.*) ServeHTTP`、`http.HandleFunc`、`gin.Default()`、`echo.New()`、`chi.NewRouter`、`fiber.New`、`mux.NewRouter`、`grpc.NewServer` |
| Node | `app.(get\|post\|put\|delete\|patch\|all)`、`router.(get\|post\|...)`、`@Controller`、`@Get\|@Post`、`fastify.register`、`Koa()` |
| C# | `\[ApiController\]`、`\[Route\(`、`\[HttpGet\]\|\[HttpPost\]`、`IEndpointRouteBuilder`、`endpoints.Map`、`app.MapControllers` |
| Ruby | `class .* < (ApplicationController\|ActionController)`、`Rails.application.routes.draw` |
| Rust | `actix_web::(get\|post)`、`#\[get\(\|post\(`、`Router::new\(\)`、`axum::Router`、`rocket::routes` |
| 通用 | `Authorization`、`request\.(headers\|body\|query\|params)` 在函数签名/参数中出现 |

> 命中层 A 直接 T1；只命中 B 或 C，需配合"文件含 HTTP/路由相关 import 或 use 语句"才确认 T1。

## 3. T2（业务逻辑）识别

层 A 路径关键字（不含 T1 的）：

```
services/  service/  business/  biz/  usecase/  usecases/  application/  app_service/
dao/  repository/  repositories/  repo/  store/  stores/  domain/  core/
manager/  managers/  workers/  worker/  tasks/  task/  jobs/  job/
processors/  processor/  consumers/  consumer/  producers/  producer/
```

文件名后缀：`*Service*`、`*Repository*`、`*Dao*`、`*Manager*`、`*Worker*`、`*Processor*`、`*Job*`、`*UseCase*`、`*Logic*`

内容关键字：含数据库操作（`db.`、`Query`、`Exec`、`Find`、`Save`、`Update`、`Delete`）或外部服务调用（`http.Get`、`fetch(`、`axios.`、`requests.`、`http.Client`）但不是 HTTP handler。

补充高优先级目录 / 文件名：`template/`、`templates/`、`view/`、`views/`、`resource/`、`resources/`、`loader/`、`plugin/`、`theme/`、`cache/`；以及 `*Template*`、`*View*`、`*Resource*`、`*Loader*`、`*Renderer*`、`*Plugin*`、`*Theme*`。这类文件即使不是入口，也常是配置驱动加载和二次消费链的关键传播层。

## 4. T3（数据结构 / DTO / Entity）识别

层 A 路径：

```
models/  model/  entities/  entity/  dto/  dtos/  schemas/  schema/
types/  type/  structs/  data/  pojo/  vo/  bean/  beans/
```

文件名后缀：`*Model*`、`*Entity*`、`*Dto*`、`*Schema*`、`*Type*`、`*Vo*`、`*Bean*`、`*Struct*`、`*Pojo*`

内容启发式：文件主要由结构体/类定义构成，函数实现少（行数 < 200 且函数 ≤ 3）。

## 5. SKIP 排除模式（强制）

以下路径**无论扩展名**全部 SKIP，不参与 EALOC 计算和审计：

```
**/test/**          **/tests/**         **/__tests__/**     **/spec/**
**/__mocks__/**     **/mock/**          **/mocks/**         **/fixtures/**
**/testdata/**      **/example/**       **/examples/**      **/demo/**
**/vendor/**        **/node_modules/**  **/dist/**          **/build/**
**/.next/**         **/.nuxt/**         **/coverage/**      **/target/**
**/bin/**（编译产物，非 cmd/bin）     **/obj/**            **/.git/**
**/migrations/**（可选：迁移脚本通常无运行时输入）
```

文件级 SKIP：`*_test.*`、`*.test.*`、`*.spec.*`、`*.mock.*`、`*.d.ts`、`*.min.js`、`*.bundle.js`

**例外**：`templates/`、`views/`、`resources/`、`plugin/`、`theme/`、`cache/`、`storage/`、`config/` 下会被模板、资源、模块、插件或脚本加载机制运行时消费的源码、模板、配置文件，不得仅因目录名直接 SKIP。

## 6. 项目包/模块识别

| 标识文件 | 项目类型 |
|---------|---------|
| `go.mod` | Go module，模块名取自 `module` 行 |
| `package.json` | Node 项目，模块名取自 `name` 字段 |
| `tsconfig.json` 配合 `package.json` | TypeScript 项目 |
| `Gemfile` `*.gemspec` | Ruby 项目 |
| `Cargo.toml` | Rust 项目 |
| `*.csproj` `*.sln` | C# / .NET 项目 |
| `pubspec.yaml` | Flutter / Dart 项目 |
| `Package.swift` | Swift 项目 |
| `CMakeLists.txt` `Makefile` `meson.build` | C/C++ 项目 |
| `mix.exs` | Elixir 项目 |

未识别时，仍可按 Tier A/B/C 启发式继续，记 `audit.repository = "<unknown>"`。

## 7. EALOC 权重

沿用核心默认：W1=1.0、W2=0.5、W3=0.1。

**校准建议**（generic 模式不自动调整，由 LLM 在 Stage 1 的代码度量说明中标注）：

- 微服务架构（多 cmd/main，文件极小）→ 提示考虑 W1=0.6
- Functional 风格（Go/Rust 中很多业务逻辑直接在 handler 里）→ 提示考虑合并 T1+T2
- 类型驱动设计（Rust/TS）→ T3 比例高但风险低，沿用 W3=0.1
