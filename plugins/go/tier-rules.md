# Go Tier 分类规则

## 文件扩展名

- `.go`：Go 源文件
- `.tmpl`、`.tpl`、`.gotmpl`、`.html`：被 Go 模板引擎消费时作为关联审计对象
- `.proto`：gRPC / protobuf 接口定义

## T1（入口点，权重 1.0）

直接接收 HTTP、RPC、消息或定时任务输入的代码。

### 路径和文件名

- `cmd/`、`api/`、`http/`、`handlers/`、`controllers/`、`routes/`、`router/`
- `grpc/`、`rpc/`、`graph/`、`resolver/`、`webhook/`、`middleware/`
- `main.go`、`server.go`、`router.go`、`routes.go`
- `*_handler.go`、`*_controller.go`、`*_resolver.go`、`*_server.go`

### 内容模式

- `func (... ) ServeHTTP(`
- `http.Handle`、`http.HandleFunc`、`ServeMux.Handle`
- Gin：`.GET/.POST/.PUT/.DELETE/.PATCH/.Any`
- Echo：`.GET/.POST/.PUT/.DELETE/.PATCH/.Any`
- Chi：`.Get/.Post/.Put/.Delete/.Route/.Mount`
- Fiber：`.Get/.Post/.Put/.Delete/.Patch/.All`
- Gorilla Mux：`.HandleFunc(...).Methods(...)`
- Beego：`beego.Router`、Controller 方法
- gRPC：`Register*Server`、实现生成的 `*Server` 接口
- GraphQL：resolver 方法
- 消息消费者、Webhook 和外部回调处理器

## T2（业务逻辑层，权重 0.5）

业务规则、数据访问、外部服务调用、后台任务和动态资源消费。

### 路径和文件名

- `service/`、`services/`、`usecase/`、`application/`、`domain/`
- `repository/`、`repo/`、`store/`、`dao/`
- `client/`、`clients/`、`gateway/`、`adapter/`、`integration/`
- `worker/`、`job/`、`task/`、`consumer/`、`producer/`
- `template/`、`templates/`、`plugin/`、`loader/`、`resource/`、`storage/`
- `*_service.go`、`*_usecase.go`、`*_repository.go`、`*_store.go`
- `*_client.go`、`*_worker.go`、`*_job.go`

### 内容模式

- `database/sql`、sqlx、GORM、ent、bun 数据访问
- `http.Client`、gRPC client、消息队列和对象存储调用
- `template.Parse*`、`ExecuteTemplate`、`plugin.Open`
- 文件写入、上传持久化、归档解压和资源加载
- 认证、授权、签名、token 和密码处理

## T3（数据结构层，权重 0.1）

主要由类型定义、DTO、数据库模型和配置结构组成，几乎不包含业务行为。

### 识别模式

- `model/`、`models/`、`entity/`、`entities/`、`dto/`、`schema/`、`types/`
- `*_model.go`、`*_entity.go`、`*_dto.go`、`*_request.go`、`*_response.go`
- 文件以 `struct`、常量、枚举和字段 tag 为主
- protobuf 源文件 `.proto` 可归 T3，但其中的敏感 RPC 定义需要回连到 T1 实现

## SKIP（不审计）

- `vendor/`
- Go module cache、构建产物和临时目录
- `testdata/`、`fixtures/`、`mocks/`、`mock/`
- `*_test.go`
- `*.pb.go`、`*_grpc.pb.go`、`*.gen.go`、`zz_generated.*.go`
- 文件头包含 `Code generated ... DO NOT EDIT.`

### 例外

- 生成的路由或 RPC glue code 用于枚举入口时可以读取，但不计入主要审计覆盖
- `testdata/` 中若包含生产时会加载的模板、策略或配置，不得直接 SKIP
- `vendor/` 中被项目修改或 fork 的安全关键代码应单独标记审计

## 优先级冲突

1. 命中 SKIP 且无例外时直接 SKIP
2. 同时命中 T1 和 T2 时归 T1
3. 含外部输入处理、动态加载或安全控制的文件不得归 T3
4. `main.go` 若仅做依赖装配可归 T2；若注册路由、middleware 或 gRPC 服务则归 T1

## 项目模块识别

优先读取：

1. `go.work` 的 `use` 列表，识别多模块仓库
2. 各 `go.mod` 的 `module` 行
3. `go list -m -json` 可用时用于补充模块信息

项目模块前缀下的 import 视为内部代码。标准库、第三方 module 和 `vendor/` 默认不计入 EALOC。

## EALOC 校准

默认权重：T1=1.0、T2=0.5、T3=0.1。

- 薄 handler + 厚 service：沿用默认权重
- 大量业务逻辑直接写在 handler：T1 已按 1.0 计入，无需重复
- protobuf / ORM 生成代码：SKIP
- 多个 `cmd/*` 共享内部包：按文件只计一次，不按二进制入口重复计算
