# Java 框架专项

## Spring MVC / Spring Boot

### 路由提取
- 注解驱动：`@Controller` + `@RequestMapping` / `@GetMapping` / `@PostMapping` 等
- 类级别 `@RequestMapping("/api")` + 方法级别 `@GetMapping("/users")` → 完整路径 `/api/users`
- `@RestController` 等同于 `@Controller` + `@ResponseBody`

### 参数绑定
- `@RequestParam` — URL 查询参数
- `@PathVariable` — URL 路径变量
- `@RequestBody` — JSON/XML 请求体（自动反序列化）
- `@ModelAttribute` — 表单数据绑定到对象
- `HttpServletRequest.getParameter()` — 原始参数访问

### 安全机制
- Spring Security：`@PreAuthorize`、`@Secured`、`http.authorizeRequests()` 配置
- CSRF 保护：默认启用（但 REST API 通常禁用）
- CORS 配置：`@CrossOrigin`、`WebMvcConfigurer.addCorsMappings()`

### 常见风险
- MyBatis `${}` vs `#{}` 混淆（`${}` 直接拼接，`#{}` 参数化）
- `@InitBinder` 批量分配漏洞（允许设置任意字段）
- Spring Boot Actuator 端点暴露（`/env`、`/heapdump`、`/configprops`）
- `spring.config.import` 配置注入
- SpEL 注入：`@Value("#{...}")` 用户可控

### 路由提取命令
```bash
# 查找所有 @RequestMapping 及其变体
rg '@(Get|Post|Put|Delete|Patch|Request)Mapping' --glob '*.java'
```

## Struts2

### 路由提取
- `struts.xml` 中的 `<action>` 标签定义
- 注解驱动：`@Action`、`@Namespace`、`@ParentPackage`
- URL 模式：`/{namespace}/{actionName}.action`

### 参数绑定
- Action 类中的 public getter/setter 自动绑定请求参数
- `ModelDriven<T>` 接口实现
- `@RequestParam` 注解

### 安全机制
- OGNL 表达式引擎（也是风险源）
- Interceptor 链（认证、验证、文件上传）
- `struts.xml` 中的 `<interceptor-ref>` 配置

### 常见风险
- OGNL 表达式注入（CVE-2017-5638 等）
- 文件上传拦截器配置不当
- Action 类中缺少权限检查
- 通配符 action 映射导致未授权访问

## Jersey (JAX-RS)

### 路由提取
- `@Path("/api")` 类级别 + `@Path("/users")` 方法级别
- `@GET`、`@POST`、`@PUT`、`@DELETE` HTTP 方法注解
- `@Produces` / `@Consumes` 媒体类型

### 参数绑定
- `@PathParam` — URL 路径变量
- `@QueryParam` — URL 查询参数
- `@FormParam` — 表单参数
- `@HeaderParam` — HTTP Header
- `@CookieParam` — Cookie

### 常见风险
- 缺少 `@RolesAllowed` 的敏感端点
- `@Context UriInfo` 构造 SSRF URL
- JAXB 反序列化漏洞

## Dubbo

### 路由提取
- `@DubboService` / `@Service` 注解定义服务
- `@DubboReference` / `@Reference` 注解引用服务
- XML 配置：`<dubbo:service>` / `<dubbo:reference>`

### 常见风险
- Dubbo 反序列化（Hessian/Java 序列化）
- 未启用认证的服务暴露
- 泛化调用（GenericService）导致的 RCE

## gRPC

### 路由提取
- `.proto` 文件中定义 `service` 和 `rpc` 方法
- Java 实现类继承 `{Service}ImplBase`

### 常见风险
- gRPC 服务未启用 TLS
- 消息反序列化漏洞
- 缺少认证拦截器

## Play Framework

### 路由提取
- `conf/routes` 文件定义路由映射
- 注解路由：`@Path`、`@Get`、`@Post` 等

### 常见风险
- Twirl 模板注入
- 路由文件中的参数绑定
- 缺少 SecurityAction 的端点
