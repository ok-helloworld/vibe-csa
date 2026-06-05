# Java/Kotlin Tier 分类规则

## 文件扩展名

- `.java` — Java 源文件
- `.kt` / `.kts` — Kotlin 源文件

## Tier 分类

### T1（入口点，权重 1.0）

控制器、过滤器、拦截器、Servlet、Action —— 直接处理 HTTP 请求的类。

**识别模式**：
- 包含 `@Controller`、`@RestController`、`@RequestMapping` 及其变体（`@GetMapping` 等）
- 实现 `javax.servlet.Filter`、`org.springframework.web.servlet.HandlerInterceptor`
- 继承 `javax.servlet.http.HttpServlet`
- 包含 `@Action`（Struts2）、`@Path`（JAX-RS/Jersey）
- 文件路径包含 `controller/`、`action/`、`servlet/`、`filter/`、`interceptor/`、`handler/`、`resource/`
- 文件名包含 `Controller`、`Action`、`Servlet`、`Filter`、`Interceptor`、`Handler`、`Resource`、`Endpoint`

### T2（业务逻辑层，权重 0.5）

Service、DAO、Repository、Manager、Utils、Config —— 处理业务逻辑和数据访问的类。

**识别模式**：
- 包含 `@Service`、`@Repository`、`@Component`
- 文件名包含 `Service`、`Dao`、`Repository`、`Mapper`、`Manager`、`Util`、`Helper`、`Config`
- 文件路径包含 `service/`、`dao/`、`repository/`、`mapper/`、`util/`、`helper/`、`config/`
- 包含 `@Configuration`、`@Bean`（Spring 配置类）
- MyBatis XML Mapper 文件（`*Mapper.xml`）
- 文件路径包含 `template/`、`templates/`、`view/`、`views/`、`resource/`、`resources/`、`loader/`、`resolver/`、`plugin/`
- 文件名包含 `Template`、`View`、`Resource`、`Loader`、`Resolver`、`Renderer`、`Plugin`
- 视图解析器、资源加载器、配置绑定器、动态 Bean 分发器相关类

### T3（数据结构层，权重 0.1）

Entity、VO、DTO、Model —— 纯数据传输对象。

**识别模式**：
- 文件名包含 `Entity`、`VO`、`DTO`、`Model`、`Bean`、`Form`、`Request`、`Response`
- 文件路径包含 `entity/`、`model/`、`dto/`、`vo/`、`bean/`、`form/`
- 仅包含字段声明和 getter/setter，无业务逻辑
- 包含 `@Entity`、`@Table`（JPA 实体）

### SKIP（不审计）

第三方库、生成代码、测试代码。

**排除模式**：
- 文件路径包含 `test/`、`tests/`、`target/`、`build/`、`.gradle/`、`node_modules/`
- 文件名包含 `Test`、`Tests`（单元测试）
- 第三方库源码（如 `org/springframework/`、`com/google/` 等包名前缀不在项目包名范围内）
- 生成代码（如 `generated/`、`protobuf/`、`graphql/` 生成文件）

**例外**：
- `templates/`、`resources/`、`mapper/`、`views/`、`plugin/` 下会被运行时模板、视图、资源、Bean、路由机制消费的 `.xml`、`.jsp`、`.ftl`、`.vm`、`.html`、`.yml`、`.yaml`、`.properties` 文件，至少归入 T2，不得直接 SKIP

## 项目包名识别

通过 `pom.xml` 的 `<groupId>` 或 `build.gradle` 的 `group` 字段识别项目包名。不在项目包名范围内的类文件标记为 SKIP。
