# 安全检查矩阵

常见安全控制及其绕过方式的参考矩阵。控制驱动审计时用于判断"防护是否充分"，Sink 驱动审计时用于判断"是否有安全网"。

## 认证控制

| 控制 | 实现方式 | 绕过方式 | 检查点 |
|------|----------|----------|--------|
| Spring Security | `@PreAuthorize`, `http.authorizeRequests()` | 端点未配置安全规则、白名单路径、Actuator 暴露 | 检查 SecurityConfig 是否覆盖所有端点 |
| Django 认证 | `@login_required`, `LoginRequiredMiddleware` | 视图无装饰器、`login_url=None` 跳过 | 检查所有 view 是否都有认证装饰器 |
| Laravel 中间件 | `auth`, `auth:api` 中间件 | 路由未应用中间件组、中间件条件分支 | 检查 RouteServiceProvider 中间件配置 |
| JWT Token | 自定义过滤器验证 Token | 过滤器未注册、路径排除列表、Token 签名验证缺失 | 检查过滤器注册和排除路径 |
| Session 认证 | Cookie + Session 存储 | `session_regenerate_id()` 缺失（固定攻击） | 检查登录后是否重新生成 Session ID |

## 授权控制

| 控制 | 实现方式 | 绕过方式 | 检查点 |
|------|----------|----------|--------|
| 角色检查 | `@Secured("ROLE_ADMIN")`, `hasRole()` | 方法级注解缺失、类级注解被方法覆盖 | 检查每个端点是否有角色注解 |
| 所有权验证 | `WHERE user_id = currentUser.id` | 使用用户可控的 user_id、查询条件被覆盖 | 检查 SQL 中的 user_id 是否来自可信来源 |
| ABAC/RBAC | 自定义权限检查函数 | 检查函数被注释掉、提前 return 跳过检查 | 检查权限检查是否在业务逻辑之前执行 |
| 数据权限 | 行级/列级访问控制 | 查询绕过、批量操作跳过单条检查 | 检查批量操作是否有数据权限过滤 |

## 输入验证

| 控制 | 实现方式 | 绕过方式 | 检查点 |
|------|----------|----------|--------|
| 参数化查询 | PreparedStatement, ORM 参数绑定 | `${}` MyBatis、`.raw()` Django、字符串拼接 | 检查 SQL 构造是否有任何字符串拼接 |
| Bean Validation | `@Valid`, `@NotNull`, `@Size` | `BindingResult` 未检查、`@Validated` 缺失 | 检查 Controller 是否处理了验证结果 |
| Pydantic Model | FastAPI 自动验证 | `Any` 类型、未定义长度限制 | 检查 Model 字段类型约束 |
| Laravel Validation | `$request->validate()` | 验证后未使用验证后的数据、使用原始 `$_POST` | 检查是否使用了 `$request->validated()` |
| 白名单验证 | 枚举值匹配、正则校验 | 正则不完整（如未锚定 `^$`）、枚举值包含危险项 | 检查正则是否完全匹配、枚举是否安全 |

## 输出编码

| 控制 | 实现方式 | 绕过方式 | 检查点 |
|------|----------|----------|--------|
| Thymeleaf | `th:text`（默认转义） | 使用 `th:utext`（不转义） | 检查是否使用了 `utext` |
| Jinja2 | `{{ var }}`（默认转义） | 使用 `{{ var|safe }}`、`{% autoescape false %}` | 检查是否有 safe 过滤器或 autoescape 关闭 |
| Blade | `{{ $var }}`（默认转义） | 使用 `{!! $var !!}`（不转义） | 检查是否有未转义输出 |
| Django 模板 | `{{ var }}`（默认转义） | 使用 `{{ var|safe }}`、`{% autoescape off %}` | 检查 safe 标签和 autoescape 设置 |
| 手动编码 | `HtmlUtils.htmlEscape()`, `htmlspecialchars()` | 编码函数未覆盖所有输出点、编码后再次拼接 | 检查所有输出点是否都经过编码 |

## CSRF 防护

| 控制 | 实现方式 | 绕过方式 | 检查点 |
|------|----------|----------|--------|
| Spring CSRF | `CsrfFilter`, `@CsrfValid` | GET 请求未检查、`csrf().disable()` | 检查 SecurityConfig 是否禁用了 CSRF |
| Django CSRF | `CsrfViewMiddleware`, `{% csrf_token %}` | `@csrf_exempt` 装饰器、`CSRF_USE_SESSIONS = False` | 检查豁免装饰器使用 |
| Laravel CSRF | `VerifyCsrfToken` 中间件、`@csrf` | 路由在 `$except` 列表中、中间件未注册 | 检查 VerifyCsrfToken 排除列表 |
| Token 验证 | 自定义 CSRF Token | Token 可预测、Token 不绑定 Session、Token 复用 | 检查 Token 生成和验证逻辑 |

## SSRF 防护

| 控制 | 实现方式 | 绕过方式 | 检查点 |
|------|----------|----------|--------|
| URL 白名单 | 只允许预定义域名 | 子域名绕过（evil.example.com）、DNS rebinding | 检查白名单是否精确匹配、是否检查了完整 URL |
| URL 黑名单 | 禁止内网 IP（10.0.0.0/8, 192.168.0.0/16） | IPv6 绕过（::1）、八进制/十六进制 IP、302 重定向 | 检查是否在请求发出前和发出后都做了验证 |
| DNS 解析验证 | 先解析 IP 再判断 | DNS rebinding（TTL 过期后 IP 变化） | 检查是否在连接时实时验证 IP |
| 网络隔离 | 内网服务不出公网 | 云实例 metadata 服务（169.254.169.254） | 检查 metadata 访问是否被阻止 |

## 文件上传防护

| 控制 | 实现方式 | 绕过方式 | 检查点 |
|------|----------|----------|--------|
| 扩展名白名单 | 只允许 .jpg/.png/.pdf | 双扩展名（shell.php.jpg）、大小写绕过（.PhP） | 检查白名单是否严格、是否处理了大小写 |
| MIME 类型检查 | `Content-Type` 验证 | 伪造 Content-Type 头 | 检查是否仅依赖 HTTP 头，还是检查了文件内容 |
| 文件头检查 | 魔数（Magic Number）验证 | 文件头 + 恶意代码拼接（图片 EXIF） | 检查是否仅验证了文件头，还是检查了整个文件 |
| 保存路径 | 随机文件名 + 非 Web 目录 | 覆盖已有文件、路径遍历 | 检查文件名是否随机、路径是否可控 |
| 文件大小限制 | `maxFileSize` 配置 | 分块上传、压缩炸弹 | 检查是否有大小限制和压缩解压限制 |

## 加密安全

| 控制 | 实现方式 | 绕过方式 | 检查点 |
|------|----------|----------|--------|
| 密码哈希 | bcrypt, argon2, PBKDF2 | MD5/SHA-1 直接哈希、无 salt | 检查哈希算法和 salt 使用 |
| 对称加密 | AES-GCM, AES-CBC | ECB 模式、硬编码密钥/IV | 检查加密模式和密钥管理 |
| 随机数 | SecureRandom, secrets | `random.Random()`, `Math.random()` | 检查随机数生成器类型 |
| 密钥管理 | KMS, 环境变量 | 硬编码在代码/配置中、提交到版本库 | 检查密钥来源 |

## 反序列化防护

| 控制 | 实现方式 | 绕过方式 | 检查点 |
|------|----------|----------|--------|
| Java ObjectInputFilter | `ObjectInputFilter.allowFilter()` | 过滤规则不完整、未应用到所有流 | 检查过滤器是否覆盖所有反序列化入口 |
| PHP allowed_classes | `unserialize($data, ["allowed_classes" => false])` | 未设置 allowed_classes、允许了危险类 | 检查 allowed_classes 配置 |
| Python pickle 替代 | json, msgpack | 仍然使用 pickle 处理不可信数据 | 检查是否有 pickle 用于网络数据 |
| 签名验证 | HMAC 签名验证数据完整性 | 密钥泄露、签名算法降级（HMAC→MD5） | 检查签名验证流程 |
