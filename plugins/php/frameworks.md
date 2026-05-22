# PHP 框架专项

## Laravel

### 路由提取
- `routes/web.php` 和 `routes/api.php` 中定义路由
- `Route::get('/users', [UserController::class, 'index'])`
- `Route::resource('users', UserController::class)` 自动注册 RESTful 路由
- 路由组：`Route::middleware('auth')->group(function () { ... })`

### 参数绑定
- 路由参数：`Route::get('/users/{id}', ...)` → `function show($id)`
- 请求输入：`$request->input('name')`、`$request->get('name')`
- JSON 请求体：`$request->json('field')`、`$request->all()`
- 验证：`$request->validate([...])`

### 安全机制
- CSRF 保护：`web` 中间件组默认启用 `VerifyCsrfToken`
- 认证：`auth` 中间件、`Auth::user()`、`Gate`、`Policy`
- 授权：`@can` Blade 指令、`$this->authorize()`
- ORM：Eloquent 参数化查询（默认安全，但 `DB::raw()` 例外）
- XSS 防护：Blade `{{ $var }}` 默认转义

### 常见风险
- `DB::raw($user_input)` SQL 注入
- `whereRaw()` / `orderByRaw()` / `havingRaw()` 用户可控
- Blade `!!$var !!` 不转义输出（等同于 `{!! !!}`）
- `eval()` / `assert()` 动态代码执行
- 文件上传未验证 MIME 类型
- `Storage::put($user_path, ...)` 路径遍历
- `redirect($user_url)` 开放重定向
- `unserialize()` 反序列化漏洞
- `Log::info($user_input)` 日志注入

### 路由提取命令
```bash
# 查找所有路由定义
rg 'Route::(get|post|put|delete|patch|resource|any)' routes/
```

## Symfony

### 路由提取
- 注解路由：`#[Route('/users', name: 'users_list')]` 在 Controller 方法上
- XML/YAML 路由配置：`config/routes.yaml`
- `@Route` (旧版注解) 或 `#[Route]` (PHP 8 属性)

### 参数绑定
- 路由参数：`public function show(Request $request, $id)`
- 请求输入：`$request->query->get('param')`、`$request->request->get('param')`
- JSON 请求体：`$request->getContent('json')`
- 表单：`$form = $this->createForm()` + `$form->handleRequest($request)`

### 安全机制
- Symfony Security：`#[IsGranted]`、`$this->denyAccessUnlessGranted()`
- CSRF：表单自动添加 CSRF token
- ORM：Doctrine 参数化查询（默认安全）
- XSS 防护：Twig `{{ var }}` 默认转义

### 常见风险
- Doctrine `createQuery($dql)` 字符串拼接
- `exec()` / `passthru()` 命令注入
- `file_get_contents($user_url)` SSRF
- 上传文件未验证
- `unserialize()` 反序列化
- Twig `{{ var|raw }}` 不转义输出

## ThinkPHP

### 路由提取
- `route/route.php` 或 `app/route.php` 中定义
- `\think\Route::get('/users', 'UserController/index')`
- 注解路由：`@Route(rule="/users")` 在 Controller 方法上

### 参数绑定
- 路由参数：`public function show($id)`
- 请求输入：`$this->request->param('name')`、`$this->request->get('name')`
- `$this->request->post()` — POST 数据

### 常见风险
- `query($sql)` / `execute($sql)` 原始 SQL 注入
- `find($id)` 中 `$id` 未验证类型
- `import()` 动态包含用户可控文件
- `unserialize()` 反序列化
- 文件上传未验证

## WordPress

### 路由提取
- `add_action('init', 'callback')` — 初始化钩子
- `add_action('wp_ajax_{action}', 'callback')` — AJAX 端点
- `add_action('rest_api_init', ...)` — REST API 端点
- `add_rewrite_rule()` — 自定义路由

### 参数绑定
- `$_GET['param']`、`$_POST['param']` — 原始参数
- `get_query_var('param')` — 查询变量
- `get_post_meta()` / `update_post_meta()` — 元数据

### 安全机制
- `$wpdb->prepare($sql, $params)` — 参数化查询
- `wp_verify_nonce()` — CSRF/Intent 验证
- `current_user_can($capability)` — 权限检查
- `sanitize_text_field()` / `esc_html()` — 输出转义

### 常见风险
- `$wpdb->query($sql)` 未使用 `prepare()`
- 缺少 `current_user_can()` 权限检查
- 缺少 `wp_verify_nonce()` CSRF 验证
- `echo $user_input` 未转义
- `unserialize()` 反序列化（如 `maybe_unserialize()`）
- `include $user_path` 文件包含

## CodeIgniter

### 路由提取
- `app/Config/Routes.php` 中定义
- `$routes->get('/users', 'UserController::index')`

### 参数绑定
- 路由参数：`public function show($id)`
- 请求输入：`$this->request->getGet('param')`、`$this->request->getPost('param')`

### 常见风险
- `$db->query($sql)` 原始 SQL 注入
- `eval()` / `assert()` 代码执行
- 文件上传未验证
- `unserialize()` 反序列化

## Yii2

### 路由提取
- URL 规则：`config/web.php` 中 `urlManager` 配置
- Controller Action：`public function actionIndex()` → `/site/index`

### 参数绑定
- 请求输入：`Yii::$app->request->get('param')`、`Yii::$app->request->post('param')`
- 模型加载：`$model->load(Yii::$app->request->post())`

### 常见风险
- `createCommand($sql)` 字符串拼接
- `Query::where($condition)` 用户可控条件
- `unserialize()` 反序列化
- 文件上传未验证
