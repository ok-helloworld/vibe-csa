# Python 框架专项

## Django

### 路由提取
- `urls.py` 中 `urlpatterns` 列表定义路由映射
- `path('users/', views.user_list)` 或 `re_path(r'^api/', ...)`
- Class-Based Views：`path('users/', views.UserListView.as_view())`
- Django REST Framework：`DefaultRouter` 自动注册 ViewSet 路由

### 参数绑定
- `request.GET.get('param')` — URL 查询参数
- `request.POST.get('param')` — POST 表单参数
- `request.body` — 原始请求体
- `request.data` — DRF 解析后的请求数据（JSON/表单）
- 视图函数参数：`def view(request, id)` — URL 路径变量

### 安全机制
- CSRF 保护：`CsrfViewMiddleware` 默认启用
- Session 安全：`SESSION_COOKIE_HTTPONLY`、`SESSION_COOKIE_SECURE`
- ORM 参数化查询（默认安全，但 `raw()` 和 `extra()` 例外）
- XSS 防护：模板引擎默认转义
- Clickjacking 防护：`XFrameOptionsMiddleware`

### 常见风险
- `Model.objects.raw()` / `extra()` 中的原始 SQL 注入
- `@csrf_exempt` 禁用 CSRF 保护
- `DEBUG = True` 在生产环境暴露敏感信息
- `AdminSite` 未限制访问
- `ModelSerializer` 的 `fields = '__all__'` 暴露敏感字段
- `reverse()` / `redirect()` 用户可控 URL 导致开放重定向
- `__import__` 或 `importlib` 动态加载用户可控模块

### 路由提取命令
```bash
# 查找所有 URL 模式
rg 'path\(|re_path\(|url\(' --glob '*urls.py'
```

## Flask

### 路由提取
- `@app.route('/users')` 或 `@blueprint.route('/users')` 装饰器
- `methods=['GET', 'POST']` 指定 HTTP 方法
- URL 变量：`@app.route('/users/<int:id>')`

### 参数绑定
- `request.args.get('param')` — URL 查询参数
- `request.form.get('param')` — 表单参数
- `request.json` — JSON 请求体
- `request.get_json()` — JSON 请求体（同 `request.json`）
- `request.files['file']` — 上传文件

### 安全机制
- Flask 无内置 CSRF 保护，需 `Flask-WTF`
- Session 默认使用签名 Cookie（但未加密）
- Jinja2 模板默认转义

### 常见风险
- `render_template_string(user_input)` 导致 SSTI
- `session` 存储敏感信息（可被解码，仅签名未加密）
- `app.secret_key` 硬编码或弱密钥
- `send_file(user_input)` 导致路径遍历/任意文件读取
- 上传文件未验证文件类型
- 缺少 `@login_required` 的视图

## FastAPI

### 路由提取
- `@app.get('/users')` / `@app.post('/users')` 等装饰器
- `APIRouter` 子路由注册
- URL 路径参数：`@app.get('/users/{user_id}')`

### 参数绑定
- 路径参数：`async def get_user(user_id: int)`
- 查询参数：`async def search(q: str, page: int = 1)`
- 请求体：`async def create_user(user: UserCreate)`（Pydantic Model）
- Header：`async def read(x_token: str = Header(...))`
- Cookie：`async def read(session_id: str = Cookie(...))`
- 表单：`async def login(username: str = Form(), password: str = Form())`

### 安全机制
- Pydantic 自动输入验证（基于类型注解）
- OAuth2 密码流（`OAuth2PasswordBearer`）
- JWT Token（需自行实现）
- CORS 中间件（需显式配置）

### 常见风险
- `BackgroundTasks` 中执行用户可控命令
- `responses` 参数直接返回用户可控内容
- 依赖注入未验证权限
- Pydantic Model 的 `Config` 中 `extra = 'allow'` 导致批量分配
- SQLAlchemy `text()` 用户可控 SQL
- CORS 配置 `allow_origins=['*']`

## Celery

### 任务定义
- `@celery.task` 或 `@shared_task` 装饰器定义异步任务
- 任务通过 `task.delay()` 或 `task.apply_async()` 调用

### 常见风险
- 任务参数来自用户输入且未验证
- `subprocess` 在 Celery 任务中执行用户可控命令
- 反序列化任务参数（Pickle 序列化默认）
- 任务结果包含敏感信息

## SQLAlchemy

### ORM 查询
- `session.query(User).filter(User.id == user_id)` — 参数化（安全）
- `session.execute(text("SELECT ..."))` — 原始 SQL（需验证）
- `Model.query.filter_by()` — 参数化（安全）

### 常见风险
- `text(user_input)` 直接传入原始 SQL
- `connection.execute(user_input)`
- 用户可控的 `order_by`、`filter` 参数
