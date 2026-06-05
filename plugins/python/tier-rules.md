# Python Tier 分类规则

## 文件扩展名

- `.py` — Python 源文件

## Tier 分类

### T1（入口点，权重 1.0）

路由处理器、视图函数、API 端点 —— 直接处理 HTTP 请求的函数/类。

**Django**:
- `urls.py` 中注册的视图函数/类
- 文件名包含 `views.py`
- 包含 `@api_view`、`APIView`、`ViewSet`、`@view`
- `urlpatterns` 中引用的函数

**Flask**:
- 包含 `@app.route`、`@blueprint.route` 的函数
- 文件名包含 `views.py`、`routes.py`

**FastAPI**:
- 包含 `@app.get`、`@app.post`、`@router.get` 等装饰器的函数
- 文件名包含 `routers/`、`routes/`、`endpoints/`

**通用**:
- 文件路径包含 `views/`、`controllers/`、`routes/`、`endpoints/`、`api/`
- 文件名包含 `handler`、`endpoint`、`controller`

### T2（业务逻辑层，权重 0.5）

Models、Services、Utils、Forms、Serializers —— 处理业务逻辑和数据访问的模块。

**识别模式**:
- 文件名包含 `models.py`、`services.py`、`utils.py`、`helpers.py`、`forms.py`、`serializers.py`、`validators.py`、`middlewares.py`
- 文件路径包含 `models/`、`services/`、`utils/`、`helpers/`、`forms/`、`serializers/`、`middleware/`
- Django Model 类（继承 `models.Model`）
- SQLAlchemy Model 类（继承 `db.Model` 或 `Base`）
- Pydantic Model 类（继承 `BaseModel`）
- Celery 任务（`@celery.task`、`@shared_task`）
- 文件路径包含 `template/`、`templates/`、`loader/`、`plugin/`、`resource/`、`instance/`、`storage/`
- 文件名包含 `Template`、`Loader`、`Plugin`、`Resource`、`Renderer`
- 模板加载器、动态导入器、资源读取器、插件注册器相关模块

### T3（数据结构层，权重 0.1）

Schemas、Entities、Config —— 纯数据传输对象和配置。

**识别模式**:
- 文件名包含 `schemas.py`、`entities.py`、`config.py`、`settings.py`、`constants.py`
- 文件路径包含 `schemas/`、`entities/`、`config/`
- 仅包含字段声明和数据类定义（`dataclass`、`TypedDict`、`NamedTuple`）
- Pydantic Schema 类（仅字段定义，无业务逻辑）

### SKIP（不审计）

第三方库、虚拟环境、生成代码、测试代码。

**排除模式**:
- 文件路径包含 `venv/`、`.venv/`、`env/`、`.env/`、`site-packages/`、`dist-packages/`、`test/`、`tests/`、`__pycache__/`、`migrations/`、`alembic/`
- 文件名包含 `test_`、`_test.py`、`conftest.py`
- `setup.py`、`manage.py`、`wsgi.py`、`asgi.py`（框架入口文件，仅检查配置项）
- 第三方库（通过 `import` 语句判断，非项目包）

**例外**:
- `templates/`、`config/`、`instance/`、`storage/`、`plugin/` 下会被模板引擎、动态导入、资源读取或插件机制运行时消费的 `.py`、`.html`、`.jinja`、`.j2`、`.yaml`、`.yml`、`.json` 文件，至少归入 T2，不得直接 SKIP

## 项目包名识别

通过 `setup.py` 的 `name`、`pyproject.toml` 的 `[project]` 段或目录结构推断项目根目录。在根目录下的 `.py` 文件视为项目代码。
