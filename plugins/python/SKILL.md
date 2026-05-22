---
name: vibe-csa-python
description: Python 代码审计插件。支持 Django, Flask, FastAPI, Celery 框架。包含分层规则、危险模式、Semgrep 规则。
---

# Python 审计插件

## 语言检测

项目包含以下任一特征时识别为 Python：
- 存在 `.py` 文件
- 存在 `requirements.txt`、`Pipfile`、`pyproject.toml`
- 存在 `manage.py`（Django）或 `app.py`/`main.py`（Flask/FastAPI）

## 分层规则

加载 `tier-rules.md` 进行文件分类：
- **T1**: Views/Routes/Handlers/API Endpoints（入口点）
- **T2**: Models/Services/Utils/Forms/Serializers/Middleware（业务逻辑）
- **T3**: Schemas/Entities/Config（数据结构）
- **SKIP**: venv、site-packages、tests、migrations、__pycache__

## Layer 1 预扫描

### P0（Critical）危险模式

| 模式 | 漏洞类型 |
|------|----------|
| `eval\(` | 代码执行 |
| `exec\(` | 代码执行 |
| `os\.system\(` | 命令执行 |
| `os\.popen\(` | 命令执行 |
| `subprocess.*shell=True` | 命令执行 |
| `__import__\(` | 动态导入 RCE |
| `importlib\.import_module` | 动态导入 RCE |
| `render_template_string` | SSTI |
| `Template\(.*\)\.render` | Jinja2 SSTI |
| `pickle\.loads?` | 反序列化 |
| `yaml\.load\(` | YAML 反序列化 |
| `marshal\.loads?` | 反序列化 |

### P1（High）危险模式

| 模式 | 漏洞类型 |
|------|----------|
| `execute\(f"` | SQL 注入 |
| `execute\(.*\+` | SQL 注入 |
| `execute\(.*%` | SQL 注入 |
| `execute\(.*\.format` | SQL 注入 |
| `\.objects\.raw\(` | Django ORM 原始 SQL |
| `session\.execute` | SQLAlchemy SQL |
| `requests\.(get\|post\|put\|delete)` | SSRF |
| `urllib.*urlopen` | SSRF |
| `httpx\.` | SSRF |
| `open\(` | 文件操作/路径遍历 |
| `Path\(.*\)\.(read\|write)` | 文件操作 |
| `shutil\.(copy\|move)` | 文件操作 |
| `os\.path\.join` | 路径遍历 |
| `ElementTree\.parse` | XXE |
| `lxml\.etree\.parse` | XXE |

### P2（Medium）危险模式

| 模式 | 漏洞类型 |
|------|----------|
| `hashlib\.(md5\|sha1)` | 弱哈希 |
| `DES\|ECB` | 弱加密 |
| `SECRET_KEY\s*=` | 硬编码密钥 |
| `random\.` (安全场景) | 不安全随机数 |
| `redirect\(` | 开放重定向 |
| `HttpResponseRedirect` | 开放重定向 |
| `Markup\(` | XSS |
| `\|safe` (Jinja2) | XSS |
| `@csrf_exempt` | CSRF 禁用 |
| `DEBUG\s*=\s*True` | 调试模式暴露 |
| `ALLOWED_HOSTS.*\*` | 允许所有主机 |

## 框架专项

加载 `frameworks.md` 获取框架专属审计指南：
- Django（路由、ORM、CSRF、Admin、DRF）
- Flask（路由、Jinja2 SSTI、Session、文件上传）
- FastAPI（路由、Pydantic 验证、依赖注入、CORS）
- Celery（异步任务、反序列化）
- SQLAlchemy（ORM、原始 SQL）

## Semgrep 规则

加载 `semgrep/` 目录下的所有 YAML 规则：
- `python-rce.yaml` — eval/exec/subprocess/模板注入
- `python-sqli.yaml` — 原始 SQL 拼接、Django raw/extra
- `python-ssrf.yaml` — requests/urllib/httpx SSRF
- `python-file.yaml` — open/pathlib/shutil 文件操作
- `python-deser.yaml` — pickle/yaml/marshal 反序列化
- `python-crypto.yaml` — MD5/DES/ECB/硬编码密钥
- `python-config.yaml` — DEBUG/ALLOWED_HOSTS/SECRET_KEY/CORS
- `python-misc.yaml` — XXE/XSS/开放重定向/认证

## 双轨审计

### Sink 驱动
从 `sinks.md` 中的危险函数出发，向上追溯参数来源。Python 特有的动态类型使得追踪更具挑战性——需要追踪变量赋值、函数返回值、类属性传递。

### 控制驱动
从 T1 View/Route 出发，向下追踪安全控制：
1. 是否有认证装饰器/中间件（`@login_required`、`@permission_classes`）
2. 是否有输入验证（Pydantic Model、Django Form、手动校验）
3. 是否有输出编码（Jinja2 默认转义、Django 模板默认转义）
4. 是否有 CSRF 保护

## 漏洞编号规则

```
{C/H/M/L}-{TYPE}-{SEQ}
```
- TYPE: SQL=SQL注入, RCE=远程代码执行, SSRF=SSRF, FILE=文件操作, XXE=XXE, AUTH=认证绕过, XSS=XSS, DESER=反序列化, SSTI=SSTI, CRYPTO=加密弱点, REDIR=开放重定向, CSRF=CSRF, CONFIG=配置问题

## 输出格式

所有发现写入 `{output_path}/findings-raw.md`，每条包含：
- 漏洞编号
- 类型
- 严重程度
- 位置（file:line）
- 简要描述
- 危险函数/模式
- Track 来源（Sink 驱动 / 控制驱动）

## 能力基线检查

以下 22 项是 Python 项目审计的最低能力基线。每项必须在审计过程中被验证（PASS/FAIL/SKIP），确保无盲区：

### 反序列化检测
- [ ] `pickle.loads()` / `pickle.load()` 用户输入
- [ ] `yaml.load()` 非 SafeLoader
- [ ] `marshal.loads()` 用户输入
- [ ] `shelve` 用户可控路径
- [ ] `jsonpickle.decode()` 用户输入

### RCE 检测
- [ ] `eval()` 用户输入
- [ ] `exec()` 用户输入
- [ ] `os.system()` 用户可控参数
- [ ] `os.popen()` 用户可控参数
- [ ] `subprocess.*` 中 `shell=True` + 用户输入
- [ ] `__import__()` / `importlib.import_module()` 用户可控

### SSTI 检测
- [ ] `render_template_string()` 用户输入
- [ ] Jinja2 `Template()` 渲染用户输入

### SQL 注入检测
- [ ] 字符串拼接/f-string/% 格式化 `.execute()`
- [ ] Django ORM `.raw()` 无参数
- [ ] SQLAlchemy `text()` / `.execute()` 字符串

### SSRF 检测
- [ ] `requests.get/post/put/delete` 用户可控 URL
- [ ] `urllib.urlopen` / `urllib.request` 用户可控
- [ ] `httpx.get/post` 用户可控
- [ ] `aiohttp` 用户可控 URL

### 文件安全
- [ ] `open()` 用户可控路径
- [ ] `Path` read/write 用户可控
- [ ] `shutil.copy/move` 用户可控
- [ ] 文件上传无类型/大小校验

### XXE 检测
- [ ] `xml.etree.ElementTree.parse()` 用户输入
- [ ] `lxml.etree.parse()` 无禁止 DTD

### XSS 检测
- [ ] `Markup()` 用户输入
- [ ] Jinja2 `|safe` 过滤器
- [ ] `HttpResponse` 直接输出用户输入

### 加密/配置
- [ ] `hashlib.md5/sha1` 用于密码
- [ ] DES/ECB 加密
- [ ] `random.*` 用于安全场景（应用 `secrets`）
- [ ] Django `DEBUG = True` 生产环境
- [ ] Django `SECRET_KEY` 硬编码
- [ ] Django `ALLOWED_HOSTS = ['*']`
- [ ] `@csrf_exempt` 装饰器
