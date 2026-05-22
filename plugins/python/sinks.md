# Python 危险函数目录（Sinks）

按漏洞类型分类。每条包含：函数签名、风险等级、grep 搜索模式、对应的 Semgrep 规则类别。

## RCE（远程代码执行）

### 代码执行
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `eval(user_input)` | Critical | `eval\(` | python-rce.yaml |
| `exec(user_input)` | Critical | `exec\(` | python-rce.yaml |
| `exec(user_input, globals(), locals())` | Critical | `exec\(` | python-rce.yaml |
| `compile(user_input, ...)` + `exec()` | Critical | `compile\(` | python-rce.yaml |
| `os.system(user_input)` | Critical | `os\.system\(` | python-rce.yaml |
| `os.popen(user_input)` | Critical | `os\.popen\(` | python-rce.yaml |
| `subprocess.call/sh.run/Popen(shell=True)` | Critical | `subprocess.*shell=True` | python-rce.yaml |
| `subprocess.call/sh.run/Popen(shell=False, args=用户拼接)` | Critical | `subprocess\.` | python-rce.yaml |
| `__import__(user_input)` | Critical | `__import__\(` | python-rce.yaml |
| `importlib.import_module(user_input)` | Critical | `importlib\.import_module` | python-rce.yaml |

### SSTI（服务端模板注入）
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `render_template_string(user_input)` (Flask/Jinja2) | Critical | `render_template_string` | python-rce.yaml |
| `Template(user_input).render()` (Jinja2) | Critical | `Template\(.*\)\.render` | python-rce.yaml |
| `render_to_string` 用户可控模板 (Django) | Critical | `render_to_string` | python-rce.yaml |

### 反序列化
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `pickle.loads(user_input)` | Critical | `pickle\.loads?` | python-deser.yaml |
| `pickle.load(user_input)` | Critical | `pickle\.load\(` | python-deser.yaml |
| `yaml.load(user_input)` (无 Loader 参数) | Critical | `yaml\.load\(` | python-deser.yaml |
| `yaml.load(user_input, Loader=UnsafeLoader)` | Critical | `UnsafeLoader\|FullLoader` | python-deser.yaml |
| `marshal.loads(user_input)` | Critical | `marshal\.loads?` | python-deser.yaml |
| `shelve.open()` | High | `shelve\.open` | python-deser.yaml |
| `jsonpickle.decode(user_input)` | High | `jsonpickle\.decode` | python-deser.yaml |

## SQL 注入

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `cursor.execute(f"SELECT ... {user_var}")` | High | `execute\(f"` | python-sqli.yaml |
| `cursor.execute("SELECT ... " + user_var)` | High | `execute\(.*\+` | python-sqli.yaml |
| `cursor.execute("SELECT ... %s" % user_var)` | High | `execute\(.*%` | python-sqli.yaml |
| `cursor.execute("SELECT ...".format(user_var))` | High | `execute\(.*\.format` | python-sqli.yaml |
| `Model.objects.raw(user_input)` (Django ORM raw SQL) | High | `\.objects\.raw\(` | python-sqli.yaml |
| `db.session.execute(text(user_input))` (SQLAlchemy) | High | `session\.execute` | python-sqli.yaml |
| `django.db.connection.cursor().execute(user_input)` | High | `connection\.cursor` | python-sqli.yaml |

**正确做法**：使用参数化查询 `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`

## SSRF

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `requests.get/post/put(user_input)` | High | `requests\.(get|post|put|delete|patch)\(` | python-ssrf.yaml |
| `urllib.request.urlopen(user_input)` | High | `urllib.*urlopen` | python-ssrf.yaml |
| `urllib.request.Request(user_input)` | High | `urllib.*Request` | python-ssrf.yaml |
| `httpx.get/post(user_input)` | High | `httpx\.` | python-ssrf.yaml |
| `aiohttp.ClientSession().get(user_input)` | High | `aiohttp` | python-ssrf.yaml |
| `ftplib.FTP().connect(user_input)` | High | `ftplib` | python-ssrf.yaml |
| `smtplib.SMTP(user_input)` | High | `smtplib` | python-ssrf.yaml |

## 文件操作

### 文件读取
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `open(user_input)` | High | `open\(` | python-file.yaml |
| `pathlib.Path(user_input).read_text()` | High | `Path\(.*\)\.read` | python-file.yaml |
| `pathlib.Path(user_input).read_bytes()` | High | `Path\(.*\)\.read` | python-file.yaml |
| `shutil.copyfile(src, dst)` | High | `shutil\.copy` | python-file.yaml |

### 文件写入
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `open(user_input, 'w')` | High | `open\(.*'w'` | python-file.yaml |
| `pathlib.Path(user_input).write_text()` | High | `Path\(.*\)\.write` | python-file.yaml |
| `shutil.move(src, dst)` | High | `shutil\.move` | python-file.yaml |

### 路径遍历
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `os.path.join(base, user_input)` | High | `os\.path\.join` | python-file.yaml |
| 直接拼接路径 `base + user_input` | High | `\+.*\.py\|\.txt\|\.json` | python-file.yaml |

### 文件上传
| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `request.FILES['file'].save()` (Django) | High | `request\.FILES` | python-file.yaml |
| `request.files['file'].save()` (Flask) | High | `request\.files` | python-file.yaml |
| 上传文件名直接使用用户输入 | High | `filename` + `save\|write` | python-file.yaml |

## XXE

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `xml.etree.ElementTree.parse(user_input)` | High | `ElementTree\.parse` | python-misc.yaml |
| `lxml.etree.parse(user_input)` (未禁用外部实体) | High | `lxml\.etree\.parse` | python-misc.yaml |
| `xml.sax.parse(user_input)` | High | `xml\.sax` | python-misc.yaml |
| `defusedxml` 未使用时 | Medium | `import xml` (未使用 defusedxml) | python-misc.yaml |

## XSS

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `markupsafe.Markup(user_input)` (未转义) | Medium | `Markup\(` | python-misc.yaml |
| Django 视图返回 `HttpResponse(user_input)` | Medium | `HttpResponse\(` | python-misc.yaml |
| Jinja2 `{{ var|safe }}` 用户可控变量 | Medium | `\|safe` | python-misc.yaml |

## 开放重定向

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `redirect(user_input)` (Django/Flask) | Medium | `redirect\(` | python-misc.yaml |
| `HttpResponseRedirect(user_input)` | Medium | `HttpResponseRedirect` | python-misc.yaml |

## 认证/授权

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| 缺少 `@login_required` 的视图 | Medium | `def .*\(request\)` (无 `@login_required`) | python-auth.yaml |
| 缺少 `@permission_classes` 的 API (DRF) | Medium | `@api_view` (无 permission) | python-auth.yaml |
| `@csrf_exempt` 滥用 | Medium | `@csrf_exempt` | python-auth.yaml |
| Django `authenticate` 但未 `login` | Low | `authenticate\(` | python-auth.yaml |

## 加密弱点

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `hashlib.md5()` / `hashlib.sha1()` | Medium | `hashlib\.(md5|sha1)` | python-crypto.yaml |
| `Crypto.Cipher.DES` / `DES3` | Medium | `DES` | python-crypto.yaml |
| `Crypto.Cipher.AES.new(key, ECB)` | Medium | `ECB` | python-crypto.yaml |
| 硬编码密钥/密码 | Medium | `password\s*=\s*"[^"]+"\|SECRET_KEY\s*=` | python-crypto.yaml |
| `random` 模块用于安全场景 | Medium | `random\.` (应为 `secrets`) | python-crypto.yaml |

## 配置问题

| Sink | 风险 | Grep 模式 | Semgrep |
|------|------|-----------|---------|
| `DEBUG = True` (生产环境) | Medium | `DEBUG\s*=\s*True` | python-config.yaml |
| `ALLOWED_HOSTS = ['*']` | Medium | `ALLOWED_HOSTS.*\*` | python-config.yaml |
| `SECRET_KEY` 硬编码在代码中 | Medium | `SECRET_KEY\s*=` | python-config.yaml |
| CORS 配置 `ALLOW_ALL_ORIGINS = True` | Medium | `ALLOW_ALL_ORIGINS` | python-config.yaml |

## P1.1 现代攻击面补全（v2）

> 以下条目在 v1 中遗漏，已新增对应 Semgrep 规则或建议人工 grep。

### RCE / 反序列化补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `dill.loads()` / `dill.load()` | High | `dill\.loads?\(` | 已新增 `python-deser-011-dill-cloudpickle` |
| `cloudpickle.loads()` / `cloudpickle.load()` | High | `cloudpickle\.loads?\(` | 同上 |
| `joblib.load()` | High | `joblib\.load\(` | 已新增 `python-deser-010-joblib`；sklearn 模型 |
| `yaml.unsafe_load()` | High | `yaml\.unsafe_load\(` | 已新增 `python-deser-009-unsafe-load` |
| `subprocess.run([...] + $VAR)` | High | `subprocess.*\[.*\]\s*\+` | 已新增 `python-rce-005b` |
| `Mako.Template($TPL).render()` | Medium | `Mako\.Template` | Mako SSTI |
| `ast.parse()` + `compile()` 链式 | Medium | `ast\.parse.*compile` | 罕见但存在 |

### SQL 注入补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `sqlalchemy.text($SQL + ...)` | High | `text\(.*\+` | 已新增 `python-sqli-009-sqlalchemy-text-concat` |
| `pandas.read_sql($SQL + ..., conn)` | High | `read_sql\(.*\+` | 已新增 `python-sqli-010-pandas-read-sql-concat` |
| `peewee` `RawQuery($SQL + ...)` | High | `RawQuery\(` | peewee ORM 原生 SQL |
| `dataset.Database.query($SQL)` | High | `dataset\..*query\(` | dataset 库 |
| Django ORM `objects.filter(**user_kwargs)` | Medium | `filter\(\*\*` | kwargs 可注入 `__lookup` 字段遍历 |

### SSRF / 网络 IO 补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `socket.create_connection((host, port))` | Medium | `create_connection\(` | 低级 socket SSRF |
| `socket.gethostbyname($host)` | Low | `gethostbyname\(` | 内网探测 |
| `smtplib.SMTP_SSL($host)` | Medium | `SMTP_SSL\(` | SMTP server 用户可控 |
| `ftplib.FTP($host)` | Medium | `ftplib\.FTP\(` | FTP server 用户可控 |
| `asyncio.open_connection($host, $port)` | Medium | `asyncio\.open_connection` | 异步 socket |

### 文件 / 临时文件补全

| Sink | 风险 | Grep 模式 | 备注 |
|------|------|-----------|------|
| `tempfile.mktemp()` | Medium | `tempfile\.mktemp\(` | 弃用 API，TOCTOU 竞态 |
| `os.symlink($USER_PATH, ...)` | Medium | `os\.symlink` | 符号链接攻击 |
| `pathlib.Path($USER).expanduser()` | Low | `expanduser\(` | `~user/...` 可枚举家目录 |

### 现代 Web 攻击面（未来补强）

| 攻击面 | 关注点 | 备注 |
|--------|--------|------|
| JWT alg confusion | `PyJWT.decode(token, algorithms=[...])` 缺失 | python-auth.yaml 待补 |
| GraphQL 字段授权 | `graphene` / `strawberry` 解析器无权限校验 | python-misc.yaml 待补 |
| FastAPI `Depends()` 链权限 | 依赖注入 override 未鉴权 | python-misc.yaml 待补 |
| LLM Prompt Injection | `langchain.PromptTemplate.from_template(USER)` | python-emerging.yaml 待补 |

