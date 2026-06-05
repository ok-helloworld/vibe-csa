# Generic 跨语言危险函数清单

> 用 ripgrep 正则跨语言匹配。命中即 Layer 1 候选发现，必须 Read 文件确认上下文（参数来源、是否参数化、是否过滤）。

## 使用方式

```bash
rg -n -t go -t js -t ts -t rb -t rs -t cs --no-heading "<pattern>" <project_root>
```

`-t` 多次叠加以同时扫多语言；未识别的扩展名追加 `--type-add 'mylang:*.xx'`。

> 没有 Semgrep 规则——本插件不提供 `semgrep/` 目录。LLM 应靠 ripgrep + Read 完成所有 Sink 验证。

---

## 1. RCE / 命令注入（P0）

| 语言 | 正则模式 | 备注 |
|------|---------|------|
| 通用 | `\beval\s*\(` | JS/Ruby/Lua/Perl 都中招 |
| 通用 | `\bexec\s*\(` | Python/Ruby/JS（也匹配函数定义，需 Read 确认）|
| Go | `exec\.Command\s*\(` | 第一个参数被拼接即危险 |
| Go | `exec\.CommandContext\s*\(` | 同上 |
| Node | `child_process\.(exec\|execSync\|spawn\|spawnSync\|execFile)` | exec/execSync 走 shell，最危险 |
| Node | `require\(['"]child_process['"]\)` | import 即可疑 |
| Node | `vm\.(runInNewContext\|runInThisContext\|Script)` | 沙箱可逃逸 |
| Ruby | `\bsystem\s*\(\|\bbackticks\s*\(\|\bspawn\s*\(\|%x\{` | `%x{cmd}` 是 Ruby 反引号 |
| Ruby | `Open3\.(popen\d?\|capture\d?)` | |
| C# | `Process\.Start\s*\(\|ProcessStartInfo` | 含 shell 调用尤其危险 |
| C# | `Assembly\.Load\s*\(` | 动态加载 .NET 程序集 |
| Rust | `std::process::Command::new\s*\(` | arg/args 含用户输入危险 |
| 通用 | `\bos\.system\s*\(\|popen\s*\(\|subprocess\.` | Python（备份匹配，主要在 plugins/python） |

**唯一标记 payload**：响应 body 应能 grep 到 `uid=\d+\(...\)` 或 `Windows IP Configuration` 才算 L3 证据（详见 `references/exploit-success-signatures.md` `cmd-exec` 组）。

## 2. SQL 注入（P0）

| 语言 | 正则模式 | 备注 |
|------|---------|------|
| 通用 | `(SELECT\|INSERT\|UPDATE\|DELETE)\s+.+\+\s*\w+` | 字符串拼接 SQL |
| 通用 | `(SELECT\|INSERT\|UPDATE\|DELETE)\s+.+(\$\{\|format\s*\(\|%s\b\|f"\|f'\|`)` | 模板字符串 |
| Go | `db\.(Query\|QueryRow\|Exec\|QueryContext\|ExecContext)\s*\(\s*fmt\.Sprintf` | 经典反例 |
| Go | `db\.(Query\|Exec)\s*\(\s*"[^"]*"\s*\+` | 字符串拼接 |
| Node | `\.(query\|exec)\s*\(\s*['"`][^'"`]*['"`]\s*\+` | mysql/pg 拼接 |
| Node | `\.raw\s*\(` | Knex/Sequelize raw 查询，参数拼接即危险 |
| Ruby | `where\s*\(\s*["'].*#\{` | Rails AR 字符串插值 |
| Ruby | `ActiveRecord::Base\.connection\.execute\s*\(` | 直接 SQL |
| C# | `SqlCommand\s*\(\s*"[^"]*"\s*\+\|new SqlCommand` | 拼接 + 参数化缺失 |
| C# | `\.ExecuteSqlRaw\s*\(\|FromSqlRaw\s*\(` | EF Core raw |
| Rust | `sqlx::query\s*\(\s*&?format!` | format! 拼接 |
| Rust | `diesel::sql_query\s*\(` | 直接 SQL |

**签名**：响应 body 命中 `sqli` 组正则（MySQL/MSSQL/PG/Oracle/SQLite 错误信息或版本字符串）。

## 3. 路径遍历 / 任意文件读取（P1）

| 语言 | 正则模式 |
|------|---------|
| 通用 | `\b(open\|fopen\|readFile\|readFileSync\|read_to_string\|File\.Open\|File\.ReadAllText)\s*\(` |
| Go | `ioutil\.ReadFile\|os\.Open\|os\.ReadFile\|filepath\.Join` |
| Go | `http\.ServeFile\|http\.FileServer` |
| Node | `fs\.(readFile\|readFileSync\|createReadStream)` |
| Node | `path\.(join\|resolve)\s*\([^)]*req\.(query\|params\|body)` |
| Ruby | `File\.(open\|read\|new)\s*\(` |
| C# | `File\.(Open\|ReadAllText\|ReadAllBytes)` 配合 `Path\.Combine` |
| Rust | `std::fs::(read\|read_to_string\|File::open)` |

**Sink Slot**：FILE-path（参数为完整路径）/ FILE-name（已固定目录）。前者高危。

**签名**：响应 body 命中 `traversal-linux` 或 `traversal-windows` 组正则。

## 4. 文件上传写入（P1 → P0 当可执行）

| 语言 | 正则模式 |
|------|---------|
| Go | `multipart\.(FileHeader\|File)`、`r\.FormFile\(`、`os\.Create\|ioutil\.WriteFile` |
| Node | `multer\(\|formidable\(\|busboy\(` |
| Node | `fs\.(writeFile\|writeFileSync\|createWriteStream)` |
| Ruby | `params\[.*\]\.tempfile\|File\.binwrite` |
| C# | `IFormFile\|FileStream\(` |
| Rust | `actix_multipart::Multipart\|axum::extract::Multipart` |

**Sink Slot**：FILE-path（攻击者控制写入路径）/ FILE-name（仅控制文件名）/ FILE-ext（仅控制扩展名）。

**强制**：文件上传发现进入 Stage 2 动态验证时必须按 `core/upload-verification.md` 3 步验证：上传 + GET 访问 + 命令回显（含 `x_unique_marker`）。

## 4.1 资源加载 / 动态消费补强（P1）

| 语言 | 正则模式 | 备注 |
|------|---------|------|
| 通用 | `load(template|view|module|plugin|resource|script)\s*\(` | 项目内包装加载器，需 Read 确认参数来源 |
| 通用 | `render\s*\([^)]*(template|view|page|theme)` | 动态模板 / 页面加载 |
| 通用 | `require\s*\([^)]*(module|plugin|path|name)` | 动态模块加载 |
| Go | `template\.ParseFiles\(|template\.ExecuteTemplate\(` | 模板名 / 文件路径可控时危险 |
| Node | `require\(\s*[^'"]|import\(\s*[^'"]` | 动态模块导入 |
| Ruby | `render\s+(file:|inline:|template:)` | 动态模板 / 文件渲染 |
| C# | `Assembly\.Load\(|AssemblyLoadContext\.LoadFromAssemblyPath` | 动态程序集 / 插件加载 |
| Rust | `tera\.render\(|handlebars\.render\(` | 模板名可控时需继续追踪 |

**规则**：配置值、数据库值、对象属性、环境变量进入模板名、模块名、插件名、资源路径时，不能停在 grep 命中，必须继续追踪消费点。

## 5. SSRF（P1）

| 语言 | 正则模式 |
|------|---------|
| Go | `http\.(Get\|Post\|Head\|NewRequest)\s*\(\|client\.Get\(\|client\.Do\(` |
| Go | `net\.Dial\(\|net\.DialContext\(` |
| Node | `axios\.(get\|post\|request)\|fetch\(\|http\.(get\|request)\|https\.(get\|request)` |
| Node | `node-fetch\|got\(\|request\(` |
| Ruby | `Net::HTTP\.\|open-uri\|RestClient\.\|HTTParty\.` |
| C# | `HttpClient\.\|WebRequest\.Create\|HttpWebRequest` |
| Rust | `reqwest::(get\|Client::new)\|hyper::Client` |

**签名**：响应命中 `ssrf` 组（云元数据 / SSH banner / Redis PONG 等）。

## 6. SSTI（P0 → 模板引擎）

| 语言 | 模板引擎 | 危险模式 |
|------|---------|---------|
| Go | `html/template` | `template.Must(template.New("").Parse(userInput))` |
| Go | `text/template` | 同上，且无 HTML 转义 |
| Node | Handlebars/Pug/EJS/Nunjucks | `template(userInput)`、`compile(userInput)` |
| Ruby | ERB | `ERB.new(userInput).result\|render inline:` |
| Ruby | Liquid | `Liquid::Template.parse(userInput)` |
| C# | Razor | `RazorEngine\.Razor\.Parse\|.Compile` |
| Rust | Tera/Askama | `Tera::one_off\(&userInput` |

**签名**：响应命中 `ssti` 组（`{{7*7*7}}` → `343`、`__import__` 输出等）。

## 7. 反序列化（P0）

| 语言 | 危险函数 | 备注 |
|------|---------|------|
| Go | `json\.Unmarshal\|gob\.Decode\|yaml\.Unmarshal` | gob 危险；yaml 看实现 |
| Node | `JSON.parse` 拼接 reviver、`node-serialize.unserialize`、`marsdb` | node-serialize 经典 RCE |
| Node | `vm\.runInNewContext` | 已在 RCE 段也列了 |
| Ruby | `Marshal\.load\|YAML\.load\|YAML\.unsafe_load\|JSON\.load`（注意 load vs parse）| Marshal/YAML.load 经典 RCE |
| C# | `BinaryFormatter\.Deserialize\|NetDataContractSerializer\|SoapFormatter\|LosFormatter` | 全部禁用级别 |
| C# | `JsonConvert\.DeserializeObject\(.+TypeNameHandling\)` | TypeNameHandling != None 即危险 |
| Rust | `serde_json::from_str` 配合不受信类型 | 较少 RCE，看 trait |

**签名**：响应命中 `deser` 组（异常堆栈 / gadget 类名）；或带 OOB 域名验证。

## 8. XXE（P1）

| 语言 | 危险函数 |
|------|---------|
| Go | `encoding/xml.Unmarshal` 默认不解析外部实体，但 `xmlpull`、`etree` 第三方库可能 |
| Node | `libxmljs\|xmldom\|xml2js` 配置不当 |
| Ruby | `Nokogiri::XML.parse` 默认禁用 DTD；`REXML::Document.new` 可解析 |
| C# | `XmlDocument\.Load\|XmlReader\.Create` 配 `DtdProcessing.Parse` |
| Rust | `xml-rs\|quick-xml` 通常安全；`libxml` crate 看配置 |

**签名**：响应命中 `xxe` 组或返回的文件内容命中 `traversal-*` 组。

## 9. 认证 / 越权 / IDOR（P1）

跨语言无统一 Sink，需手工 Read 路由 + 中间件确认：

- Go：`gin.Use` / `chi.Use` / `mux.Use` 调用前是否有 auth middleware
- Node：`app.use(authMiddleware)` 顺序、`@UseGuards` 注解
- Ruby：`before_action :authenticate_user!`
- C#：`[Authorize]` / `[AllowAnonymous]` 注解
- Rust：`tower::ServiceBuilder::layer(AuthLayer)`

**IDOR 签名**：要求 finding 中提供 `x_idor_other_user_marker`（如他人 user_id / order_id），脚本自动匹配响应中是否含该标识。

## 10. 加密 / 密钥 / 配置（P2）

| 模式 | 含义 |
|------|------|
| `(api[_-]?key\|secret\|token\|password)\s*=\s*['"`][^'"`]{8,}['"`]` | 硬编码凭证 |
| `MD5\|sha1\(` | 弱哈希（密码场景才危险） |
| `Random\(\)\|Math\.random\(\)` | 非密码学安全随机数（用于 token/盐才危险） |

**规则 10 提醒**：除非有完整数据流（弱哈希 → 密码存储 → 用户名/密码下载入口），否则属"配置类"问题，按反幻觉规则 10 不能单独标 CONFIRMED。

## 10.1 配置驱动加载与二次消费候选点（P1）

| 模式 | 含义 |
|------|------|
| `(template|view|module|plugin|resource|script|theme|loader)\s*[:=]\s*.+` | 高风险配置键可写，命中后需追踪消费点 |
| `(getenv\(|os\.environ|System\.getProperty|config\.|settings\.)` | 配置值 / 环境变量作为间接污染源 |
| `(upload|template|view|resource|plugin|theme|cache|storage)` | 重点关注是否既可写又会被运行时消费 |
| `load.*\(|render.*\(|require.*\(|Assembly\.Load|import\(` | 若与配置写入或文件写入同时出现，应优先判断是否可形成二次消费链 |

**规则**：出现“配置写入 + 动态加载 / 模板加载 + 文件上传 / 文件写入”组合时，应优先判断是否可形成资源覆盖、模板执行、模块执行或插件执行链。

---

## Stage 1 预扫描操作建议

按 P0 → P1 → P2 顺序，每个 Sink 类别跑一遍 ripgrep，把结果写入：

- `p0-critical.md`：P0 类别（RCE/SQL/反序列化/SSTI）
- `p1-high.md`：P1 类别（路径遍历/文件上传/SSRF/XXE/Auth）
- `p2-medium.md`：P2 类别（加密弱点）

每条候选记录：文件路径、行号、命中的正则、上下文 1-2 行。由 Stage 1 多 Agent 深度分析接管，逐个 Read 确认是否真为漏洞。
