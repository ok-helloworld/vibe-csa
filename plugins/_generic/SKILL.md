---
name: vibe-csa-generic
description: "Generic fallback plugin for vibe-csa when no language-specific audit plugin matches. Use for unsupported languages during white-box code security audit workflows."
---

# Generic 兜底插件（降级模式）

> 当项目语言**没有**对应的 `plugins/<lang>/` 时（Go/Node/TypeScript/Ruby/Rust/C#/Kotlin 非 JVM 项目等），核心协议自动加载本插件，以降级模式继续审计。

## 1. 触发条件

在 Stage 1 静态审计的代码度量阶段，按文件扩展名识别出语言后：

| 检测到的语言 | 加载插件 |
|------------|---------|
| Java / Kotlin（含 JVM Web 项目） | `plugins/java/` |
| Python | `plugins/python/` |
| PHP | `plugins/php/` |
| **其他**（Go / Node / TypeScript / C# / Ruby / Rust / C/C++ / Scala 等） | `plugins/_generic/` |

Stage 1 不再因“语言未识别”而 STOP，除非完全无可识别源代码文件。

## 2. 降级清单（哪些能力变化）

| 能力 | 完整插件 | Generic 兜底 |
|------|---------|--------------|
| Tier 分类（T1/T2/T3） | 语言专属语法识别 | 启发式：路径关键字 + 通用文件名模式 |
| EALOC 权重校准 | 按语言项目特征校准 | 沿用默认 W1=1.0 / W2=0.5 / W3=0.1 |
| Layer 1 Semgrep 扫描 | 8-15 条专属规则 | **跳过**（无规则） |
| Layer 1 ripgrep 危险函数 | 语言专属 Sink 清单 | 跨语言通用 Sink 模式（见 `sinks.md`） |
| Layer 2 多 Agent 并行审计 | 完整 6 维度 | **完整 6 维度**（Agent 能读任何语言的源码） |
| Stage 1 反幻觉与静态评级 | 完整 | **完整**（核心协议语言无关） |
| Stage 2 环境验证 + 签名匹配 | 完整 | **完整**（签名库在 HTTP 响应层匹配，跟语言无关） |
| 框架专项审计 | 框架字典 + 路由提取命令 | 通用关键字探测（见 `frameworks.md`） |

**关键**：Stage 1 的反幻觉铁律、Stage 2 的实质性证据强制（`_evidence_match`）、`x_finding_class` 区分，这些 v3 强化全部 100% 生效。降级只发生在 Stage 1 的静态发现阶段；运行时证据要求**没有任何放水**。

## 3. 审计姿态调整

由于无 Semgrep 自动化和 Sink 字典精度降低，多 Agent 审计应采取**更激进的"读完才下结论"**策略：

1. T1 文件 100% 用 Read 通读，不依赖正则筛选
2. 多 Agent 各自记录“我能识别什么不能识别”——例如 Agent-Injection 不熟悉 Go 的 ORM，应明示，由后续汇总与验证阶段复核
3. 框架识别失败时直接 grep `route` / `handler` / `controller` / `mux` / `app.get` / `app.post` 等关键字找入口
4. 多 Agent 报告中标注 `x_plugin_mode = "generic"`，便于审计后定位降级影响

## 4. 报告中标注

主报告 `audit` 顶层添加：

```json
{
  "audit": {
    "language": ["Go"],
    "x_plugin_mode": "generic",
    "x_generic_reason": "no plugins/go/ available; static analysis quality degraded"
  }
}
```

读者一眼能看出本次审计的静态阶段质量受限。**但 CONFIRMED 发现的运行时证据质量与完整插件无差异**，因为 Stage 2 签名匹配完全语言无关。

## 5. 升级路径

如果该语言审计频繁出现且 generic 兜底质量不够，建议补完整插件。建议优先顺序：

1. **Go**：云原生后端高频，Sink/框架（gin/echo/chi/fiber）相对集中，~600 行 markdown + 8 条 Semgrep 可达完整支持
2. **Node.js / TypeScript**：Web 后端体量最大，框架（Express/Koa/NestJS/Next.js）复杂但样式集中
3. **C# / .NET**：企业项目高频，ASP.NET Core 路由+Razor+EF Core 主导
4. **Ruby**：Rails 主导，单一框架反而好做
5. **Rust**：actix-web / axum / rocket，量小但增长快
6. **C/C++**：需要单独项目，Sink 分析方式差异大（栈溢出/整数溢出/Use-After-Free 等）

补一种新语言只需照 `plugins/plugin-schema.md` 复制目录骨架，依次填写 4 个 md + Semgrep 规则。

