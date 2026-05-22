# 语言插件接口规范

每个语言插件必须提供以下文件，供核心协议在三阶段流水线中按需加载。

## 必需文件

### 1. `tier-rules.md`

**用途**：定义该语言的文件类型 → Tier（T1/T2/T3/SKIP）分类规则。
**加载时机**：Stage 1 静态审计开始时，用于代码度量和 EALOC 计算。
**内容要求**：
- 语言文件扩展名列表
- T1 识别模式（入口点：Controller/Route/View/Handler）
- T2 识别模式（业务逻辑：Service/DAO/Model/Util）
- T3 识别模式（数据结构：Entity/DTO/Schema）
- SKIP 排除模式（第三方库、测试代码、生成代码）
- 项目包名识别方法

### 2. `sinks.md`

**用途**：按漏洞类型分类的危险函数目录。
**加载时机**：Stage 1 静态审计中的 sink 预扫描和危险模式追踪。
**内容要求**：
- 按漏洞类型（RCE/SQL/SSRF/File/XXE/Auth/XSS 等）分组
- 每条包含：函数签名、风险等级、grep 搜索模式、对应 Semgrep 规则文件
- 覆盖该语言特有的所有危险函数

### 3. `frameworks.md`

**用途**：框架专属审计指南。
**加载时机**：Stage 1 静态审计中的框架检测后，以及框架专项审计时。
**内容要求**：
- 每种框架的路由提取方式
- 参数绑定方式
- 安全机制（认证、CSRF、XSS 防护等）
- 常见风险和特有风险
- 路由提取命令（ripgrep 命令示例）

### 4. `SKILL.md`

**用途**：语言专属审计指南，整合该语言的全部审计知识。
**加载时机**：检测到该语言后，作为该语言的主要参考文档。
**内容要求**：
- 语言检测特征
- 分层规则摘要（引用 tier-rules.md）
- Layer 1 预扫描危险模式表（P0/P1/P2）
- 框架专项索引（引用 frameworks.md）
- Semgrep 规则索引
- 双轨审计说明
- 漏洞编号规则
- 输出格式规范

## 可选文件

### 5. `decompile.md`

**用途**：反编译策略（仅 Java 需要）。
**加载时机**：项目包含 .class/.jar 且无对应源码时。
**内容要求**：工具获取、使用方式、反编译策略、注意事项。

### 6. `semgrep/*.yaml`

**用途**：Semgrep 静态分析规则。
**加载时机**：Stage 1 静态审计中的预扫描阶段。
**内容要求**：
- 文件命名：`<lang>-<category>.yaml`
- 每条规则包含：id、patterns、message、severity、languages、metadata
- severity: ERROR（确认漏洞）/ WARNING（可疑）/ INFO（信息）
- metadata 包含：category、cwe、references、vibe-csa-plugin、vibe-csa-stage

## 插件目录约定

```
plugins/<lang>/
├── SKILL.md              # 必需：语言审计指南
├── sinks.md              # 必需：危险函数目录
├── frameworks.md         # 必需：框架专项
├── tier-rules.md         # 必需：Tier 分类规则
├── decompile.md          # 可选：反编译策略
└── semgrep/              # 必需：Semgrep 规则目录
    ├── <lang>-rce.yaml
    ├── <lang>-sqli.yaml
    └── ...
```

## 核心协议消费方式

核心协议在三阶段流水线中按需加载插件文件：

| Stage | 加载文件 | 用途 |
|-------|----------|------|
| Stage 1 静态审计（识别与分层） | `tier-rules.md` | 文件分类 → EALOC 计算 |
| Stage 1 静态审计（框架识别） | `frameworks.md` | 框架检测 → 框架专项规则 |
| Stage 1 静态审计（预扫描） | `semgrep/*.yaml` + `sinks.md` | Semgrep 扫描 + 危险模式匹配 |
| Stage 1 静态审计（深度分析） | `sinks.md` + `SKILL.md` | Sink 驱动追踪 + 控制驱动追踪 |
| Stage 2 动态验证（按需） | `sinks.md` + `SKILL.md` | 验证路径补充、语言上下文提示 |
