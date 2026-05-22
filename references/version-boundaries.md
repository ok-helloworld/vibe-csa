# 版本边界参考

关键框架和组件的版本边界信息。用于判断漏洞是否在目标版本中实际存在，以及利用技术是否适用于特定版本。

**使用方法**：在 Stage 1 检测到框架版本后，对照本文件确认已知漏洞和防护机制是否存在。

## Java 组件

### Fastjson

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| < 1.2.24 | 危险 | 默认开启 autotype，远程 RCE |
| 1.2.25 - 1.2.47 | 危险 | autotype 默认关闭但可绕过，多 gadget 链可用 |
| 1.2.48 - 1.2.67 | 中危 | autotype 严格限制，但仍有绕过 |
| >= 1.2.68 | 修复 | autotype 白名单模式，需显式开启 |

### Log4j2

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| 2.0 - 2.14.1 | 危险 | Log4Shell（CVE-2021-44228），JNDI 注入 RCE |
| 2.15.0 | 部分修复 | 默认禁用 JNDI lookup，但有绕过（CVE-2021-45046） |
| 2.16.0 | 进一步修复 | 完全移除 JNDI lookup，但有 DOS 漏洞 |
| >= 2.17.0 | 修复 | 全面修复 Log4Shell 和相关漏洞 |

### JDK JNDI

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| JDK 6u211 / 7u201 / 8u191 之前 | 危险 | JNDI Reference 无限制，远程 RCE |
| JDK 8u191+ | 部分缓解 | `trustURLCodebase=false` 默认，但仍有绕过方式 |
| JDK 11.0.1+ / 12+ | 进一步缓解 | LDAP ClassDefinition 限制更严格 |

### Spring Framework

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| 3.x - 5.3.17 | 危险 | Spring4Shell（CVE-2022-22965），Data Binding RCE |
| 5.3.18+ / 5.2.20+ | 修复 | 修复 Data Binding 漏洞 |
| Spring Boot < 2.5.12 | 危险 | 内嵌 Tomcat 受 Spring4Shell 影响 |
| Spring Boot >= 2.5.12 | 修复 | 升级 Spring Framework 版本 |

### Apache Shiro

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| < 1.2.4 | 危险 | 默认 AES 密钥泄露，反序列化 RCE |
| 1.2.4 - 1.5.2 | 中危 | 修复默认密钥，但仍有绕过 |
| >= 1.5.3 | 修复 | 全面修复反序列化和认证绕过 |

### Jackson

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| < 2.10.0 | 危险 | `enableDefaultTyping` 默认多态反序列化，gadget 链多 |
| 2.10.0 - 2.13.x | 中危 | 默认安全但有已知 gadget 绕过 |
| >= 2.14.0 | 修复 | 默认反序列化白名单更严格 |

## Python 组件

### Django

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| < 2.2 | 已过期 | 多个已修复 XSS/CSRF/SQLi 漏洞 |
| 2.2 - 3.2 | LTS | 安全更新中，但新功能缺失 |
| 4.0 - 4.1 | 当前 | 安全修复活跃 |
| >= 4.2 LTS | 推荐 | 最新 LTS 版本 |

**关键漏洞版本**：
- Django < 3.2.4：SQL 注入（CVE-2021-35042）
- Django < 3.2.13：SQL 注入（CVE-2022-28346/28347）
- Django < 4.0.8：DOS（CVE-2022-34265）

### PyYAML

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| 任意版本 `yaml.load()` | 危险 | 默认 Loader 不安全，可 RCE |
| >= 5.1 `yaml.safe_load()` | 安全 | SafeLoader 替代方案 |
| >= 5.1 `yaml.load(..., Loader=SafeLoader)` | 安全 | 显式指定安全 Loader |

**注意**：即使最新版本，`yaml.load(data)` 不带 Loader 参数在 5.1+ 会抛出警告，但仍可执行。

### Jinja2

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| 任意版本 | 注意 | SSTI 风险始终存在，与版本无关 |
| >= 2.8.5 | 缓解 | SandboxedEnvironment 更严格 |
| >= 2.11 | 缓解 | 更多内置函数沙箱化 |

### Flask

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| < 2.2.5 | 注意 | `session` 默认签名密钥可被暴力破解（短密钥） |
| >= 2.2.5 | 修复 | Session 安全性改进 |

## PHP 组件

### ThinkPHP

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| 5.0.x < 5.0.24 | 危险 | 多个 RCE 漏洞（方法调用/控制器实例化） |
| 5.1.x < 5.1.38 | 危险 | 同上 |
| 6.0.x | 修复 | 架构重构，移除了危险的动态调用 |

### Laravel

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| < 8.0 | 已过期 | 多个已修复漏洞 |
| 8.x - 9.x | LTS | 安全更新中 |
| 10.x - 11.x | 推荐 | 最新版本 |

**关键漏洞版本**：
- Laravel < 8.73.1：SQL 注入（CVE-2021-43617）
- Laravel 8.x 多个版本：反序列化 gadget 链变化

### WordPress

| 版本 | 状态 | 关键变化 |
|------|------|----------|
| < 5.0 | 注意 | 多个核心漏洞已修复 |
| 5.0 - 5.9 | 当前 | 安全更新活跃 |
| >= 6.0 | 推荐 | 最新版本 |

**注意**：WordPress 审计重点在插件/主题，而非核心版本。

## 利用技术与版本关系

### SQL 注入

| 技术 | 适用版本 | 不适用版本 |
|------|----------|-----------|
| UNION 注入 | 大多数关系型数据库 | 无 |
| 布尔盲注 | 所有 SQL 引擎 | 无 |
| 时间盲注 | 所有 SQL 引擎 | 无 |
| 堆叠查询 | MySQL (多语句 enabled) | 默认关闭的数据库 |
| OUTFILE 写入 | MySQL FILE 权限 | 无 FILE 权限 |

### 反序列化 Gadget 链

| Gadget 链 | 适用组件版本 |
|-----------|-------------|
| CommonsCollections 1-7 | CommonsCollections 3.1-3.2.1（高版本修复） |
| Fastjson JNDI | Fastjson < 1.2.68 |
| Shiro RememberMe | Shiro < 1.2.4（默认密钥） |
| PHP GGAS (PHPGGC) | 各 PHP 框架特定版本 |

### SSRF 绕过技术

| 技术 | 适用场景 |
|------|----------|
| 302 重定向绕过 | 仅验证请求前 URL，不验证最终地址 |
| DNS Rebinding | 仅验证 DNS 解析结果，不验证连接时 IP |
| IPv6 映射 IPv4 | 仅检查 IPv4 黑名单 |
| 八进制/十六进制 IP | 简单字符串黑名单 |
| URL 编码绕过 | URL 规范化处理差异 |
| 特殊域名（nip.io, xip.io） | IP 黑名单未覆盖动态域名 |

## 版本检测命令

### Java
```bash
# Maven 项目
grep -r '<version>' pom.xml | head -20
mvn dependency:tree | grep -i 'fastjson\|log4j\|jackson\|shiro'

# Gradle 项目
grep -r 'implementation\|compile' build.gradle

# 检查 JAR 版本
find . -name '*.jar' | grep -E 'fastjson|log4j|jackson|shiro'
```

### Python
```bash
# 依赖版本
cat requirements.txt | grep -E 'django|pyyaml|jinja2|flask|celery'
pip freeze | grep -E 'django|pyyaml|jinja2|flask|celery'
```

### PHP
```bash
# Composer 依赖
cat composer.json | grep -E '"require"'
composer show | grep -E 'thinkphp|laravel|symfony'

# WordPress 版本
grep '$wp_version' wp-includes/version.php
```
