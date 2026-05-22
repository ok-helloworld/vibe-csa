# 安全检查清单

55+ 漏洞类型检查清单，按 OWASP Top 10 分类。

## A01: Broken Access Control

- [ ] 所有 T1 端点有认证检查
- [ ] 敏感端点有授权检查（角色/权限）
- [ ] 无水平越权（IDOR）
- [ ] 无垂直越权（普通用户执行管理员操作）
- [ ] 目录遍历防护（文件操作中的路径校验）
- [ ] 开放重定向防护

## A02: Cryptographic Failures

- [ ] 密码使用 bcrypt/argon2 存储
- [ ] 无 MD5/SHA-1 用于密码哈希
- [ ] 无 DES/3DES/RC4 加密
- [ ] 无 ECB 模式
- [ ] 无硬编码密钥/密码/Token
- [ ] 使用安全随机数生成器
- [ ] TLS 配置正确（非 SSLv3/TLS 1.0）

## A03: Injection

### SQL 注入
- [ ] 所有 SQL 查询使用参数化
- [ ] 无字符串拼接 SQL
- [ ] ORM 中无 raw/extra 用户可控
- [ ] ORDER BY 子句无用户可控排序

### 命令注入
- [ ] 无 eval/exec/system 用户可控输入
- [ ] subprocess 无 shell=True + 用户输入
- [ ] 无反引号命令执行用户输入

### 模板注入
- [ ] 无 render_template_string 用户输入
- [ ] Blade 无 {!! !!} 用户输入
- [ ] Twig 无 {{ var|raw }} 用户输入
- [ ] Velocity/FreeMarker 无用户可控模板

### XSS
- [ ] 所有用户输出经 HTML 编码
- [ ] 无 innerHTML/document.write 用户输入
- [ ] 无 dangerouslySetInnerHTML 用户输入
- [ ] 无 v-html 用户输入
- [ ] Content-Security-Policy 配置

### XXE
- [ ] XML 解析器禁用 DOCTYPE
- [ ] XML 解析器禁用外部实体
- [ ] 使用 defusedxml（Python）

### LDAP 注入
- [ ] LDAP filter 使用 ldap_escape 或等效转义

## A04: Insecure Design

- [ ] 金融交易金额由服务端计算
- [ ] 库存扣减有并发控制
- [ ] 状态变更有前置状态验证
- [ ] 敏感操作有幂等性保护
- [ ] 无批量分配漏洞
- [ ] 业务流程无状态机绕过

## A05: Security Misconfiguration

- [ ] 生产环境 DEBUG = False
- [ ] 错误信息不外露
- [ ] CORS 配置限制到可信域名
- [ ] HTTP 头安全（X-Frame-Options, X-Content-Type-Options, etc.）
- [ ] 默认密码已修改
- [ ] 无用端点/接口已移除
- [ ] 框架版本为最新安全版本

## A06: Vulnerable and Outdated Components

- [ ] 第三方组件版本已知
- [ ] 无已知 CVE 的组件
- [ ] 依赖锁定版本（lock file）
- [ ] 定期更新依赖

## A07: Identification and Authentication Failures

- [ ] 认证机制对所有敏感端点生效
- [ ] 密码策略（长度、复杂度）
- [ ] 会话管理安全（HTTPOnly, Secure, SameSite）
- [ ] 暴力破解防护
- [ ] 会话固定攻击防护
- [ ] 密码重置流程安全

## A08: Software and Data Integrity Failures

- [ ] 反序列化输入经过验证
- [ ] CI/CD 流水线完整性
- [ ] 无 insecure deserialization
- [ ] 软件更新使用签名验证
- [ ] 文件上传类型验证
- [ ] 无 Phar 反序列化（PHP）

## A09: Security Logging and Monitoring Failures

- [ ] 认证失败有日志
- [ ] 授权失败有日志
- [ ] 敏感操作有审计日志
- [ ] 日志中无敏感数据（密码、Token）
- [ ] 日志注入防护

## A10: Server-Side Request Forgery

- [ ] 所有外部请求 URL 经过校验
- [ ] URL 白名单或黑名单验证
- [ ] 阻止内网地址访问
- [ ] 阻止 302 重定向绕过
- [ ] 阻止 DNS rebinding

## 框架专项检查

### Spring Security
- [ ] http.authorizeRequests() 配置正确
- [ ] CSRF 保护配置（API 可禁用）
- [ ] @PreAuthorize / @Secured 使用一致

### Django
- [ ] MIDDLEWARE 包含安全中间件
- [ ] SECURE_* 设置配置
- [ ] Admin 站点访问限制

### Laravel
- [ ] web 中间件组应用于 web 路由
- [ ] api 中间件组应用于 API 路由
- [ ] $fillable / $guarded 配置防批量分配
