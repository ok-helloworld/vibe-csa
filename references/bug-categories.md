# 中文漏洞类型参考

`vuln_type` 是报告展示字段，必须写中文，并优先从以下漏洞分类里选择。`category` 是 vibe-csa 内部路由枚举，不替代 `vuln_type`。

## 分类候选

```text
文件上传
远程文件包含
本地溢出
权限提升
信息泄漏
登录绕过
目录穿越
解析错误
越权访问
跨站脚本
路径泄漏
代码执行
远程密码修改
远程溢出
目录遍历
空字节注入
中间人攻击
格式化字符串
缓冲区溢出
HTTP 请求拆分
CRLF 注入
XML 注入
本地文件包含
证书预测
HTTP 响应拆分
SSI 注入
内存溢出
整数溢出
HTTP 响应伪造
HTTP 请求伪造
内容欺骗
XQuery 注入
缓存区过读
暴力破解
LDAP 注入
安全模式绕过
备份文件发现
XPath 注入
URL 重定向
代码泄漏
释放后重用
DNS 劫持
错误的输入验证
通用跨站脚本
服务器端请求伪造
跨域漏洞
错误的证书验证
缓存投毒
HTTP请求走私
命令注入
HTTP 参数污染
后门
Cookie 验证错误
跨站请求伪造
ShellCode
SQL 注入
任意文件下载
任意文件创建
任意文件删除
任意文件读取
其他类型
变量覆盖
命令执行
嵌入恶意代码
弱密码
拒绝服务
数据库发现
```

## 使用规则

- `title`、`description`、`impact`、`remediation` 使用中文，`fix.after` 仅填写修复后的代码。
- `vuln_type` 使用上方中文类型；确实无法匹配时使用 `其他类型`，并在 `description` 中说明具体风险。
- `x_category_label` 使用面向人的中文分组，例如 `注入类`、`认证授权类`、`请求伪造与文件操作类`。
- `category` 只允许 schema 中的英文枚举，例如 `injection`、`auth`、`ssrf_file`。
