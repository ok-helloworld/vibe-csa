# 业务场景标签

API 接口按业务风险分为 7 类场景，决定审计深度和 CoT 推理触发条件。

## 场景分类

### FINANCIAL_TRANSACTION（CRITICAL）

涉及资金流动的操作。

**关键词**：pay, payment, transfer, refund, recharge, withdraw, invoice, bill, order, checkout, amount, price, balance, coupon, discount, wallet

**审计要求**：
- 必须执行 CoT 四步推理
- 检查金额来源（服务端计算 vs 客户端传入）
- 检查并发控制（库存/余额竞态条件）
- 检查幂等性保护
- 检查事务一致性

### PRIVILEGED_OPERATION（HIGH）

涉及权限变更和敏感管理操作。

**关键词**：admin, role, permission, grant, revoke, user, password, reset, enable, disable, delete, ban, lock, unlock, assign

**审计要求**：
- 必须执行 CoT 四步推理
- 检查权限校验（角色/权限检查）
- 检查所有权验证
- 检查 CSRF 保护
- 检查操作日志记录

### RESOURCE_ALLOCATION（HIGH）

涉及资源分配和扣减。

**关键词**：stock, inventory, quota, allocate, reserve, claim, limit, capacity, coupon, ticket, gift, reward

**审计要求**：
- 必须执行 CoT 四步推理
- 检查并发控制（乐观锁/悲观锁/分布式锁）
- 检查超额扣减防护
- 检查 TOCTOU 竞态条件

### STATE_TRANSITION（HIGH）

涉及状态变更的流程。

**关键词**：status, state, approve, reject, submit, cancel, complete, publish, archive, activate, deactivate

**审计要求**：
- 必须执行 CoT 四步推理
- 检查状态机约束（前置状态验证）
- 检查不可逆操作保护
- 检查状态变更日志

### DATA_ACCESS（MEDIUM）

数据查询和导出操作。

**关键词**：list, search, query, export, download, view, detail, report, stats, analytics

**审计要求**：
- 标准审计深度
- 检查数据权限（只能访问自己的数据）
- 检查批量查询限制（分页、限流）
- 检查敏感字段脱敏

### USER_OPERATION（MEDIUM）

用户个人信息操作。

**关键词**：profile, register, login, update, avatar, nickname, bio, setting, preference, notification

**审计要求**：
- 标准审计深度
- 检查所有权验证（只能修改自己的信息）
- 检查输入验证
- 检查 CSRF 保护（状态变更操作）

### PUBLIC_ACCESS（LOW）

公开可访问的接口。

**关键词**：index, home, about, contact, help, faq, docs, static, health, ping

**审计要求**：
- 快速审计模式
- 可以跳过深度 CoT 推理
- 检查是否真的公开（确认无认证要求）
- 检查是否意外暴露敏感数据

## 场景 + Tier 矩阵

| Tier \ 场景 | FINANCIAL | PRIVILEGED | RESOURCE | STATE | DATA | USER | PUBLIC |
|-------------|-----------|------------|----------|-------|------|------|--------|
| T1 | depth+CoT | depth+CoT | depth+CoT | depth+CoT | standard | standard | quick |
| T2 | depth | depth | depth | depth | standard | standard | skip |
| T3 | standard | standard | standard | standard | skip | skip | skip |

## 场景乘数

场景标签调整 EALOC 计算：
- CRITICAL: ×1.5
- HIGH: ×1.2
- MEDIUM: ×1.0
- LOW: ×0.5

这决定了高敏感接口需要更多的审计资源。

## 场景检测

通过以下线索自动检测场景：
1. 路由路径（URL 中的关键词）
2. 方法名称（函数名中的关键词）
3. 注释和文档字符串
4. 请求/响应模型名称
5. 数据库表名
