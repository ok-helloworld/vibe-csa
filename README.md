# Vibe CSA

> 当前版本：v1.0.0

Vibe CSA (Code Security Audit) ，是一款基于 AI Agent 架构的代码审计工具，采用多 Agent 并行执行架构，用“上帝视角”静态审计源代码，用“实战模拟”动态验证漏洞，保证了web漏洞挖掘的全面性和准确性，输出稳定可靠的安全报告，提供可落地整改建议。

项目特点：
- `Stage 1`：基于源码和语言插件做静态审计
- `Stage 2`：基于静态 finding 做单漏洞动态验证
- `Stage 3`：生成标准 JSON，并导出 HTML / Word 报告

## 目录

- [适合谁](#适合谁)
- [注意事项](#注意事项)
- [环境运行依赖](#环境运行依赖)
- [执行步骤](#执行步骤)
- [Multi-Agent](#multi-agent)
- [提示词示例](#提示词示例)
- [报告生成说明](#报告生成说明)
- [流程示意图](#流程示意图)

## 适合谁

适合以下两类用户：
- 适合软件开发人员，用于web相关的安全自检
- 适合网络安全从业者，用于第三方的web安全检测

如果您是第一次接触这个项目，可以先把它理解为：
- `SKILL.md`：AI Agent 的主协议入口
- `core/`：阶段规则、证据契约、报告规范
- `plugins/`：按语言加载的静态审计规则
- `scripts/`：辅助脚本，负责合并结果、初始化 PoC、验证请求、校验和导出报告

使用AI智能体，加载此技能，配合本技能包含的检测脚本
- 优先推荐编程类智能体：Trae、Qoder、Claude Code、Codex
- 次选：龙虾类智能体


## 注意事项

- 仅用于授权的安全测试，请勿用于非法用途
- 不建议直接对生产系统做动态验证；如必须测试，请先做好隔离和备份
- `Stage 2` 需要目标 URL；若接口需要登录态，还需要准备凭证或人工登录会话


## 环境运行依赖

### Python

建议使用 Python 3.10+

安装依赖：
```bash
pip install -r vibe-csa/scripts/requirements.txt
```

需要的 Python 包：
- `jsonschema`
- `requests`
- `urllib3`
- `python-docx`
- `matplotlib`

### 多Agent智能体

- 参考`sub_agent.md`创建多智能体，可有效提高代码审计、漏洞验证的速度和质量

## 执行步骤

### 1. 静态审计

多 agent 并行分析源码，输出单个 finding JSON 到 `workDir/agent-results/`，再合并为 `workDir/static-merged.json`。

### 2. 动态验证

可选。根据静态结果生成 PoC，并在目标环境中验证漏洞是否真实存在，输出 `workDir/dynamic-verified.json`。

### 3. 最终报告

最终 JSON 生成后，再导出 HTML 和 Word 报告。

## Multi-Agent

推荐的静态 agent 分工：

- `static-injection`：注入类问题
- `static-auth`：认证、授权、会话
- `static-file-ssrf`：文件操作、SSRF、上传
- `static-deser`：反序列化、JNDI
- `static-logic`：业务逻辑、CSRF、状态流
- `static-info`：信息泄露、加密、配置问题

动态验证 agent：
- `dynamic-verifier`：只处理单个 finding 的 PoC 构造与验证

为保证效果，建议您在 AI Agent 平台上创建这些子 Agent，建议先参考根目录下的 `sub_agent.md`。该文档整理了各子 Agent 的英文标识名、调用时机，以及可直接复制使用的提示词模板。

## 提示词示例

### 静态审计提示词

```text
使用 `vibe-csa` 技能，对当前目录下的源码做静态审计，参考项目语言插件规则，按`multi-agent.md`中的推荐agent分工，每个agent独立生成 `workDir/agent-results/*.json`(格式需严格参考`references/agent-result-example.json`样例)， 最后使用`merge_static_results.py`脚本，汇总multi-agent的结果，生成`workDir/static-merged.json`

将最终JSON报告`vibe-csa-{YYYYMMDD-HHmmss}.json`生成 HTML 和 Word 报告，使用 `scripts/vibe_csa_html.py` 和 `scripts/vibe_csa_report.py` 脚本导出稳定的报告结果。
```

### 静态审计+动态漏洞验证提示词

```text
阶段一：静态审计 
使用 `vibe-csa` 技能，对当前目录下的源码做静态审计，参考项目语言插件规则，按`multi-agent.md`中的推荐agent分工，所有agent并发执行，每个agent独立生成 `workDir/agent-results/*.json`(格式需严格参考`references/agent-result-example.json`样例)， 最后使用`merge_static_results.py`脚本，汇总multi-agent的结果，生成`workDir/static-merged.json`

阶段二：动态漏洞验证
基于 `workDir/static-merged.json` 对严重/高危/抽样中危的 finding 做动态验证。先使用`scripts/prepare_dynamic_pocs.py` 生成最小骨架`workDir/findings/*.poc.json`，再根据实际场景，完善finding文件和PoC内容，最后使用`verify_vuln.py` 合并 finding文件，生成`workDir/dynamic-verified.json`

目标 URL: http://127.0.0.1:8056/admin.php?p=/Index/ucenter
授权声明: 已获得书面授权，授权范围包含该目标全部接口和页面
测试账号（1个）:
账号：admin
密码：123456

安全测试要求：允许对测试过程中自己创建的数据、自己上传的文件、自己插入的记录做删除、更新、清理操作，以便验证删除/编辑/恢复/回收类漏洞；禁止对原始业务数据、他人数据、生产数据做破坏性操作。允许上传文件进行文件上传测试。

阶段三：报告生成
将最终JSON报告`vibe-csa-{YYYYMMDD-HHmmss}.json`生成 HTML 和 Word 报告，使用 `scripts/vibe_csa_html.py` 和 `scripts/vibe_csa_report.py` 脚本导出稳定的报告结果。

```

## 报告生成说明

输出结果在`workDir`工作目录，可以使用以下命令手工执行报表生成：
示例：
```bash
python vibe_csa_html.py -i workDir/reports/vibe-csa-{YYYYMMDD-HHmmss}.json -o workDir/reports/vibe-csa-final.html
python vibe_csa_report.py -i workDir/reports/vibe-csa-{YYYYMMDD-HHmmss}.json -o workDir/reports/vibe-csa-final.docx
```

## 流程示意图
![流程示意图](vibe-csa_v1.0.png)
