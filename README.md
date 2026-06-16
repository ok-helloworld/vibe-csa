# Vibe CSA

> 当前版本：v1.0.15

Vibe CSA (Code Security Audit)，是一款基于 AI Agent 架构的代码审计工具，采用多 Agent 并行执行架构，用“上帝视角”静态审计源代码，用“实战模拟”动态验证漏洞，保证了 Web 漏洞挖掘的全面性和准确性，输出稳定可靠的安全报告，并提供可落地整改建议。主要能力：AI 代码审计和 AI 漏洞评估。

项目特点：
- `Stage 1`：基于源码和语言插件做静态审计
- `Stage 2`：基于静态 finding 做单漏洞动态验证
- `Stage 3`：生成标准 JSON，并导出 HTML / Word 报告

## 目录

- [适合谁](#适合谁)
- [注意事项](#注意事项)
- [快速开始](#快速开始)
- [环境运行依赖](#环境运行依赖)
- [工作目录与报告输出](#工作目录与报告输出)
- [提示词示例](#提示词示例)
- [流程示意图](#流程示意图)

## 适合谁

适合以下两类用户：
- 适合软件开发人员，用于 Web 相关的安全自检
- 适合网络安全从业者，用于第三方的 Web 安全检测

使用 AI 智能体加载此技能，并配合本技能包含的检测脚本：
- 3 分钟使用教程视频：[bilibili.com/video/BV1RiGX6rESQ/](https://www.bilibili.com/video/BV1RiGX6rESQ/)
- 优先推荐编程类智能体：Qoder、Claude Codex、OpenCode、workbuddy 等
- 次选：龙虾类智能体

## 注意事项

- 仅用于授权的安全测试，请勿用于非法用途
- 不建议直接对生产系统做动态验证；如必须测试，请先做好隔离和备份

## 快速开始

请先手工安装 `Git` 代码管理软件工具：[git-scm.com](https://git-scm.com/)

`Git` 工具安装完成后，就可以让 AI 智能体自动安装本技能和环境依赖，可以直接发送下面这段提示词：

```text
帮我安装 vibe-csa skill（包括环境运行依赖），仓库地址：https://gitee.com/ok-helloworld/vibe-csa
```


## 环境运行依赖

### Git

强烈推荐先安装 Git，并使用 `git clone` 获取本项目，不要使用网页下载 ZIP 压缩包的方式使用项目。

推荐优先从 Gitee 克隆，访问更顺畅：

```bash
git clone https://gitee.com/ok-helloworld/vibe-csa
```

推荐原因：

- 只有 Git 仓库方式才能配合项目内的自动更新机制，持续获取最新的技能规则、脚本能力和参考资料
- 这样可以让 AI 智能体持续获得最新的渗透测试流程、检测方法和能力增强

### Python

建议使用 Python 3.10+

安装依赖：

```bash
pip install playwright jsonschema requests urllib3 python-docx matplotlib httpx charset-normalizer chardet
playwright install chromium
```

### 多 Agent 智能体

创建多 Agent 智能体，可有效提高代码审计、漏洞验证的速度和质量：
- 调用本技能运行时，会自动创建多 Agent 智能体（安装时可略过）
- 如果后续想手工创建，可参考 `references/sub_agents`，共 8 个子 Agent 定义

## 工作目录与报告输出

本技能的所有输出都会写入到当前工作目录下的 `workDir/` 文件夹，最终报告位于 `workDir/reports/`。

建议每个代码审计任务使用单独的工作目录，方便区分不同任务的中间文件和最终报告。

## 提示词示例

### 静态审计提示词

```text
使用 `vibe-csa` 技能，对当前目录下的源码做静态审计，同时启动 7 个静态审计 agent 并发执行分工审计，每个 agent 独立生成 `workDir/agent-results/*.json` ，最后使用 `merge_static_results.py` 脚本汇总结果，生成 `workDir/static-merged.json`，并使用脚本去除重复漏洞项

将最终 JSON 报告生成 HTML 和 Word 报告：使用 `scripts/vibe_csa_html.py` 和 `scripts/vibe_csa_report.py` 脚本导出稳定的报告结果。
```

### 静态审计+动态漏洞验证提示词

```text
阶段一：静态审计
使用 `vibe-csa` 技能，对当前目录下的源码做静态审计，同时启动 7 个静态审计 agent 并发执行分工审计，每个 agent 独立生成 `workDir/agent-results/*.json` ，最后使用 `merge_static_results.py` 脚本汇总结果，生成 `workDir/static-merged.json`，并使用脚本去除重复漏洞项

阶段二：动态漏洞验证
只对静态审计到的“严重/高危/抽样中危”的漏洞进行动态验证：先使用 `scripts/prepare_dynamic_pocs.py` 同时生成 `workDir/static-findings/FINDING-*.json`、`workDir/dynamic-findings/FINDING-*.json` 和 `workDir/dynamic-state.json`，再启动 `1~5` 个 `dynamic-verifier` 自定义子 Agent 并发执行漏洞验证，基于 `dynamic-state.json` 的验证队列，读取对应静态参考文件并只回写动态 finding 文件；全部完成后，再使用脚本汇总生成 `workDir/dynamic-verified.json`

目标 URL: https://example.com
授权声明: 已获得书面授权，授权范围包含该目标全部接口和页面
测试账号（1个）:
账号：admin
密码：123456
登录方式：你调用脚本打开浏览器，我手动输入账号密码登录

白帽子职业操守：允许对测试过程中自己创建的数据、自己上传的文件、自己插入的记录做删除、更新、清理操作，以便验证删除/编辑/恢复/回收类漏洞；禁止对原始业务数据、他人数据、生产数据做破坏性操作。允许上传文件进行文件上传测试。

阶段三：报告生成
将最终 JSON 报告生成 HTML 和 Word 报告：使用 `scripts/vibe_csa_html.py` 和 `scripts/vibe_csa_report.py` 脚本导出稳定的报告结果。

```

## 流程示意图
![流程示意图](vibe-csa_v1.0.png)
