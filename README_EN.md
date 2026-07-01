<div align="center">

[中文](./README.md) | [English](./README_EN.md)

</div>

# Vibe CSA

> Current Version: v1.0.16

Vibe CSA (Code Security Audit) is a code audit tool based on AI Agent architecture, adopting a multi-Agent parallel execution architecture. It statically audits source code with a "God's eye view" and dynamically verifies vulnerabilities through "combat simulation", ensuring the comprehensiveness and accuracy of Web vulnerability discovery, outputting stable and reliable security reports, and providing actionable remediation recommendations. Main capabilities: AI Code Audit and AI Vulnerability Assessment.

Project Features:
- `Stage 1`: Static audit based on source code and language plugins
- `Stage 2`: Dynamic verification of single vulnerabilities based on static findings
- `Stage 3`: Generate standard JSON and export HTML / Word reports

## Table of Contents

- [Who Is It For](#who-is-it-for)
- [Important Notes](#important-notes)
- [Quick Start](#quick-start)
- [Environment Dependencies](#environment-dependencies)
- [Working Directory & Report Output](#working-directory--report-output)
- [Prompt Examples](#prompt-examples)
- [Workflow Diagram](#workflow-diagram)

## Who Is It For

Suitable for the following two types of users:
- Software developers for Web-related security self-inspection
- Cybersecurity professionals for third-party Web security assessment

Use AI agents to load this skill and work with the detection scripts included in this skill:
- 3-minute tutorial video: [bilibili.com/video/BV1RiGX6rESQ/](https://www.bilibili.com/video/BV1RiGX6rESQ/)
- Recommended: Programming AI agents such as Qoder, Claude Codex, OpenCode, workbuddy, etc.
- Alternative: Lobster-type agents

## Important Notes

- Only for authorized security testing, do not use for illegal purposes
- Not recommended for dynamic verification on production systems; if testing is necessary, please ensure isolation and backup first

## Quick Start

Please install the `Git` source code management tool first: [git-scm.com](https://git-scm.com/)

After installing `Git`, you can let the AI agent automatically install this skill and environment dependencies by sending the following prompt:

```text
Help me install the vibe-csa skill (including environment dependencies), repository: https://gitee.com/ok-helloworld/vibe-csa
```


## Environment Dependencies

### Git

It is strongly recommended to install Git first and use `git clone` to obtain this project. Do not use the web page download ZIP compressed package method.

It is recommended to clone from Gitee first for smoother access:

```bash
git clone https://gitee.com/ok-helloworld/vibe-csa
```

Reasons for recommendation:

- Only the Git repository method can work with the auto-update mechanism in the project to continuously obtain the latest skill rules, script capabilities, and reference materials
- This allows AI agents to continuously obtain the latest penetration testing processes, detection methods, and capability enhancements

### Python

Python 3.10+ is recommended

Install dependencies:

```bash
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple playwright jsonschema requests urllib3 python-docx matplotlib httpx charset-normalizer chardet
playwright install chromium
```

### Multi-Agent System

Creating a multi-Agent system can effectively improve the speed and quality of code audit and vulnerability verification:
- When calling this skill to run, it will automatically create a multi-Agent system (can be skipped during installation)
- If you want to create it manually later, you can refer to `references/sub_agents`, which contains 8 sub-Agent definitions

## Working Directory & Report Output

All outputs from this skill will be written to the `workDir/` folder in the current working directory, with the final report located in `workDir/reports/`.

It is recommended to use a separate working directory for each code audit task to facilitate distinguishing intermediate files and final reports for different tasks.

## Prompt Examples

### Static Audit Prompt

```text
Use the `vibe-csa` skill to perform static audit on the source code in the current directory, simultaneously launching 7 static audit agents for concurrent divisional audit. Each agent independently generates `workDir/agent-results/*.json`, and finally use the `merge_static_results.py` script to aggregate results, generating `workDir/static-merged.json`, and use the script to remove duplicate vulnerability items

Generate HTML and Word reports from the final JSON report: use the `scripts/vibe_csa_html.py` and `scripts/vibe_csa_report.py` scripts to export stable report results.
```

### Static Audit + Dynamic Vulnerability Verification Prompt

```text
Stage 1: Static Audit
Use the `vibe-csa` skill to perform static audit on the source code in the current directory, simultaneously launching 7 static audit agents for concurrent divisional audit. Each agent independently generates `workDir/agent-results/*.json`, and finally use the `merge_static_results.py` script to aggregate results, generating `workDir/static-merged.json`, and use the script to remove duplicate vulnerability items

Stage 2: Dynamic Vulnerability Verification
Only perform dynamic verification on "critical/high-risk/sampled medium-risk" vulnerabilities found in static audit: first use `scripts/prepare_dynamic_pocs.py` to simultaneously generate `workDir/static-findings/FINDING-*.json`, `workDir/dynamic-findings/FINDING-*.json` and `workDir/dynamic-state.json`, then launch `1~5` `dynamic-verifier` custom sub-Agents for concurrent vulnerability verification, based on the verification queue in `dynamic-state.json`, read the corresponding static reference files and only write back dynamic finding files; after all are completed, use the script to aggregate and generate `workDir/dynamic-verified.json`

Target URL: https://example.com
Authorization Statement: Written authorization obtained, authorization scope covers all interfaces and pages of the target
Test Account (1):
Username: admin
Password: 123456
Login Method: You call the script to open the browser, I will manually enter the username and password to log in

White hat professional ethics: Allowed to delete, update, and clean up data created by yourself, files uploaded by yourself, and records inserted by yourself during the testing process, in order to verify deletion/editing/recovery/recycling vulnerabilities; prohibited from performing destructive operations on original business data, others' data, and production data. Allowed to upload files for file upload testing.

Stage 3: Report Generation
Generate HTML and Word reports from the final JSON report: use the `scripts/vibe_csa_html.py` and `scripts/vibe_csa_report.py` scripts to export stable report results.

```
