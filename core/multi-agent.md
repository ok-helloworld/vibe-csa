# vibe-csa Multi-Agent Index

This file is now a lightweight index. The detailed rules have been split by
stage to keep responsibilities clearer.

## Documents

- Stage 1 static audit: `{SKILL_ROOT}/core/static-multi-agent.md`
- Stage 2 dynamic verification: `{SKILL_ROOT}/core/dynamic-multi-agent.md`

## When To Read

- Read `static-multi-agent.md` when creating or running Stage 1 static agents,
  generating `workDir/agent-results/*.json`, or merging into
  `workDir/static-merged.json`.
- Read `dynamic-multi-agent.md` when creating or running Stage 2
  `dynamic-verifier` agents, claiming work from `workDir/dynamic-state.json`,
  or writing `workDir/findings/FINDING-*.poc.json`.
