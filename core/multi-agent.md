# vibe-csa Multi-Agent Plan

This document defines the agent split used by vibe-csa.

## Stage Boundaries

| Stage | Agent responsibility | Output |
| --- | --- | --- |
| Stage 1 static audit | Parallel domain agents inspect source code | `workDir/agent-results/*.json` and `workDir/static-merged.json` |
| Stage 2 dynamic verification (optional) | `dynamic-verifier` builds and validates PoC for a single finding | `workDir/findings/*.poc.json` and `workDir/dynamic-verified.json` |
| Stage 3 report generation | Script-based validation and final report output | `workDir/reports/vibe-csa-{timestamp}.json` |

Static agents must never write runtime responses. In static-only mode, `poc.steps` must be empty and `poc.result` must remain `pending`.

## Stage 1 Agent Split

| Agent | Domain | Focus |
| --- | --- | --- |
| `static-injection` | Injection | SQL injection, command injection, code injection, SSTI, expression injection, LDAP/XPath injection |
| `static-auth` | Auth and authorization | Login bypass, IDOR, privilege escalation, session/JWT/OAuth issues |
| `static-file-ssrf` | Request forgery and file access | SSRF, upload, arbitrary file read/write, path traversal, file inclusion, XXE |
| `static-deser` | Deserialization | Java/PHP/Python deserialization, JNDI, object injection, dangerous gadget chains |
| `static-logic` | Business logic | Payment tampering, state bypass, race conditions, CSRF, webhook forgery, bulk abuse |
| `static-info` | Information disclosure and crypto | Key leakage, weak crypto, debug interfaces, error leakage, CORS, security headers |

Smaller projects should start at least 4 agents. Standard and deep modes should usually start all 6.

## Stage 1 Output Contract

Each agent writes one JSON file:

```text
workDir/agent-results/agent-{name}.json
```

Each file must use the shared v3 top-level structure:

```json
{
  "schema_version": "3.0",
  "audit": {
    "stage": "static_audit"
  },
  "findings": []
}
```

## Generate Static Skeleton

Before starting the audit, each static agent must use
`{SKILL_ROOT}/scripts/prepare_static_aegnt_result.py` to generate its
static-audit skeleton file first.

Example:

```bash
python {SKILL_ROOT}/scripts/prepare_static_aegnt_result.py {agent_name}
```

The skeleton file is written to:

```text
workDir/agent-results/agent-{name}.json
```

The agent must then write the audit result back into that skeleton file and
fill every field before Stage 1 finishes.

The generated skeleton file is the only allowed Stage 1 output base for that
agent. The agent must write back to the same file path and must not discard the
skeleton structure and replace it with ad-hoc JSON. If the file is overwritten,
the final content must still preserve the skeleton field set, canonical field
names, and object structure.

Agent findings may be completed incrementally during analysis, but before Stage
1 finishes each finding must be complete enough to support Stage 2. Static
findings must include:

- Chinese `title`
- Chinese `vuln_type`
- internal `category`
- `location.file/line_start/snippet`
- `analysis.source`
- `analysis.sink`
- `analysis.data_flow`
- `analysis.attack_surface`
- `analysis.preconditions`
- `analysis.security_controls`
- `analysis.bypass_strategy`
- `analysis.verification_plan`
- `static_evidence.evidence_refs`
- `static_evidence.anti_false_positive`
- `remediation`
- `fix`

## Output Requirement

- Use `{SKILL_ROOT}/references/agent-result-example.json` as the write-back
  example and `{SKILL_ROOT}/core/report-format.md` as the normative field
  contract
- Write real audit results back into
  `workDir/agent-results/agent-{name}.json`, preserve the generated skeleton
  structure, and complete every field that appears in the skeleton file
- `findings` may contain one or more items according to the real audit results

Field alignment:

- Stage 1 field naming, enums, object shapes, and canonical fields such as
  `vuln_id`, `vuln_type`, `location.*`, `analysis.*`,
  `static_evidence.*`, `poc.*`, `remediation`, and `fix` must stay aligned
  with `{SKILL_ROOT}/core/report-format.md`
- Do not replace canonical fields with legacy flat fields such as `id`, `type`,
  `file`, `line`, `snippet`, `data_flow`, or `controls_observed`, and do not
  invent alternate top-level metadata such as `agent_id`, `audit_phase`,
  `audit_scope`, or non-v3 `schema_version` values
- If a field appears in the generated skeleton file, it must be written back
- If a field is optional in `report-format.md` and does not appear in the
  generated skeleton file, it may be omitted; if present, it must still follow
  the same field name and structure

Static agents must not:

- fill `poc.steps[].response`
- mark a code-only finding as `CONFIRMED`
- set `finding_class` to `runtime_verified`
- invent `evidence_level=L2/L3` without runtime proof
- write the final report directly

## Merge Rule

The orchestrator merges all Stage 1 agent JSON files with:

```bash
python {SKILL_ROOT}/scripts/merge_static_results.py \
  --input-dir workDir/agent-results \
  --output workDir/static-merged.json \
  --source-path {source_path} \
  --target-url {target_url}
```

Duplicate handling:

| Condition | Behavior |
| --- | --- |
| same `file + line_start + vuln_type` | treat as duplicate, keep higher-confidence item and merge evidence refs / reviewed files |
| same `file + line_start` but different `vuln_type` | keep both |
| same `file + vuln_type` and nearby lines | keep both as related findings |
| different agents give different interpretations | keep both, let report readers or Stage 2 decide |

## Stage 2 Dynamic Verification Agent

This is optional and should be created as a separate `dynamic-verifier` agent.
It reads one finding JSON at a time and does not inherit the static-agent chat history.

Suggested input:

```text
workDir/findings/FINDING-001.poc.json
```

Responsibilities:

1. Re-read source code and confirm route, parameters, auth, and filters.
2. Build or refine `poc.steps[].request` from the static finding.
3. Call `verify_vuln.py` to send the request and write the real `response`.
4. Preserve multiple steps for multi-step exploitation chains.
5. Record complete request and response data, including `raw` fields.
6. Write `dynamic_verification.final_evidence`.
7. When evidence is insufficient, preserve the attempt history and write `failure_log[]`.

Constraints:

- Do not fabricate `response`.
- Do not widen scope beyond the current finding.
- Do not change a static finding to confirmed without runtime proof.
- Keep the finding as `HYPOTHESIS` when proof is incomplete.

Stage 2 output:

- `workDir/findings/FINDING-xxx.poc.json`
- `workDir/dynamic-verified.json`

The Stage 2 pipeline is usually:

```bash
python {SKILL_ROOT}/scripts/prepare_dynamic_pocs.py \
  --input workDir/static-merged.json \
  --output-dir workDir/findings

python {SKILL_ROOT}/scripts/verify_vuln.py \
  workDir/findings/FINDING-001.poc.json \
  --target {target_url} \
  --credentials workDir/sessions/creds.json \
  --role {role}

python {SKILL_ROOT}/scripts/verify_vuln.py \
  --merge workDir/findings/*.poc.json \
  --into workDir/dynamic-verified.json
```

If no dynamic verification is required, skip this stage and go directly to Stage 3.
