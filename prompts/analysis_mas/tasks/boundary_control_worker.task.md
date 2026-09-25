# Boundary And Control Worker Task

- task_id: {{TASK_ID}}
- work_dir: {{WORK_DIR}}

## Exact boundary question

{{EXACT_QUESTION}}

## Current hypothesis

{{CURRENT_HYPOTHESIS}}

## Candidate reproducer

- path: {{REPRODUCER_PATH}}
- command: {{REPRODUCER_COMMAND}}

## Proposed oracle

{{ORACLE_DESCRIPTION}}

## Suspected boundary dimensions

{{BOUNDARY_DIMENSIONS}}

## Legitimate behavior hypothesis

{{LEGITIMATE_BEHAVIOR_HYPOTHESIS}}

## Available evidence paths

{{EVIDENCE_PATHS}}

## Required work

1. Re-run or inspect the candidate reproducer.
2. Identify the dimensions likely responsible for the behavior transition.
3. Vary one dimension at a time where feasible.
4. Construct at least one legitimate control.
5. Construct at least one negative or non-triggering mutation.
6. Construct safe and violating boundary neighbors when feasible.
7. Test alternate semantic encodings or public entrypoints when relevant.
8. Apply the non-instance-specific stress checklist for the relevant vulnerability family: path/file/archive, URL/origin/redirect, authentication/session/token, parser/protocol/command/object-shape, and project-specific state or business-rule dimensions.
9. For each relevant stress family, add a row, explain why an existing row covers it, or record an explicit coverage gap.
10. Construct or source-qualify at least one boundary counterexample: an input that satisfies the current inferred safe predicate but may still violate the vulnerability description, reach a sensitive operation, bypass an existing validator, or cross a trust/protocol boundary. If no such case is found, record how it was ruled out.
11. Record baseline-expected and patched-expected behavior for each case, including whether the case should flip or remain stable.
12. Record compatibility requirements and coverage gaps.
13. Distinguish observed boundary evidence from an inferred predicate.

## Required outputs

- structured JSON: {{OUTPUT_JSON_PATH}}
- boundary matrix JSON: {{BOUNDARY_MATRIX_PATH}}
- control runner script: {{CONTROL_SCRIPT_PATH}}
- testcase directory: {{TESTCASE_OUTPUT_DIR}}
- comparison logs directory: {{LOG_OUTPUT_DIR}}

If controls cannot be executed, still produce a source-qualified matrix and mark observed behavior as unavailable.

## Prohibited actions

- Do not modify production source.
- Do not repair the vulnerability.
- Do not classify a case as legitimate only because it does not crash.
- Do not assume the boundary is numeric.
- Do not overwrite the primary reproducer without preserving it.
- Do not produce the final vulnerability model.
