# Reproducer Worker Task

- task_id: {{TASK_ID}}
- work_dir: {{WORK_DIR}}

## Exact runtime question

{{EXACT_QUESTION}}

## Current hypothesis

{{CURRENT_HYPOTHESIS}}

## Candidate source path or mechanism

{{CANDIDATE_SOURCE_PATH}}

## Discovered build and run information

{{BUILD_RUN_INFORMATION}}

## Initial testcase idea

{{INITIAL_TESTCASE_IDEA}}

## Proposed oracle hypothesis

{{ORACLE_HYPOTHESIS}}

## Available evidence paths

{{EVIDENCE_PATHS}}

## Required work

1. Determine the smallest practical way to execute the suspected path.
2. Define a security-relevant, phase-aware oracle before claiming success.
3. State separately what proves vulnerable-baseline success, patched-secure success, and patched insecurity; do not rely on exit code alone unless explicitly justified.
4. Record whether the testcase executes/imports current worktree production code and whether it is valid for post-patch verification; mark standalone models and source simulations as baseline-only.
5. Construct or refine a candidate reproducer.
6. Record exact commands, runtime requirements, and environment assumptions.
7. Run enough repetitions to characterize stability when feasible.
8. Minimize irrelevant testcase dimensions without losing the observed property.
9. Record alternative explanations and limitations.

## Required outputs

- structured JSON: {{OUTPUT_JSON_PATH}}
- candidate reproducer script: {{REPRODUCER_SCRIPT_PATH}}
- candidate oracle JSON: {{ORACLE_JSON_PATH}}
- testcase directory: {{TESTCASE_OUTPUT_DIR}}
- runtime logs directory: {{LOG_OUTPUT_DIR}}

If no credible runnable reproducer can be created, leave the script absent and explain why in the JSON.

## Prohibited actions

- Do not modify production source.
- Do not patch the vulnerability.
- Do not weaken security controls to manufacture a result.
- Do not modify project tests as proof.
- Do not call the candidate independently verified.
- Do not produce the final vulnerability model.
