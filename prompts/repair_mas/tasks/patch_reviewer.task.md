# Patch Reviewer Task

- task_id: {{TASK_ID}}
- work_dir: {{WORK_DIR}}

## Exact review question

{{EXACT_QUESTION}}

## Canonical analysis handoff

- vulnerability model: {{VULNERABILITY_MODEL_PATH}}
- validation matrix: {{VALIDATION_MATRIX_PATH}}

## Current repair mode

{{REPAIR_MODE}}

## Root cause summary

{{ROOT_CAUSE_SUMMARY}}

## Expected secure behavior

{{EXPECTED_SECURE_BEHAVIOR}}

## Security boundary predicate

{{SECURITY_BOUNDARY_PREDICATE}}

## Attack path summary

{{ATTACK_PATH_SUMMARY}}

## Target locations

{{TARGET_LOCATIONS}}

## Instance obligations

{{INSTANCE_OBLIGATIONS}}

## Compatibility requirements

{{COMPATIBILITY_REQUIREMENTS}}

## Validation requirements

{{VALIDATION_REQUIREMENTS}}

## Must-preserve controls

{{MUST_PRESERVE_CONTROLS}}

## Must-block or reject cases

{{MUST_BLOCK_OR_REJECT_CASES}}

## Coverage gaps from analysis

{{COVERAGE_GAPS}}

## Critical questions

{{CRITICAL_QUESTIONS}}

## Candidate under review

- candidate patch: {{CANDIDATE_PATCH_PATH}}

## Required work

1. Read the canonical vulnerability model and the repair artifacts named above.
2. Validate the current candidate patch in full against the analysis commitments.
3. Walk the full validation matrix and record review status on blocking rows.
4. Evaluate every required review dimension with evidence references.
5. Apply the reviewer checklist and return a structured verdict with refinement guidance.

## Required outputs

- review findings JSON: {{FINDINGS_OUTPUT_PATH}}
- validation matrix review updates: {{VALIDATION_MATRIX_PATH}}

The findings JSON must follow the reviewer system prompt schema and include all required dimensions.
