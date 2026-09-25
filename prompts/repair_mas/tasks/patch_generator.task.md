# Patch Generator Task

- task_id: {{TASK_ID}}
- work_dir: {{WORK_DIR}}

## Exact repair question

{{EXACT_QUESTION}}

## Canonical analysis handoff

- vulnerability model: {{VULNERABILITY_MODEL_PATH}}
- repair state: {{REPAIR_STATE_PATH}}
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

## Focus for this delegation

{{FOCUS_NOTES}}

## Allowed edit scope

{{ALLOWED_EDIT_SCOPE}}

## Required work

1. Read the canonical vulnerability model and the repair artifacts named above.
2. Implement a minimal repair that restores the expected secure behavior and boundary predicate.
3. Satisfy the instance obligations, must-block cases, and compatibility requirements.
4. Execute or update the relevant validation-matrix rows on the patched worktree when feasible.
5. Write the candidate patch and a concise implementation rationale.

## Required outputs

- candidate patch: {{CANDIDATE_PATCH_PATH}}
- validation matrix updates: {{VALIDATION_MATRIX_PATH}}
- implementation note path: {{IMPLEMENTATION_NOTE_PATH}}
- structured result JSON: {{OUTPUT_JSON_PATH}}

The structured result should follow the generator system prompt schema.
