# Source And Reachability Worker Task

- task_id: {{TASK_ID}}
- work_dir: {{WORK_DIR}}

## Exact question

{{EXACT_QUESTION}}

## Current hypothesis

{{CURRENT_HYPOTHESIS}}

## Relevant source hints

{{SOURCE_HINTS}}

## Known or suspected entrypoints

{{ENTRYPOINT_HINTS}}

## Available evidence paths

{{EVIDENCE_PATHS}}

## Required work

1. Inspect the relevant production source.
2. Identify attacker-controlled inputs.
3. Trace plausible paths to security-sensitive operations or decisions.
4. Identify validation, normalization, authorization, trust, ownership, or lifecycle controls.
5. Identify the most plausible missing or incorrect control.
6. Check adjacent public or configuration entrypoints that may share the same unsafe assumption.
7. Record alternative explanations and unresolved reachability assumptions.

## Required outputs

- structured JSON: {{OUTPUT_JSON_PATH}}
- concise source trace: {{OUTPUT_MARKDOWN_PATH}}

The JSON must follow the worker system prompt schema.

## Prohibited actions

- Do not modify production source.
- Do not create a repair patch.
- Do not perform broad fuzzing.
- Do not overwrite another worker's artifacts.
- Do not produce the final vulnerability model.
