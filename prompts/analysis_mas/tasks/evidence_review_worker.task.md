# Evidence Review Worker Task

- task_id: {{TASK_ID}}
- work_dir: {{WORK_DIR}}

## Proposed conclusion

{{PROPOSED_CONCLUSION}}

## Claims requiring review

{{CLAIMS_TO_CHALLENGE}}

## Known uncertainties

{{KNOWN_UNCERTAINTIES}}

## Evidence artifact paths

{{EVIDENCE_PATHS}}

## Required work

1. Inspect the proposed conclusion and all supplied evidence.
2. Check whether public reachability is supported.
3. Check whether the oracle is security-relevant and phase-aware; verify that vulnerable-baseline success cannot be misread as patched-secure success from exit code or a generic `PASS` label.
4. Check patch coupling: determine whether the reproducer executes current worktree production code or is only a standalone model/source simulation unsuitable for post-patch validation.
5. Check whether the claimed root cause explains the observed behavior.
6. Check whether legitimate controls exercise the same relevant functionality.
7. Check whether the inferred boundary is supported rather than guessed.
8. Check environment and dependency assumptions.
9. Identify alternative explanations and fatal contradictions.
10. Recommend an analysis status and confidence.

You may run a small number of targeted commands to verify critical claims.

## Required output

- structured JSON: {{OUTPUT_JSON_PATH}}

The JSON must follow the worker system prompt schema.

## Prohibited actions

- Do not modify production source.
- Do not construct a repair patch.
- Do not redo broad exploration or fuzzing.
- Do not create the final vulnerability model.
- Do not accept claims merely because multiple agents agree.
