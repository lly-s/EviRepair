## USER

Please fix the vulnerability in this {{BENCHMARK_NAME}} {{TASK_KIND}} based on the following information:{{PROBLEM_STATEMENT}}

Task runtime information:
{{PATH_POLICY}}
{{FINAL_PATCH_INSTRUCTIONS}}

Repair-source practice:
- Rely on the canonical vulnerability model and repository-local artifacts for repair evidence.
- Prefer local inspection, builds, and tests under the target workdir when validating a candidate.

## Canonical analysis handoff

Use this file as the primary and initially sufficient vulnerability-analysis input:

`{{WORK_DIR}}/.vulnerability-analysis/vulnerability_model.json`

Prefer reading that file first. Read only narrowly relevant artifacts explicitly referenced by the canonical model when a concrete repair, test-interpretation, or refinement question needs them.

The canonical model follows the required vulnerability handoff schema and includes repair-facing fields for:

- vulnerability summary;
- root cause;
- attack path;
- security boundary;
- repair guidance;
- review context.

## Coordinated repair task

Use the delegated repair workflow with the Repair MAS task templates:

- `prompts/repair_mas/tasks/patch_generator.task.md`
- `prompts/repair_mas/tasks/patch_reviewer.task.md`

Every subagent invocation should use the corresponding template, filled with the current handoff-derived fields and required output paths.

Maintain repair artifacts under:

`{{WORK_DIR}}/.repair/`

Including:

- `repair_state.json`
- `validation_matrix.json`
- `candidate.patch`
- `patch_review_findings.json`

### Validation matrix expectation

Project matrix rows from the analysis handoff before the first generation attempt:

- violating / legitimate / negative / boundary-neighbor cases;
- compatibility requirements;
- validation requirements;
- actionable coverage-gap closure rows;
- build/load and clean-apply checks needed for final selection;
- any unresolved boundary dimensions named by the handoff.

The leader initializes the skeleton. The generator fills execution evidence for rows it runs. The reviewer marks review acceptance on blocking rows and uses the matrix as the primary validation surface.

### Subagent coordination

Coordinate:

- `patch_generator` for focused implementation and matrix execution updates;
- `patch_reviewer` for full validation of the current candidate across the reviewer dimensions.

Put refinement focus notes in generator tasks. Fill reviewer tasks from the current handoff and current candidate for a full validation each time.

## User Task

Produce a minimal secure repair for the described vulnerability through an explicit delegated refinement loop.

The repair accounts for:

- benchmark-specific validation instructions supplied below;
- repository-native general build, test, and load checks when applicable;
- the validated vulnerability reproducer and oracle from the analysis handoff;
- legitimate controls, normal-task cases, boundary-adjacent cases, and compatibility requirements;
- clean application and build/load behavior in a clean Docker or clean-worktree environment;
- a review-approved validation matrix.

Benchmark-specific validation instructions:
{{VALIDATION_INSTRUCTIONS}}

Produce the first best-supported candidate patch as soon as a focused source change is available. Keep that patch on disk while validation and review continue, and replace it when a stronger candidate is selected.

For each repair attempt:

1. test it using phase-aware oracle semantics; treat baseline-oriented scripts according to their intended phase rather than by exit code alone;
2. verify patch coupling: a post-patch security claim comes from a test that executes or imports the current patched worktree, or from an explicitly limited source-qualified substitute recorded in the matrix;
3. run the Patch Reviewer role against the vulnerability model, current patch, and validation matrix;
4. diagnose every failed gate using the reviewer dimension results;
5. refine the patch, matrix evidence, or narrowly supported repair premise;
6. repeat until the required gates pass or the bounded refinement budget is exhausted.

A failed security, build/load, compatibility, or matrix gate leads to another refinement attempt unless the failure is shown to be an invalid test or unavailable environment; record that decision.

Always write the selected final or best-supported unified diff to:

- `{{FINAL_PATCH_PATH}}`

The file contains a unified diff generated from the target workdir.

After writing that file, clean-apply `{{FINAL_PATCH_PATH}}` to the recorded baseline and repeat the critical vulnerability and compatibility review checks against the applied patch. If those checks expose a patch defect, return to refinement and regenerate the file.

Finish only after creating and clean-apply-checking `{{FINAL_PATCH_PATH}}` and writing the required repair-state, matrix, and review artifacts.
