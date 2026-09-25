## USER

Please analyze the vulnerability in this {{BENCHMARK_NAME}} {{TASK_KIND}} based on the following information:{{PROBLEM_STATEMENT}}

Task runtime information:
{{PATH_POLICY}}

Repair-source restrictions:
{{REPAIR_SOURCE_RESTRICTIONS}}

## Analysis Role and Task

Perform the complete vulnerability analysis workflow for the described issue.

Use only the repository and environment available under `{{WORK_DIR}}` for instance-specific facts.

Treat this as the analysis-only pass for the repository repair workflow.

Do not modify production source code or create a repair in this stage.

Write all analysis artifacts under:

`{{WORK_DIR}}/.vulnerability-analysis/`

The canonical final artifact must be:

`{{WORK_DIR}}/.vulnerability-analysis/vulnerability_model.json`
