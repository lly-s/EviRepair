# EviRepair

Anonymous code release for peer review.

EviRepair is an evidence-driven multi-agent framework for repository-level automated vulnerability repair from sparse vulnerability reports. The framework separates the repair process into two coordinated stages: evidence reconstruction and patch development. Specialized agents analyze source reachability, reproducibility, security boundaries, and affected behavior, after which a reviewed vulnerability model guides patch generation and patch review.

The release provides the English prompts, structured agent communication schemas, and experiment runners used with PatchEval and SEC-bench. The runners support GLM-compatible OpenAI-style endpoints, DeepSeek, and Qwen through the OpenCode-based repair workflow.

## Repository contents

```text
prompts/    English prompts for analysis and patch development
schema/     Vulnerability-model and agent-communication schemas
scripts/    Model runners, sandbox launchers, and evaluation utilities
```

The main prompt groups are:

```text
prompts/analysis_mas/    Vulnerability evidence reconstruction
prompts/repair_mas/      Patch generation and patch review
```

The unified experiment entry point is:

```text
scripts/run_euirepair.sh
```

## Installation

The reference environment uses Python 3.10 or later, Bash, and the sandbox dependencies required by the selected evaluation workflow.

Before running an experiment, download the PatchEval and SEC-bench datasets, obtain the corresponding target repository snapshots, and prepare the required Python and sandbox environments. Configure the dataset paths, repository paths, model endpoint, model identifier, and API credentials for the local environment.

## Running the experiments

All three supported model families use the same entry point and the same multi-agent repair and benchmark-evaluation workflow. Before running an experiment, configure the model endpoint, API credentials, sandbox service key, local dataset paths, repository snapshots, and Python environment.

The model and benchmark are selected with two arguments:

```bash
bash scripts/run_euirepair.sh --model deepseek --benchmark patcheval
bash scripts/run_euirepair.sh --model qwen --benchmark secbench
bash scripts/run_euirepair.sh --model glm --benchmark patcheval
```

The supported model families are `glm`, `deepseek`, and `qwen`. The supported benchmarks are `patcheval` and `secbench`. The unified launcher passes the selected configuration to the internal repair and evaluation components, including patch generation, retry handling, official benchmark scoring, and result recording.

The downloaded resources are supplied through path options. A typical local layout is:

```text
/data/
├── PatchEval/              PatchEval installation and evaluation code
├── patcheval_verified.json  Verified PatchEval dataset
├── patcheval_cases.txt      List of PatchEval case IDs
├── SEC-bench/               SEC-bench source/repository snapshots
└── eval-secbench.jsonl      SEC-bench dataset
```

For example:

```bash
export AGENT_BASE_URL="https://your-endpoint.example/v1/chat/completions"
export AGENT_API_KEY="your-model-api-key"
export OPEN_SANDBOX_API_KEY="your-sandbox-api-key"

bash scripts/run_euirepair.sh \
  --model deepseek \
  --benchmark patcheval \
  --output-dir /data/results/deepseek-patcheval \
  --patcheval-root /data/PatchEval \
  --patcheval-dataset /data/patcheval_verified.json \
  --patcheval-case-list /data/patcheval_cases.txt
```

For SEC-bench, replace the benchmark and dataset options:

```bash
bash scripts/run_euirepair.sh \
  --model qwen \
  --benchmark secbench \
  --output-dir /data/results/qwen-secbench \
  --secbench-dataset /data/eval-secbench.jsonl \
  --secbench-root /data/SEC-bench
```

`--output-dir` is the root directory for generated logs, intermediate artifacts, patches, and evaluation results. The launcher creates the directory when needed. The dataset files and repository snapshots must be downloaded and prepared before running the command.

The launcher accepts additional options and forwards them to the selected evaluation workflow. Run the following command to see the common options:

```bash
bash scripts/run_euirepair.sh --help
```

## Reproducibility

To reproduce the reported experiments, download the required benchmark data and repository snapshots, prepare the execution environment, configure an accessible model endpoint, and run the corresponding PatchEval or SEC-bench entry point. The schemas and English prompts in this repository define the structured communication and evidence-review workflow used by the agents.

Do not commit API keys, access tokens, private endpoints, or machine-specific paths when adapting the configuration to a local environment.
