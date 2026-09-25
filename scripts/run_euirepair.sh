#!/usr/bin/env bash
set -Eeuo pipefail

# Unified EviRepair entry point.
# The model and benchmark are selected here; the existing Python runners and
# sandbox launchers remain internal implementation details.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/run_euirepair.sh --model MODEL --benchmark BENCHMARK [paths] [options]

MODEL       glm | deepseek | qwen
BENCHMARK   patcheval | secbench

Required environment:
  AGENT_BASE_URL        OpenAI-compatible endpoint, with an optional
                        trailing /chat/completions
  AGENT_API_KEY         API key for the model endpoint
  OPEN_SANDBOX_API_KEY  Sandbox service key

Optional environment:
  PATCHEVAL_API_KEYS    Comma-separated rotating model keys
  PY                    Python interpreter used by the experiment runners

Path options:
  --output-dir PATH         Root directory for generated results
  --patcheval-root PATH     Local PatchEval installation/root
  --patcheval-dataset PATH  PatchEval verified dataset JSON file
  --patcheval-case-list PATH  PatchEval case-list text file
  --secbench-dataset PATH   SEC-bench JSONL dataset
  --secbench-root PATH      SEC-bench repository/source root

Additional options are passed to the selected backend runner.
EOF
}

MODEL_FAMILY=""
BENCHMARK=""
MODEL_NAME=""
OUTPUT_DIR=""
PATCHEVAL_ROOT=""
PATCHEVAL_DATASET=""
PATCHEVAL_CASE_LIST=""
SECBENCH_DATASET_PATH=""
SECBENCH_ROOT_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model)
      MODEL_FAMILY="${2:?missing value for --model}"
      shift 2
      ;;
    --benchmark)
      BENCHMARK="${2:?missing value for --benchmark}"
      shift 2
      ;;
    --model-name)
      MODEL_NAME="${2:?missing value for --model-name}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing value for --output-dir}"
      shift 2
      ;;
    --patcheval-root)
      PATCHEVAL_ROOT="${2:?missing value for --patcheval-root}"
      shift 2
      ;;
    --patcheval-dataset)
      PATCHEVAL_DATASET="${2:?missing value for --patcheval-dataset}"
      shift 2
      ;;
    --patcheval-case-list)
      PATCHEVAL_CASE_LIST="${2:?missing value for --patcheval-case-list}"
      shift 2
      ;;
    --secbench-dataset)
      SECBENCH_DATASET_PATH="${2:?missing value for --secbench-dataset}"
      shift 2
      ;;
    --secbench-root)
      SECBENCH_ROOT_PATH="${2:?missing value for --secbench-root}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

if [[ -z "${MODEL_FAMILY}" || -z "${BENCHMARK}" ]]; then
  usage >&2
  exit 2
fi

case "${MODEL_FAMILY}" in
  glm)      MODEL_NAME="${MODEL_NAME:-glm-5.2}" ;;
  deepseek) MODEL_NAME="${MODEL_NAME:-deepseek-v4.1-flash}" ;;
  qwen)     MODEL_NAME="${MODEL_NAME:-qwen3.8-27b-fp8}" ;;
  *)
    echo "Unsupported model: ${MODEL_FAMILY}. Choose glm, deepseek, or qwen." >&2
    exit 2
    ;;
esac

case "${BENCHMARK}" in
  patcheval|secbench) ;;
  *)
    echo "Unsupported benchmark: ${BENCHMARK}. Choose patcheval or secbench." >&2
    exit 2
    ;;
esac

: "${AGENT_BASE_URL:?AGENT_BASE_URL is required}"
: "${AGENT_API_KEY:?AGENT_API_KEY is required}"
: "${OPEN_SANDBOX_API_KEY:?OPEN_SANDBOX_API_KEY is required}"

# The Python runners expect the OpenAI-compatible base URL rather than the
# full Chat Completions path. The shell launchers perform the same cleanup.
BASE_URL="${AGENT_BASE_URL%/chat/completions}"
export MODEL="${MODEL_NAME}"
export PATCHEVAL_REMOTE_MODEL="${MODEL_NAME}"
export GLM_API_BASE="${BASE_URL}"
export GLM_BASE_URL="${BASE_URL}"
export GLM_API_KEY="${AGENT_API_KEY}"
export PATCHEVAL_API_KEYS="${PATCHEVAL_API_KEYS:-${AGENT_API_KEY}}"
AGENT_MODEL="openai/${MODEL_NAME}"

if [[ -n "${OUTPUT_DIR}" ]]; then
  export RUN_BASE="${OUTPUT_DIR}"
fi
if [[ -n "${PATCHEVAL_ROOT}" ]]; then
  export PATCH_EVAL="${PATCHEVAL_ROOT}"
  export VERIFIED_PATCH_EVAL="${PATCHEVAL_ROOT}"
fi
if [[ -n "${PATCHEVAL_DATASET}" ]]; then
  export VERIFIED_DATASET="${PATCHEVAL_DATASET}"
fi
if [[ -n "${PATCHEVAL_CASE_LIST}" ]]; then
  export PATCHEVAL_CASE_LIST
  export CVE_LIST_FILE="${PATCHEVAL_CASE_LIST}"
fi
if [[ -n "${SECBENCH_DATASET_PATH}" ]]; then
  export SECBENCH_DATASET="${SECBENCH_DATASET_PATH}"
fi
if [[ -n "${SECBENCH_ROOT_PATH}" ]]; then
  export SECBENCH_SOURCE_ROOT="${SECBENCH_ROOT_PATH}"
fi

OUTPUT_ARGS=()
if [[ -n "${OUTPUT_DIR}" ]]; then
  OUTPUT_ARGS=(--exp-root "${OUTPUT_DIR}")
fi

case "${MODEL_FAMILY}:${BENCHMARK}" in
  deepseek:patcheval)
    exec "${PY:-python3}" "${SCRIPT_DIR}/run_deepseek_patcheval_230.py" \
      --model "${MODEL_NAME}" --agent-model "${AGENT_MODEL}" \
      --base-url "${BASE_URL}" "${OUTPUT_ARGS[@]}" "$@"
    ;;
  deepseek:secbench)
    exec "${PY:-python3}" "${SCRIPT_DIR}/run_deepseek_secbench.py" \
      --model "${MODEL_NAME}" --agent-model "${AGENT_MODEL}" \
      --base-url "${BASE_URL}" "${OUTPUT_ARGS[@]}" "$@"
    ;;
  qwen:patcheval)
    exec "${PY:-python3}" "${SCRIPT_DIR}/run_qwen_patcheval_230.py" \
      --model "${MODEL_NAME}" --agent-model "${AGENT_MODEL}" \
      --base-url "${BASE_URL}" "${OUTPUT_ARGS[@]}" "$@"
    ;;
  qwen:secbench)
    exec "${PY:-python3}" "${SCRIPT_DIR}/run_qwen_secbench.py" \
      --model "${MODEL_NAME}" --agent-model "${AGENT_MODEL}" \
      --base-url "${BASE_URL}" "${OUTPUT_ARGS[@]}" "$@"
    ;;
  glm:patcheval)
    exec "${SCRIPT_DIR}/launch_d14_repair_mas_directglm_sandbox.sh" "$@"
    ;;
  glm:secbench)
    exec "${SCRIPT_DIR}/launch_d14_secbench_directglm_local.sh" "$@"
    ;;
esac
