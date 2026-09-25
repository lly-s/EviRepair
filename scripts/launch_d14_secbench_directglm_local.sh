#!/usr/bin/env bash
set -Eeuo pipefail

normalize_openai_base() {
  local raw="${1%/}"
  if [[ "${raw}" == */v1 ]]; then
    printf '%s\n' "${raw}"
  else
    printf '%s/v1\n' "${raw}"
  fi
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
D_ROOT="${D_ROOT:-$(cd -- "${SCRIPT_DIR}/.." && pwd -P)}"
PATCH_EVAL="${PATCH_EVAL:-/path/to/local/resource"
PY="${PY:-${PATCH_EVAL}/.venv/bin/python}"
SECBENCH_EVAL_PY="${SECBENCH_EVAL_PY:-${D_ROOT}/.venv_secbench_eval/bin/python}"

MODE="${MODE:-subset}"
if [[ "${MODE}" != "smoke" && "${MODE}" != "subset" && "${MODE}" != "full" ]]; then
  echo "MODE must be smoke, subset, or full" >&2
  exit 2
fi

SECBENCH_DATASET="${SECBENCH_DATASET:-${D_ROOT}/sec-datasets/eval-secbench300-cve200-oss100.jsonl}"
SECBENCH_SANDBOX_REGISTRY_PREFIX="${SECBENCH_SANDBOX_REGISTRY_PREFIX:-registry-v2.h.example.invalid/ailab-ai4good1}"
SECBENCH_SANDBOX_IMAGE_REPOSITORY="${SECBENCH_SANDBOX_IMAGE_REPOSITORY:-${SECBENCH_SANDBOX_REGISTRY_PREFIX}/secbench}"
SECBENCH_IMAGE_TEMPLATE="${SECBENCH_IMAGE_TEMPLATE:-}"
if [[ -z "${SECBENCH_IMAGE_TEMPLATE}" ]]; then
  SECBENCH_IMAGE_TEMPLATE="${SECBENCH_SANDBOX_IMAGE_REPOSITORY}:{instance_id}-patch"
fi
SECBENCH_IMAGE_PREFIX="${SECBENCH_IMAGE_PREFIX:-hwiwonlee/secb.eval.x86_64}"
INSTANCE_ID="${INSTANCE_ID:-njs.cve-2022-32414}"
INSTANCE_LIST_FILE="${INSTANCE_LIST_FILE:-${D_ROOT}/sec-datasets/instance_ids.txt}"

STAMP="${STAMP:-$(date +%Y%m%d_%H%M%S)}"
MODEL="${MODEL:-glm-5.2}"
GLM_BASE_URL="${GLM_BASE_URL:-https://api.yuli-cs.net}"
GLM_API_BASE="${GLM_API_BASE:-$(normalize_openai_base "${GLM_BASE_URL}")}"
AGENT_API_KEY_ENV="${AGENT_API_KEY_ENV:-GLM_API_KEY}"

if [[ -z "${!AGENT_API_KEY_ENV:-}" ]]; then
  echo "missing agent API key in environment variable ${AGENT_API_KEY_ENV}" >&2
  exit 2
fi

MAX_WORKERS="${MAX_WORKERS:-1}"
WORKER_LAUNCH_JITTER_SECONDS="${WORKER_LAUNCH_JITTER_SECONDS:-0}"
CLEANUP_LOCAL_IMAGE="${CLEANUP_LOCAL_IMAGE:-1}"
RUN_BASE="${RUN_BASE:-${D_ROOT}/outputs}"
PREFIX="${PREFIX:-d14_secbench_${MODE}_${MODEL//[^A-Za-z0-9_.-]/_}_mw${MAX_WORKERS}_${STAMP}}"
SHARED_BASE="${RUN_BASE}/${PREFIX}"
OUTPUTS_ROOT="${SHARED_BASE}/inference"
MANIFEST_DIR="${SHARED_BASE}/manifests"
TASK_LIST="${MANIFEST_DIR}/${PREFIX}.tasks.txt"
PLAN_JSON="${SHARED_BASE}/${PREFIX}_plan.json"
LOG_DIR="${SHARED_BASE}/logs"
BATCH_LOG="${LOG_DIR}/${PREFIX}.batch.log"
EVAL_INPUT_DIR="${SHARED_BASE}/secbench_eval_input"
EVAL_INPUT_JSONL="${EVAL_INPUT_DIR}/output.jsonl"
OFFICIAL_EVAL_DIR="${SHARED_BASE}/secbench_official_eval"
SECBENCH_SOURCE_ROOT="${SECBENCH_SOURCE_ROOT:-${D_ROOT}/SEC-bench}"
SECBENCH_OFFICIAL_EVAL_MODE="${SECBENCH_OFFICIAL_EVAL_MODE:-all}"
SECBENCH_OFFICIAL_EVAL_WORKERS="${SECBENCH_OFFICIAL_EVAL_WORKERS:-${MAX_WORKERS}}"
SECBENCH_OFFICIAL_EVAL_TIMEOUT_SECONDS="${SECBENCH_OFFICIAL_EVAL_TIMEOUT_SECONDS:-600}"
STAGE_TIMEOUT_SECONDS="${STAGE_TIMEOUT_SECONDS:-7200}"
ANALYSIS_TIMEOUT_SECONDS="${ANALYSIS_TIMEOUT_SECONDS:-10800}"
REPAIR_TIMEOUT_SECONDS="${REPAIR_TIMEOUT_SECONDS:-7200}"
REPRODUCER_TIMEOUT_SECONDS="${REPRODUCER_TIMEOUT_SECONDS:-300}"

if [[ ! -x "${SECBENCH_EVAL_PY}" ]]; then
  echo "missing_secbench_eval_python: ${SECBENCH_EVAL_PY}" >&2
  exit 2
fi

mkdir -p "${OUTPUTS_ROOT}" "${MANIFEST_DIR}" "${LOG_DIR}" "${EVAL_INPUT_DIR}"

CLEANUP_LOCAL_IMAGE_ARG=()
if [[ "${CLEANUP_LOCAL_IMAGE}" != "0" && "${CLEANUP_LOCAL_IMAGE}" != "false" && "${CLEANUP_LOCAL_IMAGE}" != "no" && "${CLEANUP_LOCAL_IMAGE}" != "off" ]]; then
  CLEANUP_LOCAL_IMAGE_ARG=(--cleanup-local-image)
fi

"${PY}" - "${SECBENCH_DATASET}" "${TASK_LIST}" "${PLAN_JSON}" "${MODE}" "${INSTANCE_ID}" "${INSTANCE_LIST_FILE}" "${ANALYSIS_TIMEOUT_SECONDS}" "${REPAIR_TIMEOUT_SECONDS}" "${STAGE_TIMEOUT_SECONDS}" "${REPRODUCER_TIMEOUT_SECONDS}" <<'PYDATA'
import json
import sys
from pathlib import Path

dataset = Path(sys.argv[1])
task_list = Path(sys.argv[2])
plan = Path(sys.argv[3])
mode = sys.argv[4]
instance_id = sys.argv[5]
instance_list_file = Path(sys.argv[6])
analysis_timeout_seconds = int(sys.argv[7])
repair_timeout_seconds = int(sys.argv[8])
stage_timeout_seconds = int(sys.argv[9])
reproducer_timeout_seconds = int(sys.argv[10])

if not dataset.exists():
    raise SystemExit(f"SEC-bench dataset missing: {dataset}")

records = []
with dataset.open(encoding="utf-8") as handle:
    for line in handle:
        if line.strip():
            records.append(json.loads(line))
by_id = {str(row.get("instance_id", "")): row for row in records}

if mode == "smoke":
    selected = [instance_id]
elif mode == "subset":
    if not instance_list_file.exists():
        raise SystemExit(f"MODE=subset requires INSTANCE_LIST_FILE: {instance_list_file}")
    selected = [
        line.strip()
        for line in instance_list_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
else:
    selected = [str(row["instance_id"]) for row in records]

missing = [item for item in selected if item not in by_id]
if missing:
    raise SystemExit(f"selected SEC-bench instance IDs missing from dataset: {missing[:20]}")

for item in selected:
    row = by_id[item]
    for field in ["instance_id", "bug_description", "sanitizer_report", "work_dir"]:
        if not str(row.get(field, "")).strip():
            raise SystemExit(f"SEC-bench record {item} missing {field}")

task_list.write_text("\n".join(selected) + "\n", encoding="utf-8")
plan.write_text(json.dumps({
    "benchmark": "secbench",
    "mode": mode,
    "count": len(selected),
    "dataset": str(dataset),
    "task_list": str(task_list),
    "tasks": selected,
    "timeout_profile": {
        "total_timeout_seconds": 0,
        "analysis_timeout_seconds": analysis_timeout_seconds,
        "repair_timeout_seconds": repair_timeout_seconds,
        "stage_timeout_seconds": stage_timeout_seconds,
        "reproducer_timeout_seconds": reproducer_timeout_seconds,
    },
    "prompt_input_policy": "patch task uses work_dir plus bug_description and sanitizer_report only; reference patch and bug_report are not rendered into the agent prompt",
}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"event": "secbench_task_list_ready", "count": len(selected), "task_list": str(task_list)}, ensure_ascii=False), flush=True)
PYDATA

export PATCH_EVAL
export PATCHEVAL_RUNTIME="${PATCHEVAL_RUNTIME:-sandbox_api}"
runtime_lc="$(printf '%s' "${PATCHEVAL_RUNTIME}" | tr '[:upper:]' '[:lower:]')"
if [[ ! "${runtime_lc}" =~ ^(sandbox|sandbox_api|brainbox)$ ]]; then
  echo "secbench_requires_sandbox_runtime: PATCHEVAL_RUNTIME=${PATCHEVAL_RUNTIME}" >&2
  exit 2
fi
sandbox_key_value="${SANDBOX_API_KEY:-${OPEN_SANDBOX_API_KEY:-}}"
if [[ -z "${sandbox_key_value}" && -n "${SANDBOX_AK:-${OPEN_SANDBOX_AK:-}}" && -n "${SANDBOX_SK:-${OPEN_SANDBOX_SK:-}}" ]]; then
  sandbox_key_value="${SANDBOX_AK:-${OPEN_SANDBOX_AK}}:${SANDBOX_SK:-${OPEN_SANDBOX_SK}}"
fi
if [[ -z "${sandbox_key_value}" ]]; then
  echo "missing_sandbox_api_key: set OPEN_SANDBOX_API_KEY or SANDBOX_API_KEY before running SEC-bench sandbox flow" >&2
  exit 2
fi
export OPEN_SANDBOX_API_KEY="${sandbox_key_value}"
export SANDBOX_API_KEY="${sandbox_key_value}"
export SANDBOX_PROJECT="${SANDBOX_PROJECT:-ailab-ai4good1}"
export SANDBOX_API_BASE="${SANDBOX_API_BASE:-https://h.example.invalid/brainbox/v1}"
export PATCHEVAL_SANDBOX_CPU="${PATCHEVAL_SANDBOX_CPU:-4}"
export PATCHEVAL_SANDBOX_MEMORY="${PATCHEVAL_SANDBOX_MEMORY:-8Gi}"
export PATCHEVAL_SANDBOX_REQUEST_CPU="${PATCHEVAL_SANDBOX_REQUEST_CPU:-500m}"
export PATCHEVAL_SANDBOX_REQUEST_MEMORY="${PATCHEVAL_SANDBOX_REQUEST_MEMORY:-1Gi}"
export PATCHEVAL_SANDBOX_INSTANCE_CAPACITY="${PATCHEVAL_SANDBOX_INSTANCE_CAPACITY:-300}"
export PATCHEVAL_SANDBOX_ENV_NAME_SUFFIX="${PATCHEVAL_SANDBOX_ENV_NAME_SUFFIX:-secbench-d14}"
export PATCHEVAL_SANDBOX_LIFECYCLE_MINUTES="${PATCHEVAL_SANDBOX_LIFECYCLE_MINUTES:--1}"
export PATCHEVAL_SANDBOX_STOP_AFTER="${PATCHEVAL_SANDBOX_STOP_AFTER:-1}"
export PATCHEVAL_SANDBOX_START_TIMEOUT="${PATCHEVAL_SANDBOX_START_TIMEOUT:-1800}"
export PATCHEVAL_SANDBOX_REQUEST_TIMEOUT="${PATCHEVAL_SANDBOX_REQUEST_TIMEOUT:-7200}"
export PATCHEVAL_SANDBOX_MIN_EXEC_TIMEOUT="${PATCHEVAL_SANDBOX_MIN_EXEC_TIMEOUT:-300}"
export PATCHEVAL_SANDBOX_EXEC_HEARTBEAT="${PATCHEVAL_SANDBOX_EXEC_HEARTBEAT:-15}"
export PATCHEVAL_SANDBOX_CREATE_CAPACITY_WAIT_SECONDS="${PATCHEVAL_SANDBOX_CREATE_CAPACITY_WAIT_SECONDS:-7200}"
export PATCHEVAL_SANDBOX_CREATE_RETRY_SECONDS="${PATCHEVAL_SANDBOX_CREATE_RETRY_SECONDS:-20}"
export PATCHEVAL_SANDBOX_IMAGE_PREFIXES="${PATCHEVAL_SANDBOX_IMAGE_PREFIXES:-${SECBENCH_SANDBOX_REGISTRY_PREFIX}}"
export PATCHEVAL_SANDBOX_ENV_CACHE="${PATCHEVAL_SANDBOX_ENV_CACHE:-${SHARED_BASE}/sandbox_env_cache.json}"
export STAGE_TIMEOUT_SECONDS ANALYSIS_TIMEOUT_SECONDS REPAIR_TIMEOUT_SECONDS REPRODUCER_TIMEOUT_SECONDS
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
unset PATCH_EVAL_HTTP_PROXY PATCH_EVAL_HTTPS_PROXY PATCH_EVAL_ALL_PROXY
unset PATCH_EVAL_http_proxy PATCH_EVAL_https_proxy PATCH_EVAL_all_proxy
unset NO_PROXY no_proxy

set +e
"${PY}" "${D_ROOT}/scripts/run_full_no_knowledge_chain_batch.py" \
  --task-list "${TASK_LIST}" \
  --dataset "${SECBENCH_DATASET}" \
  --outputs-root "${OUTPUTS_ROOT}" \
  --benchmark secbench \
  --secbench-image-prefix "${SECBENCH_IMAGE_PREFIX}" \
  --secbench-image-template "${SECBENCH_IMAGE_TEMPLATE}" \
  --max-workers "${MAX_WORKERS}" \
  --worker-launch-jitter-seconds "${WORKER_LAUNCH_JITTER_SECONDS}" \
  --workflow d_analysis_mas \
  --agent-model "${MODEL}" \
  --agent-base-url "${GLM_API_BASE}" \
  --agent-api-key-env "${AGENT_API_KEY_ENV}" \
  --stage-timeout-seconds "${STAGE_TIMEOUT_SECONDS}" \
  --analysis-timeout-seconds "${ANALYSIS_TIMEOUT_SECONDS}" \
  --repair-timeout-seconds "${REPAIR_TIMEOUT_SECONDS}" \
  --reproducer-timeout-seconds "${REPRODUCER_TIMEOUT_SECONDS}" \
  --skip-postprocess \
  --container-name-suffix "${PREFIX}" \
  "${CLEANUP_LOCAL_IMAGE_ARG[@]}" \
  2>&1 | tee "${BATCH_LOG}"
batch_rc=${PIPESTATUS[0]}
set -e

set +e
"${SECBENCH_EVAL_PY}" "${D_ROOT}/scripts/secbench_official_eval_from_patches.py" \
  --task-list "${TASK_LIST}" \
  --dataset-jsonl "${SECBENCH_DATASET}" \
  --patches-dir "${OUTPUTS_ROOT}/patches" \
  --eval-input-dir "${EVAL_INPUT_DIR}" \
  --official-output-dir "${OFFICIAL_EVAL_DIR}" \
  --secbench-root "${SECBENCH_SOURCE_ROOT}" \
  --image-prefix "${SECBENCH_IMAGE_PREFIX}" \
  --image-template "${SECBENCH_IMAGE_TEMPLATE}" \
  --num-workers "${SECBENCH_OFFICIAL_EVAL_WORKERS}" \
  --mode "${SECBENCH_OFFICIAL_EVAL_MODE}" \
  --runtime "${PATCHEVAL_RUNTIME}" \
  --eval-timeout-seconds "${SECBENCH_OFFICIAL_EVAL_TIMEOUT_SECONDS}" \
  2>&1 | tee "${LOG_DIR}/${PREFIX}.official_eval.log"
official_eval_rc=${PIPESTATUS[0]}
set -e

if [[ "${official_eval_rc}" -ne 0 ]]; then
  echo "official_eval_rc=${official_eval_rc}" >&2
fi

echo "prefix=${PREFIX}"
echo "shared_base=${SHARED_BASE}"
echo "outputs_root=${OUTPUTS_ROOT}"
echo "task_list=${TASK_LIST}"
echo "batch_log=${BATCH_LOG}"
echo "secbench_eval_input_dir=${EVAL_INPUT_DIR}"
echo "secbench_eval_input=${EVAL_INPUT_JSONL}"
echo "secbench_official_eval_dir=${OFFICIAL_EVAL_DIR}"
echo "secbench_official_eval_log=${LOG_DIR}/${PREFIX}.official_eval.log"
if [[ "${batch_rc}" -ne 0 ]]; then
  exit "${batch_rc}"
fi
exit "${official_eval_rc}"
