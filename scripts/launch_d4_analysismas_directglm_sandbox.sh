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

driver_main() {
  proxy_pid=""
  echo "[$(date +%F_%T)] driver_prepare" > "${DRIVER_LOG}"
  if [[ "${USE_BRAINBOX_PROXY:-0}" == "1" ]]; then
    set +e
    "${PY}" "${D_ROOT}/scripts/brainbox_openai_proxy.py" > "${PROXY_LOG}" 2>&1 &
    proxy_pid=$!
    set -e
    echo "[$(date +%F_%T)] host_brainbox_proxy_pid=${proxy_pid}" >> "${DRIVER_LOG}"
    proxy_ready=0
    for _ in $(seq 1 90); do
      if "${PY}" - "${PROXY_URL}/healthz" >> "${DRIVER_LOG}" 2>&1 <<'PYHEALTH'
import sys
import urllib.request
url = sys.argv[1]
with urllib.request.urlopen(url, timeout=5) as resp:
    print(resp.status, resp.read().decode("utf-8")[:200])
PYHEALTH
      then
        proxy_ready=1
        break
      fi
      sleep 2
    done
    if [[ "${proxy_ready}" != "1" ]]; then
      echo "[$(date +%F_%T)] host_brainbox_proxy_healthcheck_failed" >> "${DRIVER_LOG}"
      if kill -0 "${proxy_pid}" 2>/dev/null; then
        kill "${proxy_pid}" 2>/dev/null || true
      fi
      return 13
    fi
    if ! "${PY}" - "${GLM_API_BASE}" "${AGENT_API_KEY_ENV}" "${MODEL}" >> "${DRIVER_LOG}" 2>&1 <<'PYPREFLIGHT'
import json
import os
import sys
import urllib.request

base = sys.argv[1].rstrip("/")
key = os.environ.get(sys.argv[2], "").strip()
model = sys.argv[3] if len(sys.argv) > 3 else "glm-5.2"
headers = {"Content-Type": "application/json"}
if key:
    headers["Authorization"] = "Bearer " + key
    headers["x-api-key"] = key
body = json.dumps({
    "model": model,
    "messages": [{"role": "user", "content": "仅回复 OK"}],
    "max_tokens": 8,
    "temperature": 0,
}).encode("utf-8")
req = urllib.request.Request(f"{base}/chat/completions", data=body, headers=headers, method="POST")
with urllib.request.urlopen(req, timeout=60) as resp:
    print("chat", resp.status, resp.read(200).decode("utf-8", "replace")[:120])
PYPREFLIGHT
    then
      echo "[$(date +%F_%T)] host_brainbox_proxy_preflight_failed base=${GLM_API_BASE}" >> "${DRIVER_LOG}"
      if kill -0 "${proxy_pid}" 2>/dev/null; then
        kill "${proxy_pid}" 2>/dev/null || true
        wait "${proxy_pid}" 2>/dev/null || true
      fi
      return 15
    fi
  fi

  echo "[$(date +%F_%T)] driver_start prefix=${PREFIX} mode=${MODE}" >> "${DRIVER_LOG}"
  echo "d_root=${D_ROOT}" >> "${DRIVER_LOG}"
  echo "outputs_root=${OUTPUTS_ROOT}" >> "${DRIVER_LOG}"
  echo "runtime=${PATCHEVAL_RUNTIME}" >> "${DRIVER_LOG}"
  echo "sandbox_project=${SANDBOX_PROJECT}" >> "${DRIVER_LOG}"
  echo "sandbox_lifecycle=${PATCHEVAL_SANDBOX_LIFECYCLE_MINUTES}" >> "${DRIVER_LOG}"
  echo "agent_base_url=${GLM_API_BASE}" >> "${DRIVER_LOG}"
  echo "brainbox_in_container_proxy=${PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY:-unset}" >> "${DRIVER_LOG}"
  echo "brainbox_proxy_mode=${PATCHEVAL_BRAINBOX_PROXY_MODE:-unset}" >> "${DRIVER_LOG}"
  echo "brainbox_upstream_base=${BRAINBOX_UPSTREAM_API_BASE:-${GLM_API_BASE}}" >> "${DRIVER_LOG}"
  echo "postprocess=disabled; generated repair patch is submitted directly to verified eval" >> "${DRIVER_LOG}"
  echo "max_workers=${MAX_WORKERS} eval_max_workers=${EVAL_MAX_WORKERS}" >> "${DRIVER_LOG}"
  echo "setup_gate=${PATCHEVAL_OPENCODE_SETUP_MAX_CONCURRENCY:-unset} pre_mas_gate=${PATCHEVAL_PRE_MAS_MAX_CONCURRENCY:-unset} run_gate=${PATCHEVAL_OPENCODE_RUN_MAX_CONCURRENCY:-unset}" >> "${DRIVER_LOG}"

  mkdir -p "${DATASET_DIR}" "${MANIFEST_DIR}"
  "${PY}" - "${VERIFIED_DATASET}" "${DATASET}" "${MANIFEST}" "${PLAN_JSON}" "${MODE}" "${CVE_ID}" "${CVE_LIST_FILE:-}" "${VERIFIED_IMAGE_PREFIX}" <<'PYDATA' >> "${DRIVER_LOG}" 2>&1
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dataset = Path(sys.argv[2])
manifest = Path(sys.argv[3])
plan = Path(sys.argv[4])
mode = sys.argv[5]
cve_id = sys.argv[6]
cve_list_file = Path(sys.argv[7]) if len(sys.argv) > 7 and sys.argv[7] else None
verified_image_prefix = sys.argv[8].rstrip("/")

def repo_basename(repo_url):
    name = str(repo_url or "").rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    if not name:
        raise SystemExit("verified dataset sample missing repo; cannot derive work_dir")
    return name

def image_tag(row, pid):
    image = str(row.get("image_url") or "")
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        return last.rsplit(":", 1)[-1]
    return str(pid).lower()

requested = []
if mode == "subset":
    if not cve_list_file:
        raise SystemExit("MODE=subset requires CVE_LIST_FILE")
    text = cve_list_file.read_text(encoding="utf-8")
    if cve_list_file.suffix.lower() == ".json":
        obj = json.loads(text)
        if isinstance(obj, dict) and isinstance(obj.get("cves"), list):
            requested = [str(item).strip() for item in obj["cves"] if str(item).strip()]
        elif isinstance(obj, list):
            requested = [str(item.get("cve_id") or item.get("cve") or item).strip() for item in obj if str(item).strip()]
        else:
            raise SystemExit(f"unsupported CVE JSON manifest shape: {cve_list_file}")
    else:
        requested = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if not requested:
        raise SystemExit(f"CVE_LIST_FILE is empty: {cve_list_file}")

requested_set = set(requested)
src_rows = json.loads(src.read_text(encoding="utf-8"))
if not isinstance(src_rows, list):
    raise SystemExit(f"verified dataset must be a JSON list: {src}")

rows = []
for obj in src_rows:
    pid = obj.get("cve_id")
    if mode == "smoke":
        if pid == cve_id:
            rows.append(obj)
    elif mode == "subset":
        if pid in requested_set:
            rows.append(obj)
    else:
        rows.append(obj)

if mode == "smoke" and len(rows) != 1:
    raise SystemExit(f"expected one {cve_id} row, got {len(rows)}")
if mode == "subset":
    found = {
        row.get("cve_id") or row.get("problem_id") or row.get("instance_id") or row.get("id")
        for row in rows
    }
    missing = sorted(requested_set - found)
    if missing:
        raise SystemExit(f"CVE_LIST_FILE includes ids missing from dataset: {missing}")
if mode == "full" and len(rows) != 230:
    raise SystemExit(f"expected full 230 rows, got {len(rows)}")

ids = [
    row.get("cve_id")
    for row in rows
]
d4_rows = []
for row, pid in zip(rows, ids):
    cve_description = str(row.get("cve_description") or "").strip()
    if not cve_description:
        raise SystemExit(f"verified dataset sample {pid} missing cve_description")
    image_name = f"{verified_image_prefix}:{image_tag(row, pid)}"
    d4_rows.append({
        "cve_id": pid,
        "image_name": image_name,
        "image_url": image_name,
        "work_dir": f"/workspace/{repo_basename(row.get('repo'))}",
        "problem_statement": cve_description,
        "cve_description": cve_description,
        "fix_patch": "",
        "repo": row.get("repo", ""),
    })
dataset.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in d4_rows), encoding="utf-8")
manifest.write_text("".join(str(pid) + "\n" for pid in ids), encoding="utf-8")
record = {
    "subset_label": f"D13_analysis_mas_repair_mas_{mode}",
    "definition": "D13 direct-GLM run using Analysis MAS and Repair MAS, skips MAS postprocess, and submits generated patches directly to verified eval",
    "count": len(rows),
    "cves": ids,
    "flow": "D13_analysis_mas_vulnerability_model_repair_mas_direct_eval",
    "dataset": str(dataset),
    "manifest": str(manifest),
    "source_cve_list_file": str(cve_list_file) if cve_list_file else "",
}
plan.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"event": "dataset_preflight_ok", "mode": mode, "count": len(rows), "dataset": str(dataset)}, ensure_ascii=False), flush=True)
PYDATA

  cd "${D_ROOT}" || exit 20
  set +e
  "${PY}" "${D_ROOT}/scripts/run_full_no_knowledge_chain_batch.py" \
    --cve-list "${MANIFEST}" \
    --dataset "${DATASET}" \
    --outputs-root "${OUTPUTS_ROOT}" \
    --max-workers "${MAX_WORKERS}" \
    --worker-launch-jitter-seconds "${WORKER_LAUNCH_JITTER_SECONDS}" \
    --resume \
    --workflow d_analysis_mas \
    --agent-model "${MODEL}" \
    --agent-base-url "${GLM_API_BASE}" \
    --agent-api-key-env "${AGENT_API_KEY_ENV}" \
    --stage-timeout-seconds "${STAGE_TIMEOUT_SECONDS}" \
    --analysis-timeout-seconds "${ANALYSIS_TIMEOUT_SECONDS}" \
    --repair-timeout-seconds "${REPAIR_TIMEOUT_SECONDS}" \
    --experiment-variant D13 \
    --skip-postprocess \
    --container-name-suffix "${PREFIX}" \
    2>&1 | tee "${BATCH_LOG}"
  batch_rc=${PIPESTATUS[0]}
  set -e
  echo "[$(date +%F_%T)] inference_finished rc=${batch_rc}" >> "${DRIVER_LOG}"

  if [[ -n "${proxy_pid}" ]] && kill -0 "${proxy_pid}" 2>/dev/null; then
    kill "${proxy_pid}" 2>/dev/null || true
    wait "${proxy_pid}" 2>/dev/null || true
    echo "[$(date +%F_%T)] host_brainbox_proxy_stopped_before_eval" >> "${DRIVER_LOG}"
  fi

  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
  unset PATCH_EVAL_HTTP_PROXY PATCH_EVAL_HTTPS_PROXY PATCH_EVAL_ALL_PROXY
  unset PATCH_EVAL_http_proxy PATCH_EVAL_https_proxy PATCH_EVAL_all_proxy
  unset NO_PROXY no_proxy
  echo "[$(date +%F_%T)] eval_proxy_env_cleared" >> "${DRIVER_LOG}"

  "${PY}" - "${VERIFIED_DATASET}" "${INPUT_JSON}" "${VERIFIED_IMAGE_PREFIX}" <<'PYVERIFYDATA' >> "${DRIVER_LOG}" 2>&1
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
image_prefix = sys.argv[3].rstrip("/")

rows = json.loads(src.read_text(encoding="utf-8"))
for row in rows:
    image = str(row.get("image_url") or row.get("image_name") or "")
    tag = image.rsplit(":", 1)[-1] if ":" in image.rsplit("/", 1)[-1] else str(row["cve_id"]).lower()
    row["image_url"] = f"{image_prefix}:{tag}"

dst.parent.mkdir(parents=True, exist_ok=True)
dst.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"event": "verified_eval_input_written", "path": str(dst), "count": len(rows), "image_prefix": image_prefix}, ensure_ascii=False), flush=True)
PYVERIFYDATA

  cd "${VERIFIED_PATCH_EVAL}/patcheval/exp_agent" || exit 21
  set +e
  "${PY}" process_data.py \
    --runner-output "${OUTPUTS_ROOT}" \
    --process-data-path "${PROCESS_JSON}" \
    --test-data-path "${INPUT_JSON}" \
    2>&1 | tee "${PROCESS_LOG}"
  process_rc=${PIPESTATUS[0]}
  set -e
  echo "[$(date +%F_%T)] process_data_finished rc=${process_rc} process_json=${PROCESS_JSON}" >> "${DRIVER_LOG}"

  eval_rc=99
  if [[ "${process_rc}" -eq 0 ]]; then
    cd "${EVALUATION_DIR}" || exit 22
    set +e
    "${PY}" "${EVAL_SCRIPT}" \
      --output "${PREFIX}" \
      --patch_file "${PROCESS_JSON}" \
      --input_file "${INPUT_JSON}" \
      --max_workers "${EVAL_MAX_WORKERS}" \
      2>&1 | tee "${EVAL_LOG}"
    eval_rc=${PIPESTATUS[0]}
    set -e
    echo "[$(date +%F_%T)] eval_finished rc=${eval_rc}" >> "${DRIVER_LOG}"
    eval_src="${EVALUATION_DIR}/evaluation_output/${PREFIX}"
    if [[ -d "${eval_src}" ]]; then
      cp -a "${eval_src}/." "${EVALUATION_DIR}/"
    fi
  else
    echo "[$(date +%F_%T)] eval_skipped process_data_rc=${process_rc}" >> "${DRIVER_LOG}"
  fi

  "${PY}" - "${SHARED_BASE}" "${OUTPUTS_ROOT}" "${PREFIX}" "${MODE}" "${batch_rc}" "${process_rc}" "${eval_rc}" <<'PYSUMMARY' >> "${DRIVER_LOG}" 2>&1
import json
import pathlib
import sys
import time

shared = pathlib.Path(sys.argv[1])
outputs = pathlib.Path(sys.argv[2])
prefix = sys.argv[3]
mode = sys.argv[4]
record = {
    "prefix": prefix,
    "mode": mode,
    "shared_base": str(shared),
    "outputs_root": str(outputs),
    "batch_rc": int(sys.argv[5]),
    "process_data_rc": int(sys.argv[6]),
    "eval_rc": int(sys.argv[7]),
    "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "batch_summary_exists": (outputs / "batch_summary.json").exists(),
    "process_json_exists": (shared / "evaluation" / f"{prefix}_process.jsonl").exists(),
    "evaluation_summary_exists": (shared / "evaluation" / "summary.json").exists(),
    "patch_count": len(list((outputs / "patches").glob("*.patch"))),
    "candidate_patch_count": len(list((outputs / "candidate_patches").glob("*.patch"))),
}
(shared / "driver_result_manifest.json").write_text(
    json.dumps(record, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
print(json.dumps(record, ensure_ascii=False))
PYSUMMARY
  echo "[$(date +%F_%T)] driver_finished" >> "${DRIVER_LOG}"
  if [[ "${batch_rc}" -ne 0 ]]; then
    return "${batch_rc}"
  fi
  if [[ "${process_rc}" -ne 0 ]]; then
    return "${process_rc}"
  fi
  return "${eval_rc}"
}

if [[ -t 0 ]]; then
  stty -echo
fi
read -r FIRST_SECRET_VALUE || FIRST_SECRET_VALUE="${OPEN_SANDBOX_API_KEY:-}"
read -r SECOND_SECRET_VALUE || SECOND_SECRET_VALUE="${GLM_API_KEY:-}"
if [[ "${FIRST_SECRET_VALUE}" == *:* ]]; then
  OPEN_SANDBOX_API_KEY_VALUE="${FIRST_SECRET_VALUE}"
  GLM_API_KEY_VALUE="${SECOND_SECRET_VALUE}"
else
  THIRD_SECRET_VALUE=""
  read -r -t 1 THIRD_SECRET_VALUE || true
  OPEN_SANDBOX_API_KEY_VALUE="${FIRST_SECRET_VALUE}:${SECOND_SECRET_VALUE}"
  GLM_API_KEY_VALUE="${THIRD_SECRET_VALUE:-${GLM_API_KEY:-}}"
fi
if [[ -t 0 ]]; then
  stty echo
  printf '\n'
fi

if [[ -z "${OPEN_SANDBOX_API_KEY_VALUE:-}" ]]; then
  echo "missing_open_sandbox_api_key" >&2
  exit 2
fi
if [[ "${OPEN_SANDBOX_API_KEY_VALUE}" != *:* ]]; then
  echo "invalid_open_sandbox_api_key_format_expected_ak_colon_sk" >&2
  exit 2
fi
if [[ -z "${GLM_API_KEY_VALUE:-}" ]]; then
  echo "missing_glm_api_key" >&2
  exit 2
fi
if [[ "${GLM_API_KEY_VALUE}" != sk-* ]]; then
  echo "invalid_glm_api_key_format_expected_sk_prefix" >&2
  exit 2
fi

MODE="${MODE:-subset}"
if [[ "${MODE}" != "smoke" && "${MODE}" != "subset" && "${MODE}" != "full" ]]; then
  echo "MODE must be smoke, subset, or full" >&2
  exit 2
fi

STAMP="${STAMP:-$(date +%Y%m%d_%H%M%S)}"
if [[ -z "${MAX_WORKERS+x}" ]]; then
  if [[ "${MODE}" == "full" || "${MODE}" == "subset" ]]; then
    MAX_WORKERS=30
  else
    MAX_WORKERS=1
  fi
fi
if [[ -z "${EVAL_MAX_WORKERS+x}" ]]; then
  if [[ "${MODE}" == "full" || "${MODE}" == "subset" ]]; then
    EVAL_MAX_WORKERS=30
  else
    EVAL_MAX_WORKERS=1
  fi
fi
if [[ -z "${WORKER_LAUNCH_JITTER_SECONDS+x}" ]]; then
  WORKER_LAUNCH_JITTER_SECONDS=0
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DEFAULT_D_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
D_ROOT="${D_ROOT:-${DEFAULT_D_ROOT}}"
PATCH_EVAL="${PATCH_EVAL:-/path/to/local/resource"
VERIFIED_PATCH_EVAL="${VERIFIED_PATCH_EVAL:-/path/to/local/resource"
VERIFIED_DATASET="${VERIFIED_DATASET:-${VERIFIED_PATCH_EVAL}/patcheval/datasets/patcheval_verified.json}"
VERIFIED_IMAGE_REPOSITORY="${VERIFIED_IMAGE_REPOSITORY:-ailab-ai4good1/patcheval-cve-verified}"
VERIFIED_IMAGE_PREFIX="${VERIFIED_IMAGE_PREFIX:-registry-v2.h.example.invalid/${VERIFIED_IMAGE_REPOSITORY}}"
OPENCODE="${OPENCODE:-${PATCH_EVAL}/patcheval/exp_agent/opencode}"
EVAL_CWD="${EVAL_CWD:-${VERIFIED_PATCH_EVAL}/patcheval/evaluation}"
if [[ -z "${EVAL_SCRIPT+x}" ]]; then
  if [[ "${PATCHEVAL_RUNTIME:-sandbox_api}" =~ ^(sandbox|sandbox_api|brainbox)$ ]]; then
    EVAL_SCRIPT="${VERIFIED_PATCH_EVAL}/patcheval/evaluation/run_evaluation_sandbox_api.py"
  else
    EVAL_SCRIPT="${VERIFIED_PATCH_EVAL}/patcheval/evaluation/run_evaluation.py"
  fi
fi
INPUT_JSON="${INPUT_JSON:-}"
PY="${PY:-${PATCH_EVAL}/.venv/bin/python}"
MODEL="${MODEL:-glm-5.2}"
CVE_ID="${CVE_ID:-CVE-2021-21384}"
GROUP_JSON_DEFAULT="${D_ROOT}/verified_pass1_failed80_sample20_success150_sample10_seed20260731.cves.txt"
CVE_LIST_FILE="${CVE_LIST_FILE:-${GROUP_JSON_DEFAULT}}"
PROJECT_DIR_NAME="$(basename "${D_ROOT}")"
PROJECT_SUFFIX="${PROJECT_DIR_NAME#mas_static_trace_multi_direction_}"
DEFAULT_RUN_BASE_NAME="analysis_mas_${PROJECT_SUFFIX/_/_sub2api_}"
RUN_BASE="${RUN_BASE:-${D_ROOT}/outputs}"
PREFIX="${PREFIX:-analysismasD13_sample30_directglm_sandboxapi_glm52_mw${MAX_WORKERS}_evalmw${EVAL_MAX_WORKERS}_${STAMP}}"
SHARED_BASE="${RUN_BASE}/${PREFIX}"
OUTPUTS_ROOT="${SHARED_BASE}/inference"
DATASET_DIR="${SHARED_BASE}/datasets"
MANIFEST_DIR="${SHARED_BASE}/manifests"
DATASET="${DATASET_DIR}/${PREFIX}.jsonl"
MANIFEST="${MANIFEST_DIR}/${PREFIX}.txt"
PLAN_JSON="${SHARED_BASE}/${PREFIX}_plan.json"
EVALUATION_DIR="${SHARED_BASE}/evaluation"
PROCESS_JSON="${EVALUATION_DIR}/${PREFIX}_process.jsonl"
if [[ -z "${INPUT_JSON}" ]]; then
  INPUT_JSON="${EVALUATION_DIR}/${PREFIX}_verified_eval_input.json"
fi
LOG_DIR="${SHARED_BASE}/logs"
DRIVER_LOG="${LOG_DIR}/driver.nohup.out"
PROXY_LOG="${LOG_DIR}/brainbox_proxy.log"
BATCH_LOG="${LOG_DIR}/${PREFIX}.batch.log"
PROCESS_LOG="${LOG_DIR}/${PREFIX}.process_data.log"
EVAL_LOG="${LOG_DIR}/${PREFIX}.eval.log"
GLM_BASE_URL="${GLM_BASE_URL:-https://api.yuli-cs.net}"
GLM_API_BASE="${GLM_API_BASE:-$(normalize_openai_base "${GLM_BASE_URL}")}"
PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY="${PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY:-1}"
PATCHEVAL_BRAINBOX_PROXY_MODE="${PATCHEVAL_BRAINBOX_PROXY_MODE:-host_bridge}"
BRAINBOX_PROXY_PORT="${BRAINBOX_PROXY_PORT:-18104}"
PROXY_URL="http://127.0.0.1:${BRAINBOX_PROXY_PORT}"
USE_BRAINBOX_PROXY=0
AGENT_API_KEY_ENV="GLM_API_KEY"
brainbox_proxy_flag="$(printf '%s' "${PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY}" | tr '[:upper:]' '[:lower:]')"
if [[ "${brainbox_proxy_flag}" != "0" && "${brainbox_proxy_flag}" != "false" && "${brainbox_proxy_flag}" != "no" && "${brainbox_proxy_flag}" != "off" ]]; then
  BRAINBOX_UPSTREAM_API_BASE="${GLM_API_BASE}"
  GLM_API_BASE="http://127.0.0.1:${BRAINBOX_PROXY_PORT}/v1"
  proxy_mode_lc="$(printf '%s' "${PATCHEVAL_BRAINBOX_PROXY_MODE}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${proxy_mode_lc}" == "host_bridge" || "${proxy_mode_lc}" == "bridge" ]]; then
    USE_BRAINBOX_PROXY=1
    AGENT_API_KEY_ENV="PATCHEVAL_DUMMY_AGENT_KEY"
  fi
  BRAINBOX_HOSTS_NAME="${BRAINBOX_HOSTS_NAME:-h.example.invalid}"
  if [[ -z "${BRAINBOX_HOSTS_IP:-}" ]]; then
    BRAINBOX_HOSTS_IP="$(getent hosts "${BRAINBOX_HOSTS_NAME}" 2>/dev/null | awk 'NR==1 {print $1}')"
  fi
fi

mkdir -p "${LOG_DIR}" "${OUTPUTS_ROOT}" "${EVALUATION_DIR}" "${DATASET_DIR}" "${MANIFEST_DIR}"

export OPEN_SANDBOX_API_KEY="${OPEN_SANDBOX_API_KEY_VALUE}"
export SANDBOX_API_KEY="${OPEN_SANDBOX_API_KEY_VALUE}"
export GLM_API_KEY="${GLM_API_KEY_VALUE}"
export SANDBOX_PROJECT="${SANDBOX_PROJECT:-anonymous-model}"
export SANDBOX_API_BASE="${SANDBOX_API_BASE:-https://h.example.invalid/brainbox/v1}"
export PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY
export PATCHEVAL_BRAINBOX_PROXY_MODE
export BRAINBOX_PROXY_PORT
export PATCHEVAL_DUMMY_AGENT_KEY="${PATCHEVAL_DUMMY_AGENT_KEY:-sk-local-proxy}"
if [[ "${brainbox_proxy_flag}" != "0" && "${brainbox_proxy_flag}" != "false" && "${brainbox_proxy_flag}" != "no" && "${brainbox_proxy_flag}" != "off" ]]; then
  export BRAINBOX_SUB2API_KEY="${BRAINBOX_SUB2API_KEY:-${GLM_API_KEY_VALUE}}"
  export BRAINBOX_SANDBOX_ID="${BRAINBOX_SANDBOX_ID:-sbx-ec349971-c4f}"
  export BRAINBOX_USER_SLOT="${BRAINBOX_USER_SLOT:-repair}"
  export BRAINBOX_UPSTREAM_API_BASE
  export BRAINBOX_HOSTS_NAME
  export BRAINBOX_HOSTS_IP
elif [[ -z "${PATCHEVAL_OPENCODE_HEADERS_JSON:-}" ]]; then
  PATCHEVAL_OPENCODE_HEADERS_JSON="$(
    GLM_API_KEY_VALUE="${GLM_API_KEY_VALUE}" "${PY}" - <<'PYHEADERS'
import json
import os

print(json.dumps({"Authorization": "Bearer " + os.environ["GLM_API_KEY_VALUE"]}))
PYHEADERS
  )"
  export PATCHEVAL_OPENCODE_HEADERS_JSON
fi

unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
unset PATCH_EVAL_HTTP_PROXY PATCH_EVAL_HTTPS_PROXY PATCH_EVAL_ALL_PROXY
unset PATCH_EVAL_http_proxy PATCH_EVAL_https_proxy PATCH_EVAL_all_proxy
unset NO_PROXY no_proxy

export PATCHEVAL_RUNTIME="${PATCHEVAL_RUNTIME:-sandbox_api}"
export PATCHEVAL_SANDBOX_INTERNAL_PROXY="${PATCHEVAL_SANDBOX_INTERNAL_PROXY:-0}"
export PATCHEVAL_SANDBOX_CPU="${PATCHEVAL_SANDBOX_CPU:-4}"
export PATCHEVAL_SANDBOX_MEMORY="${PATCHEVAL_SANDBOX_MEMORY:-8Gi}"
export PATCHEVAL_SANDBOX_REQUEST_CPU="${PATCHEVAL_SANDBOX_REQUEST_CPU:-500m}"
export PATCHEVAL_SANDBOX_REQUEST_MEMORY="${PATCHEVAL_SANDBOX_REQUEST_MEMORY:-1Gi}"
export PATCHEVAL_SANDBOX_INSTANCE_CAPACITY="${PATCHEVAL_SANDBOX_INSTANCE_CAPACITY:-230}"
export PATCHEVAL_SANDBOX_ENV_NAME_SUFFIX="${PATCHEVAL_SANDBOX_ENV_NAME_SUFFIX:-analysis-mas-d13-directglm}"
export PATCHEVAL_SANDBOX_LIFECYCLE_MINUTES="${PATCHEVAL_SANDBOX_LIFECYCLE_MINUTES:--1}"
export PATCHEVAL_SANDBOX_STOP_AFTER="${PATCHEVAL_SANDBOX_STOP_AFTER:-1}"
export PATCHEVAL_SANDBOX_START_TIMEOUT="${PATCHEVAL_SANDBOX_START_TIMEOUT:-1800}"
export PATCHEVAL_SANDBOX_REQUEST_TIMEOUT="${PATCHEVAL_SANDBOX_REQUEST_TIMEOUT:-7200}"
export PATCHEVAL_SANDBOX_MIN_EXEC_TIMEOUT="${PATCHEVAL_SANDBOX_MIN_EXEC_TIMEOUT:-300}"
export PATCHEVAL_SANDBOX_EXEC_HEARTBEAT="${PATCHEVAL_SANDBOX_EXEC_HEARTBEAT:-15}"
export PATCHEVAL_SANDBOX_CREATE_CAPACITY_WAIT_SECONDS="${PATCHEVAL_SANDBOX_CREATE_CAPACITY_WAIT_SECONDS:-7200}"
export PATCHEVAL_SANDBOX_CREATE_RETRY_SECONDS="${PATCHEVAL_SANDBOX_CREATE_RETRY_SECONDS:-20}"
export PATCHEVAL_SANDBOX_IMAGE_MAP_FILE="${PATCHEVAL_SANDBOX_IMAGE_MAP_FILE:-/path/to/local/resource"
export PATCHEVAL_SANDBOX_IMAGE_PREFIXES="${PATCHEVAL_SANDBOX_IMAGE_PREFIXES:-}"
export PATCHEVAL_SANDBOX_ENV_CACHE="${PATCHEVAL_SANDBOX_ENV_CACHE:-${SHARED_BASE}/sandbox_env_cache.json}"
export PATCHEVAL_DOCKER_MAX_PARALLEL="${PATCHEVAL_DOCKER_MAX_PARALLEL:-20}"
export PATCHEVAL_OPENCODE_OUTPUT_LIMIT="${PATCHEVAL_OPENCODE_OUTPUT_LIMIT:-64000}"
export PATCH_EVAL_NPM_INSTALL_TIMEOUT="${PATCH_EVAL_NPM_INSTALL_TIMEOUT:-900}"
export PATCH_EVAL_NPM_FETCH_TIMEOUT="${PATCH_EVAL_NPM_FETCH_TIMEOUT:-300000}"
export PATCHEVAL_OPENCODE_SETUP_MAX_CONCURRENCY="${PATCHEVAL_OPENCODE_SETUP_MAX_CONCURRENCY:-30}"
export PATCHEVAL_PRE_MAS_MAX_CONCURRENCY="${PATCHEVAL_PRE_MAS_MAX_CONCURRENCY:-30}"
export PATCHEVAL_OPENCODE_RUN_MAX_CONCURRENCY="${PATCHEVAL_OPENCODE_RUN_MAX_CONCURRENCY:-30}"
export STAGE_TIMEOUT_SECONDS="${STAGE_TIMEOUT_SECONDS:-7200}"
export ANALYSIS_TIMEOUT_SECONDS="${ANALYSIS_TIMEOUT_SECONDS:-10800}"
export REPAIR_TIMEOUT_SECONDS="${REPAIR_TIMEOUT_SECONDS:-7200}"
export PATCHEVAL_EXPERIMENT_VARIANT="${PATCHEVAL_EXPERIMENT_VARIANT:-D13}"
export MAX_WORKERS EVAL_MAX_WORKERS WORKER_LAUNCH_JITTER_SECONDS
export PATCH_EVAL VERIFIED_PATCH_EVAL VERIFIED_DATASET VERIFIED_IMAGE_REPOSITORY VERIFIED_IMAGE_PREFIX D_ROOT OPENCODE EVAL_CWD EVAL_SCRIPT INPUT_JSON PY MODEL CVE_ID
export RUN_BASE PREFIX SHARED_BASE OUTPUTS_ROOT DATASET_DIR MANIFEST_DIR DATASET MANIFEST PLAN_JSON CVE_LIST_FILE
export EVALUATION_DIR PROCESS_JSON LOG_DIR DRIVER_LOG PROXY_LOG BATCH_LOG PROCESS_LOG EVAL_LOG GLM_BASE_URL GLM_API_BASE
export AGENT_API_KEY_ENV USE_BRAINBOX_PROXY PROXY_URL

if [[ "${FOREGROUND:-0}" == "1" ]]; then
  driver_main
  driver_rc=$?
  echo "prefix=${PREFIX}"
  echo "pid=foreground"
  echo "shared_base=${SHARED_BASE}"
  echo "driver_log=${DRIVER_LOG}"
  echo "driver_rc=${driver_rc}"
  exit "${driver_rc}"
fi

(
  trap '' HUP
  driver_main
) >/dev/null 2>&1 &
pid=$!
disown "${pid}" 2>/dev/null || true
echo "prefix=${PREFIX}"
echo "pid=${pid}"
echo "shared_base=${SHARED_BASE}"
echo "driver_log=${DRIVER_LOG}"
