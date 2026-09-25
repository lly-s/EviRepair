#!/usr/bin/env python3
"""Run OpenCode + qwen3.8-27b-fp8 on SEC-bench-300 with sandbox images.

Inference uses the D14 OpenCode batch runner against ailab-ai4good1 images
started in the configured sandbox project. Official scoring uses the SEC-bench
sandbox evaluator. Environment/retryable failures are re-run after each
inference pass, and a ledger records the valid entry chosen from each round.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List


D_ROOT = Path(__file__).resolve().parents[1]
PATCH_EVAL = Path(
    os.environ.get(
        "PATCH_EVAL",
        "/path/to/local/resource",
    )
)
SECBENCH_DATASET = Path(
    os.environ.get(
        "SECBENCH_DATASET",
        str(D_ROOT / "sec-datasets/eval-secbench300-cve200-oss100.jsonl"),
    )
)
SECBENCH_ROOT = Path(
    os.environ.get(
        "SECBENCH_SOURCE_ROOT",
        "<REPOSITORY_ROOT>/d14/SEC-bench",
    )
)
SECBENCH_IMAGE_REPOSITORY = os.environ.get(
    "SECBENCH_SANDBOX_IMAGE_REPOSITORY",
    "registry-v2.h.example.invalid/ailab-ai4good1/secbench",
).rstrip("/")
SECBENCH_IMAGE_TEMPLATE = os.environ.get(
    "SECBENCH_IMAGE_TEMPLATE",
    f"{SECBENCH_IMAGE_REPOSITORY}:{{instance_id}}-patch",
)
SECBENCH_IMAGE_PREFIX = os.environ.get("SECBENCH_IMAGE_PREFIX", "hwiwonlee/secb.eval.x86_64")
BATCH_PY = D_ROOT / "scripts/run_full_no_knowledge_chain_batch.py"
EVAL_PY = D_ROOT / "scripts/secbench_official_eval_from_patches.py"
DEFAULT_EXP_ROOT = D_ROOT / "outputs/qwen_secbench"
DEFAULT_PY = Path(os.environ.get("PY", str(PATCH_EVAL / ".venv/bin/python")))
DEFAULT_EVAL_PY = Path(
    os.environ.get(
        "SECBENCH_EVAL_PY",
        "<REPOSITORY_ROOT>/d14/.venv_secbench_eval/bin/python",
    )
)

RETRYABLE_RE = re.compile(
    r"("
    r"connection to remote host was lost|"
    r"websocket|"
    r"timed? ?out|"
    r"sandbox api|"
    r"failed to (start|create|prepare) sandbox|"
    r"ensure_environment|"
    r"capacity|"
    r"429|"
    r"502|"
    r"503|"
    r"504|"
    r"insufficient_user_quota|"
    r"disk quota exceeded|"
    r"no space left|"
    r"预扣费|"
    r"rate limit|"
    r"econnreset|"
    r"connection reset|"
    r"temporarily unavailable|"
    r"gateway time|"
    r"ssl|"
    r"network is unreachable|"
    r"name or service not known|"
    r"broken pipe|"
    r"remote end closed|"
    r"http.?5\d\d"
    r")",
    re.I,
)
INFRA_STAGES = {
    "docker_pull",
    "work_container",
    "opencode_setup",
    "opencode_setup_wait",
    "pre_mas_wait",
    "batch_exception",
    "brainbox_container_proxy",
    "initialization",
}
EVAL_INFRA_RE = re.compile(
    r"("
    r"sandbox official eval (failed|timed out|worker failed)|"
    r"sandbox api|"
    r"failed to (start|create|prepare) sandbox|"
    r"insufficient(?:_user)?_quota|"
    r"capacity exceeded|no capacity|out of capacity|"
    r"connection to remote host was lost|"
    r"websocket|"
    r"\bHTTP[/ ]*(?:429|502|503|504)\b|"
    r"(?:status|code)[:\s]*(?:429|502|503|504)\b|"
    r"(?:429 too many|502 bad gateway|503 service unavailable|504 gateway time)|"
    r"econnreset|"
    r"connection reset|"
    r"temporarily unavailable|"
    r"gateway time|"
    r"broken pipe|"
    r"remote end closed"
    r")",
    re.I,
)
LEDGER_FIELDS = [
    "instance_id",
    "included_in_stats",
    "status",
    "source_round",
    "is_success",
    "has_patch",
    "patch_bytes",
    "eval_strict",
    "eval_medium",
    "eval_generous",
    "eval_retryable",
    "stage",
    "error",
]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def load_dataset(path: Path) -> Dict[str, Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}
    for row in read_jsonl(path):
        instance_id = str(row.get("instance_id") or "").strip()
        if not instance_id:
            raise SystemExit(f"{path} contains a record without instance_id")
        by_id[instance_id] = row
    return by_id


def read_id_list(path: Path) -> List[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def prepare_task_list(path: Path, selected: Iterable[str]) -> List[str]:
    ids = [str(item) for item in selected]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(item + "\n" for item in ids), encoding="utf-8")
    return ids


def patch_bytes(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def classify_result(instance_id: str, inference_root: Path) -> Dict[str, Any]:
    process_path = inference_root / "process_logs" / f"{instance_id}.process.json"
    patch_path = inference_root / "patches" / f"{instance_id}.patch"
    process: Dict[str, Any] = {}
    if process_path.exists():
        try:
            if process_path.stat().st_size <= 0:
                process = {"error_message": "process.json is empty", "stage": "batch_exception"}
            else:
                loaded = read_json(process_path)
                if isinstance(loaded, dict):
                    process = loaded
                else:
                    process = {"error_message": "process.json is not an object", "stage": "batch_exception"}
        except Exception:
            process = {"error_message": "process.json is unreadable", "stage": "batch_exception"}
    error = str(process.get("error_message") or "")
    stage = str(process.get("stage") or "")
    success = bool(process.get("is_success"))
    has_patch = patch_bytes(patch_path) > 0
    unfinished_agent = stage in {
        "d_analysis_mas",
        "d_repair_mas",
        "d_post_repair_validation",
        "candidate_patch_extract",
        "pre_mas_done",
    }
    retryable = (not success) and (
        bool(RETRYABLE_RE.search(error))
        or stage in INFRA_STAGES
        or not process_path.exists()
        or (unfinished_agent and not has_patch)
    )
    if success and has_patch:
        status = "valid_success"
        retryable = False
    elif has_patch and not retryable:
        status = "valid_with_patch"
        retryable = False
    elif retryable:
        status = "retryable_env_fail"
    else:
        status = "valid_model_fail"
    return {
        "instance_id": instance_id,
        "status": status,
        "retryable": retryable,
        "is_success": success,
        "has_patch": has_patch,
        "patch_bytes": patch_bytes(patch_path),
        "stage": stage,
        "error": error[:400],
        "process_path": str(process_path) if process_path.exists() else "",
        "patch_path": str(patch_path) if patch_path.exists() else "",
        "container_id": process.get("container_id") or "",
        "eval_strict": "",
        "eval_medium": "",
        "eval_generous": "",
        "eval_retryable": False,
    }


def snapshot_round(round_dir: Path, inference_root: Path, ids: List[str]) -> None:
    dest_logs = round_dir / "process_logs"
    dest_patches = round_dir / "patches"
    dest_logs.mkdir(parents=True, exist_ok=True)
    dest_patches.mkdir(parents=True, exist_ok=True)
    for instance_id in ids:
        src_log = inference_root / "process_logs" / f"{instance_id}.process.json"
        src_patch = inference_root / "patches" / f"{instance_id}.patch"
        if src_log.exists():
            shutil.copy2(src_log, dest_logs / src_log.name)
        if src_patch.exists():
            shutil.copy2(src_patch, dest_patches / src_patch.name)
    src_summary = inference_root / "batch_summary.json"
    if src_summary.exists():
        shutil.copy2(src_summary, round_dir / "batch_summary.json")


def write_ledger(exp_root: Path, rows: List[Dict[str, Any]]) -> None:
    ledger_dir = exp_root / "ledger"
    write_json(ledger_dir / "valid_entries.json", rows)
    csv_path = ledger_dir / "valid_entries.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in LEDGER_FIELDS})
    valid_only = [row for row in rows if row.get("included_in_stats")]
    write_json(ledger_dir / "valid_for_stats.json", valid_only)
    with (ledger_dir / "valid_for_stats.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in valid_only:
            writer.writerow({field: row.get(field, "") for field in LEDGER_FIELDS})
    retry_path = ledger_dir / "retry_queue.txt"
    retry_path.write_text(
        "".join(row["instance_id"] + "\n" for row in rows if row.get("retryable")),
        encoding="utf-8",
    )


def write_status(exp_root: Path, payload: Dict[str, Any]) -> None:
    payload = dict(payload)
    payload["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    write_json(exp_root / "campaign_status.json", payload)


def api_preflight(base_url: str, key: str, model: str) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with OK only."}],
            "max_tokens": 8,
            "temperature": 0,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = resp.read(400).decode("utf-8", "replace")
            return {"ok": True, "status": resp.status, "body_prefix": payload[:200]}
    except urllib.error.HTTPError as exc:
        detail = exc.read(400).decode("utf-8", "replace")
        return {"ok": False, "status": exc.code, "body_prefix": detail[:300]}
    except Exception as exc:
        return {"ok": False, "status": None, "body_prefix": str(exc)[:300]}


def run_cmd(command: List[str], cwd: Path, env: Dict[str, str], log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"\n# {time.strftime('%Y-%m-%dT%H:%M:%S')} {' '.join(command)}\n")
        handle.flush()
        proc = subprocess.run(command, cwd=str(cwd), env=env, stdout=handle, stderr=subprocess.STDOUT)
    return proc.returncode


def run_inference_round(
    *,
    py: Path,
    env: Dict[str, str],
    inference_root: Path,
    dataset_path: Path,
    task_list: Path,
    model: str,
    base_url: str,
    max_workers: int,
    log_path: Path,
) -> int:
    command = [
        str(py),
        str(BATCH_PY),
        "--task-list",
        str(task_list),
        "--dataset",
        str(dataset_path),
        "--outputs-root",
        str(inference_root),
        "--benchmark",
        "secbench",
        "--secbench-image-prefix",
        SECBENCH_IMAGE_PREFIX,
        "--secbench-image-template",
        SECBENCH_IMAGE_TEMPLATE,
        "--max-workers",
        str(max_workers),
        "--resume",
        "--workflow",
        "d_analysis_mas",
        "--agent-model",
        model,
        "--agent-base-url",
        base_url,
        "--agent-api-key-env",
        "GLM_API_KEY",
        "--experiment-variant",
        "D13",
        "--stage-timeout-seconds",
        env.get("STAGE_TIMEOUT_SECONDS", "7200"),
        "--analysis-timeout-seconds",
        env.get("ANALYSIS_TIMEOUT_SECONDS", "10800"),
        "--repair-timeout-seconds",
        env.get("REPAIR_TIMEOUT_SECONDS", "7200"),
        "--reproducer-timeout-seconds",
        env.get("REPRODUCER_TIMEOUT_SECONDS", "300"),
        "--skip-postprocess",
        "--container-name-suffix",
        "qwen_secbench",
        "--cleanup-local-image",
    ]
    return run_cmd(command, D_ROOT, env, log_path)


def collect_existing(inference_root: Path, all_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    latest: Dict[str, Dict[str, Any]] = {}
    for instance_id in all_ids:
        process_path = inference_root / "process_logs" / f"{instance_id}.process.json"
        if not process_path.exists():
            continue
        row = classify_result(instance_id, inference_root)
        row["source_round"] = "existing"
        row["included_in_stats"] = not row["retryable"]
        latest[instance_id] = row
    return latest


def archive_before_retry(inference_root: Path, archived: Path, ids: List[str]) -> None:
    archived.mkdir(parents=True, exist_ok=True)
    for instance_id in ids:
        for rel in (f"process_logs/{instance_id}.process.json", f"patches/{instance_id}.patch"):
            src = inference_root / rel
            if src.exists():
                dest = archived / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                src.unlink()


def load_eval_report(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    by_id: Dict[str, Dict[str, Any]] = {}
    for row in read_jsonl(path):
        instance_id = str(row.get("instance_id") or "").strip()
        if instance_id:
            by_id[instance_id] = row
    return by_id


def attach_eval_results(rows: List[Dict[str, Any]], official_dir: Path) -> List[Dict[str, Any]]:
    reports = {
        "strict": load_eval_report(official_dir / "report_strict.jsonl"),
        "medium": load_eval_report(official_dir / "report_medium.jsonl"),
        "generous": load_eval_report(official_dir / "report_generous.jsonl"),
    }
    for row in rows:
        instance_id = row["instance_id"]
        if not row.get("included_in_stats"):
            row["eval_strict"] = "excluded"
            row["eval_medium"] = "excluded"
            row["eval_generous"] = "excluded"
            row["eval_retryable"] = False
            continue
        eval_error = ""
        for mode in ("strict", "medium", "generous"):
            item = reports[mode].get(instance_id) or {}
            if item:
                row[f"eval_{mode}"] = "pass" if item.get("success") else "fail"
                eval_error = str(item.get("reason") or item.get("logs") or eval_error)
            elif not row.get(f"eval_{mode}"):
                row[f"eval_{mode}"] = "unknown"
        blob = " ".join(
            [
                eval_error,
                str((reports["strict"].get(instance_id) or {}).get("logs") or ""),
            ]
        )
        row["eval_retryable"] = bool(EVAL_INFRA_RE.search(blob))
        if row["eval_retryable"] and row.get("eval_strict") in {"fail", "unknown"}:
            row["eval_strict"] = "retryable_env_fail"
            row["eval_medium"] = "retryable_env_fail"
            row["eval_generous"] = "retryable_env_fail"
    return rows


def run_official_eval(
    *,
    py: Path,
    env: Dict[str, str],
    exp_root: Path,
    task_list: Path,
    inference_root: Path,
    official_dir: Path,
    eval_input_dir: Path,
    max_workers: int,
    log_path: Path,
) -> int:
    official_dir.mkdir(parents=True, exist_ok=True)
    eval_input_dir.mkdir(parents=True, exist_ok=True)
    command = [
        str(py),
        str(EVAL_PY),
        "--task-list",
        str(task_list),
        "--dataset-jsonl",
        str(SECBENCH_DATASET),
        "--patches-dir",
        str(inference_root / "patches"),
        "--eval-input-dir",
        str(eval_input_dir),
        "--official-output-dir",
        str(official_dir),
        "--secbench-root",
        str(SECBENCH_ROOT),
        "--image-prefix",
        SECBENCH_IMAGE_PREFIX,
        "--image-template",
        SECBENCH_IMAGE_TEMPLATE,
        "--num-workers",
        str(max_workers),
        "--mode",
        "all",
        "--runtime",
        "sandbox_api",
        "--eval-timeout-seconds",
        env.get("SECBENCH_OFFICIAL_EVAL_TIMEOUT_SECONDS", "600"),
    ]
    return run_cmd(command, D_ROOT, env, log_path)


def missing_placeholder(instance_id: str) -> Dict[str, Any]:
    return {
        "instance_id": instance_id,
        "status": "missing",
        "retryable": True,
        "included_in_stats": False,
        "source_round": "",
        "is_success": False,
        "has_patch": False,
        "patch_bytes": 0,
        "eval_strict": "",
        "eval_medium": "",
        "eval_generous": "",
        "eval_retryable": False,
        "stage": "",
        "error": "not run yet",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exp-root", type=Path, default=DEFAULT_EXP_ROOT)
    parser.add_argument("--python", type=Path, default=DEFAULT_PY)
    parser.add_argument("--eval-python", type=Path, default=DEFAULT_EVAL_PY)
    parser.add_argument("--model", default=os.environ.get("PATCHEVAL_REMOTE_MODEL", "qwen3.8-27b-fp8"))
    parser.add_argument("--agent-model", default=os.environ.get("MODEL", "openai/qwen3.8-27b-fp8"))
    parser.add_argument("--base-url", default=os.environ.get("GLM_API_BASE", "http://api.example.invalid/v1"))
    parser.add_argument("--max-workers", type=int, default=int(os.environ.get("MAX_WORKERS", "30")))
    parser.add_argument("--eval-max-workers", type=int, default=int(os.environ.get("EVAL_MAX_WORKERS", "30")))
    parser.add_argument("--max-rounds", type=int, default=4)
    parser.add_argument("--max-eval-rounds", type=int, default=3)
    parser.add_argument("--skip-smoke", action="store_true")
    parser.add_argument("--skip-eval", action="store_true")
    parser.add_argument("--smoke-id", default="njs.cve-2022-32414")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    keys = [item.strip() for item in os.environ.get("PATCHEVAL_API_KEYS", "").split(",") if item.strip()]
    if not keys:
        raise SystemExit("PATCHEVAL_API_KEYS must contain the rotating API keys")
    if not os.environ.get("OPEN_SANDBOX_API_KEY"):
        raise SystemExit("OPEN_SANDBOX_API_KEY is required")
    if not SECBENCH_DATASET.exists():
        raise SystemExit(f"SEC-bench dataset missing: {SECBENCH_DATASET}")
    if not SECBENCH_ROOT.exists():
        raise SystemExit(f"SEC-bench source root missing: {SECBENCH_ROOT}")
    if not args.python.exists():
        raise SystemExit(f"inference python missing: {args.python}")
    if not args.eval_python.exists():
        raise SystemExit(f"official eval python missing: {args.eval_python}")

    dataset = load_dataset(SECBENCH_DATASET)
    all_ids = [str(row["instance_id"]) for row in read_jsonl(SECBENCH_DATASET)]
    if len(all_ids) != 300:
        raise SystemExit(f"expected 300 SEC-bench records, got {len(all_ids)}")
    missing_fields = []
    for instance_id in all_ids:
        row = dataset[instance_id]
        for field in ("bug_description", "sanitizer_report", "work_dir"):
            if not str(row.get(field) or "").strip():
                missing_fields.append(f"{instance_id}.{field}")
    if missing_fields:
        raise SystemExit(f"SEC-bench records missing required fields: {missing_fields[:20]}")

    exp_root = args.exp_root.resolve()
    inference_root = exp_root / "aggregated" / "inference"
    logs_dir = exp_root / "logs"
    inference_root.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    write_json(
        exp_root / "experiment_config.json",
        {
            "benchmark": "secbench",
            "model": args.model,
            "agent_model": args.agent_model,
            "base_url": args.base_url,
            "key_count": len(keys),
            "max_workers": args.max_workers,
            "eval_max_workers": args.eval_max_workers,
            "runtime": "sandbox_api",
            "sandbox_project": os.environ.get("SANDBOX_PROJECT"),
            "image_repository": SECBENCH_IMAGE_REPOSITORY,
            "image_template": SECBENCH_IMAGE_TEMPLATE,
            "dataset": str(SECBENCH_DATASET),
            "secbench_root": str(SECBENCH_ROOT),
            "evaluator": str(EVAL_PY),
            "case_count": len(all_ids),
            "local_docker_pull": False,
        },
    )

    print("==== API preflight ====", flush=True)
    preflight = [api_preflight(args.base_url, key, args.model) for key in keys]
    write_json(
        exp_root / "logs" / "api_preflight.json",
        [{"ok": item["ok"], "status": item["status"], "body_prefix": item["body_prefix"]} for item in preflight],
    )
    if not all(item["ok"] for item in preflight):
        print("API preflight failed; not starting the SEC-bench run.", flush=True)
        print(json.dumps(preflight, ensure_ascii=False, indent=2), flush=True)
        return 2
    print(f"API preflight ok for {len(keys)} keys; model={args.model}", flush=True)

    env = os.environ.copy()
    env["SANDBOX_PROJECT"] = env.get("SANDBOX_PROJECT") or "anonymous-model"
    env["SANDBOX_API_BASE"] = env.get("SANDBOX_API_BASE") or "https://h.example.invalid/brainbox/v1"
    env["SANDBOX_API_KEY"] = env.get("SANDBOX_API_KEY") or env.get("OPEN_SANDBOX_API_KEY") or ""
    env.pop("PATCHEVAL_SANDBOX_IMAGE_MAP_FILE", None)
    env["GLM_API_KEY"] = keys[0]
    env["PATCHEVAL_API_KEYS"] = ",".join(keys)
    env["PATCHEVAL_RUNTIME"] = "sandbox_api"
    env["PATCHEVAL_API_KEY_PROXY"] = "off"
    env["PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY"] = "0"
    env["PATCHEVAL_SANDBOX_INTERNAL_PROXY"] = "0"
    env["PATCHEVAL_OPENCODE_REASONING"] = env.get("PATCHEVAL_OPENCODE_REASONING", "0")
    env["PATCH_EVAL_DROP_REASONING_EFFORT"] = env.get("PATCH_EVAL_DROP_REASONING_EFFORT", "1")
    env.pop("PATCHEVAL_OPENCODE_HEADERS_JSON", None)
    env["PATCHEVAL_SANDBOX_STOP_AFTER"] = "1"
    env["PATCHEVAL_SANDBOX_CPU"] = env.get("PATCHEVAL_SANDBOX_CPU", "4")
    env["PATCHEVAL_SANDBOX_MEMORY"] = env.get("PATCHEVAL_SANDBOX_MEMORY", "8Gi")
    env["PATCHEVAL_SANDBOX_REQUEST_CPU"] = env.get("PATCHEVAL_SANDBOX_REQUEST_CPU", "500m")
    env["PATCHEVAL_SANDBOX_REQUEST_MEMORY"] = env.get("PATCHEVAL_SANDBOX_REQUEST_MEMORY", "1Gi")
    env["PATCHEVAL_SANDBOX_INSTANCE_CAPACITY"] = env.get("PATCHEVAL_SANDBOX_INSTANCE_CAPACITY", "300")
    env["PATCHEVAL_SANDBOX_LIFECYCLE_MINUTES"] = env.get("PATCHEVAL_SANDBOX_LIFECYCLE_MINUTES", "1440")
    env["PATCHEVAL_SANDBOX_START_TIMEOUT"] = env.get("PATCHEVAL_SANDBOX_START_TIMEOUT", "1800")
    env["PATCHEVAL_SANDBOX_REQUEST_TIMEOUT"] = env.get("PATCHEVAL_SANDBOX_REQUEST_TIMEOUT", "7200")
    env["PATCHEVAL_SANDBOX_CREATE_CAPACITY_WAIT_SECONDS"] = env.get(
        "PATCHEVAL_SANDBOX_CREATE_CAPACITY_WAIT_SECONDS", "7200"
    )
    env["PATCHEVAL_SANDBOX_ENV_CACHE"] = str(exp_root / "sandbox_env_cache.json")
    env["PATCHEVAL_SANDBOX_ENV_NAME_SUFFIX"] = "qwen-secbench-d14"
    env["PATCHEVAL_SANDBOX_IMAGE_PREFIXES"] = env.get(
        "PATCHEVAL_SANDBOX_IMAGE_PREFIXES",
        "registry-v2.h.example.invalid/ailab-ai4good1",
    )
    env["SECBENCH_IMAGE_TEMPLATE"] = SECBENCH_IMAGE_TEMPLATE
    env["SECBENCH_SANDBOX_IMAGE_REPOSITORY"] = SECBENCH_IMAGE_REPOSITORY
    env["STAGE_TIMEOUT_SECONDS"] = env.get("STAGE_TIMEOUT_SECONDS", "7200")
    env["ANALYSIS_TIMEOUT_SECONDS"] = env.get("ANALYSIS_TIMEOUT_SECONDS", "10800")
    env["REPAIR_TIMEOUT_SECONDS"] = env.get("REPAIR_TIMEOUT_SECONDS", "7200")
    env["REPRODUCER_TIMEOUT_SECONDS"] = env.get("REPRODUCER_TIMEOUT_SECONDS", "300")
    env["SECBENCH_OFFICIAL_EVAL_TIMEOUT_SECONDS"] = env.get("SECBENCH_OFFICIAL_EVAL_TIMEOUT_SECONDS", "600")
    env["PATCHEVAL_PERSIST_OPENCODE_SESSION_TRACE"] = env.get("PATCHEVAL_PERSIST_OPENCODE_SESSION_TRACE", "0")
    env["PATCHEVAL_COPY_CONTAINER_ARTIFACTS"] = env.get("PATCHEVAL_COPY_CONTAINER_ARTIFACTS", "0")
    env["PATCHEVAL_OPENCODE_SETUP_MAX_CONCURRENCY"] = str(args.max_workers)
    env["PATCHEVAL_PRE_MAS_MAX_CONCURRENCY"] = str(args.max_workers)
    env["PATCHEVAL_OPENCODE_RUN_MAX_CONCURRENCY"] = str(args.max_workers)
    env["PYTHONPATH"] = str(PATCH_EVAL / "patcheval/exp_agent/opencode") + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    for proxy_key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "PATCH_EVAL_HTTP_PROXY",
        "PATCH_EVAL_HTTPS_PROXY",
        "PATCH_EVAL_ALL_PROXY",
    ):
        env.pop(proxy_key, None)

    if not args.skip_smoke:
        print(f"==== smoke inference {args.smoke_id} ====", flush=True)
        write_status(exp_root, {"phase": "smoke", "smoke_id": args.smoke_id})
        smoke_root = exp_root / "smoke"
        smoke_infer = smoke_root / "inference"
        smoke_list = smoke_root / "manifest.txt"
        prepare_task_list(smoke_list, [args.smoke_id])
        rc = run_inference_round(
            py=args.python,
            env=env,
            inference_root=smoke_infer,
            dataset_path=SECBENCH_DATASET,
            task_list=smoke_list,
            model=args.agent_model,
            base_url=args.base_url,
            max_workers=1,
            log_path=logs_dir / "smoke_inference.log",
        )
        smoke_class = classify_result(args.smoke_id, smoke_infer)
        write_json(smoke_root / "classification.json", smoke_class)
        print(json.dumps({"smoke_rc": rc, **smoke_class}, ensure_ascii=False), flush=True)
        if smoke_class["status"] == "retryable_env_fail" and not smoke_class.get("container_id"):
            print("Smoke failed before a sandbox was created. Stopping.", flush=True)
            write_status(exp_root, {"phase": "smoke_failed", "smoke": smoke_class})
            return 3

    latest_rows = collect_existing(inference_root, all_ids)
    for instance_id in all_ids:
        latest_rows.setdefault(instance_id, missing_placeholder(instance_id))

    for round_idx in range(1, args.max_rounds + 1):
        if round_idx == 1:
            todo = [item for item in all_ids if latest_rows[item].get("retryable") or latest_rows[item]["status"] == "missing"]
        else:
            todo = [row["instance_id"] for row in latest_rows.values() if row.get("retryable")]
            if not todo:
                break
            archive_before_retry(
                inference_root,
                exp_root / "rounds" / f"round{round_idx:02d}" / "cleared_before_retry",
                todo,
            )

        if not todo:
            break

        print(f"==== inference round {round_idx} count={len(todo)} ====", flush=True)
        write_status(
            exp_root,
            {
                "phase": "inference",
                "round": round_idx,
                "todo": len(todo),
                "valid": sum(1 for row in latest_rows.values() if row.get("included_in_stats")),
                "retryable": sum(1 for row in latest_rows.values() if row.get("retryable")),
            },
        )
        round_list = exp_root / "manifests" / f"round{round_idx:02d}.txt"
        prepare_task_list(round_list, todo)
        rc = run_inference_round(
            py=args.python,
            env=env,
            inference_root=inference_root,
            dataset_path=SECBENCH_DATASET,
            task_list=round_list,
            model=args.agent_model,
            base_url=args.base_url,
            max_workers=min(args.max_workers, max(1, len(todo))),
            log_path=logs_dir / f"round{round_idx:02d}_inference.log",
        )
        snapshot_round(exp_root / "rounds" / f"round{round_idx:02d}", inference_root, todo)
        for instance_id in todo:
            row = classify_result(instance_id, inference_root)
            row["source_round"] = f"round{round_idx:02d}"
            row["included_in_stats"] = not row["retryable"]
            row["inference_rc"] = rc
            latest_rows[instance_id] = row
        for instance_id in all_ids:
            latest_rows.setdefault(instance_id, missing_placeholder(instance_id))
        ordered = [latest_rows[instance_id] for instance_id in all_ids]
        write_ledger(exp_root, ordered)
        print(
            json.dumps(
                {
                    "round": round_idx,
                    "todo": len(todo),
                    "valid": sum(1 for row in ordered if row.get("included_in_stats")),
                    "retryable": sum(1 for row in ordered if row.get("retryable")),
                    "success_patches": sum(1 for row in ordered if row.get("status") == "valid_success"),
                },
                ensure_ascii=False,
            ),
            flush=True,
        )

    ordered = [latest_rows[instance_id] for instance_id in all_ids]
    valid_rows = [row for row in ordered if row.get("included_in_stats")]
    write_json(
        exp_root / "ledger" / "stats_pre_eval.json",
        {
            "listed": len(all_ids),
            "valid_for_stats": len(valid_rows),
            "still_retryable": sum(1 for row in ordered if row.get("retryable")),
            "valid_success": sum(1 for row in valid_rows if row["status"] == "valid_success"),
            "valid_with_patch": sum(1 for row in valid_rows if row["status"] == "valid_with_patch"),
            "valid_model_fail": sum(1 for row in valid_rows if row["status"] == "valid_model_fail"),
        },
    )
    write_ledger(exp_root, ordered)

    if args.skip_eval:
        write_status(exp_root, {"phase": "inference_complete_eval_skipped", "valid": len(valid_rows)})
        print(f"exp_root={exp_root}", flush=True)
        return 0

    official_dir = exp_root / "evaluation" / "official"
    eval_input_dir = exp_root / "evaluation" / "eval_input"
    eval_ids = [row["instance_id"] for row in valid_rows]
    eval_rc = 0
    for eval_round in range(1, args.max_eval_rounds + 1):
        if not eval_ids:
            break
        print(f"==== official eval round {eval_round} on {len(eval_ids)} entries ====", flush=True)
        write_status(
            exp_root,
            {
                "phase": "official_eval",
                "eval_round": eval_round,
                "eval_todo": len(eval_ids),
            },
        )
        eval_list = exp_root / "manifests" / f"eval_round{eval_round:02d}.txt"
        prepare_task_list(eval_list, eval_ids)
        eval_rc = run_official_eval(
            py=args.eval_python,
            env=env,
            exp_root=exp_root,
            task_list=eval_list,
            inference_root=inference_root,
            official_dir=official_dir,
            eval_input_dir=eval_input_dir,
            max_workers=min(args.eval_max_workers, max(1, len(eval_ids))),
            log_path=logs_dir / f"official_eval_round{eval_round:02d}.log",
        )
        ordered = attach_eval_results(ordered, official_dir)
        write_ledger(exp_root, ordered)
        eval_ids = [
            row["instance_id"]
            for row in ordered
            if row.get("included_in_stats") and row.get("eval_retryable")
        ]
        if not eval_ids:
            break

    write_json(
        exp_root / "ledger" / "final_summary.json",
        {
            "listed": len(all_ids),
            "valid_for_stats": sum(1 for row in ordered if row.get("included_in_stats")),
            "eval_strict_pass": sum(1 for row in ordered if row.get("eval_strict") == "pass"),
            "eval_medium_pass": sum(1 for row in ordered if row.get("eval_medium") == "pass"),
            "eval_generous_pass": sum(1 for row in ordered if row.get("eval_generous") == "pass"),
            "eval_fail_strict": sum(1 for row in ordered if row.get("eval_strict") == "fail"),
            "excluded_env_fail": sum(1 for row in ordered if not row.get("included_in_stats")),
            "eval_still_retryable": sum(1 for row in ordered if row.get("eval_retryable")),
            "official_eval_rc": eval_rc,
            "eval_dir": str(official_dir),
            "valid_entries_csv": str(exp_root / "ledger" / "valid_for_stats.csv"),
        },
    )
    write_status(
        exp_root,
        {
            "phase": "complete",
            "valid_for_stats": sum(1 for row in ordered if row.get("included_in_stats")),
            "eval_strict_pass": sum(1 for row in ordered if row.get("eval_strict") == "pass"),
            "official_eval_rc": eval_rc,
        },
    )
    print(f"official_eval_rc={eval_rc}", flush=True)
    print(f"exp_root={exp_root}", flush=True)
    return 0 if eval_rc == 0 else eval_rc


if __name__ == "__main__":
    raise SystemExit(main())
