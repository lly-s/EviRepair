#!/usr/bin/env python3
"""Run OpenCode + deepseek-v4.1-flash on PatchEval-230 with sandbox images.

Inference uses the existing D14 OpenCode batch runner. Official scoring uses
the PatchEval-Verified sandbox evaluator. Environment/retryable failures are
re-run after the first 230-case pass, and a ledger records the valid entry
chosen from each round.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


D_ROOT = Path(__file__).resolve().parents[1]
PATCH_EVAL = Path(
    os.environ.get(
        "PATCH_EVAL",
        "/path/to/local/resource",
    )
)
VERIFIED_PATCH_EVAL = Path(
    os.environ.get(
        "VERIFIED_PATCH_EVAL",
        "/path/to/local/resource",
    )
)
VERIFIED_DATASET = Path(
    os.environ.get(
        "VERIFIED_DATASET",
        str(VERIFIED_PATCH_EVAL / "patcheval/datasets/patcheval_verified.json"),
    )
)
VERIFIED_IMAGE_PREFIX = os.environ.get(
    "VERIFIED_IMAGE_PREFIX",
    "registry-v2.h.example.invalid/ailab-ai4good1/patcheval-cve-verified",
).rstrip("/")
EVAL_SCRIPT = Path(
    os.environ.get(
        "EVAL_SCRIPT",
        str(VERIFIED_PATCH_EVAL / "patcheval/evaluation/run_evaluation_sandbox_api.py"),
    )
)
PROCESS_DATA_PY = VERIFIED_PATCH_EVAL / "patcheval/exp_agent/process_data.py"
BATCH_PY = D_ROOT / "scripts/run_full_no_knowledge_chain_batch.py"
CVE_LIST_230 = Path(os.environ.get("PATCHEVAL_CASE_LIST", str(D_ROOT / "patcheval-dataset/230.txt")))
DEFAULT_EXP_ROOT = D_ROOT / "outputs/deepseek_patcheval"
DEFAULT_PY = Path(os.environ.get("PY", str(PATCH_EVAL / ".venv/bin/python")))

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
}


def read_cve_list(path: Path) -> List[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def repo_basename(repo_url: str) -> str:
    name = str(repo_url or "").rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    if not name:
        raise SystemExit("verified dataset sample missing repo")
    return name


def image_tag(row: Dict[str, Any], pid: str) -> str:
    image = str(row.get("image_url") or "")
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        return last.rsplit(":", 1)[-1]
    return str(pid).lower()


def prepare_dataset(dataset_path: Path, manifest_path: Path, selected: Iterable[str]) -> int:
    selected_list = [str(item) for item in selected]
    selected_set = set(selected_list)
    src_rows = read_json(VERIFIED_DATASET)
    by_id = {row.get("cve_id"): row for row in src_rows}
    missing = [cve for cve in selected_list if cve not in by_id]
    if missing:
        raise SystemExit(f"CVE list includes ids missing from dataset: {missing}")
    rows = []
    for cve in selected_list:
        row = by_id[cve]
        description = str(row.get("cve_description") or "").strip()
        if not description:
            raise SystemExit(f"verified dataset sample {cve} missing cve_description")
        image_name = f"{VERIFIED_IMAGE_PREFIX}:{image_tag(row, cve)}"
        rows.append(
            {
                "cve_id": cve,
                "image_name": image_name,
                "image_url": image_name,
                "work_dir": f"/workspace/{repo_basename(row.get('repo'))}",
                "problem_statement": description,
                "cve_description": description,
                "fix_patch": "",
                "repo": row.get("repo", ""),
            }
        )
    dataset_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    dataset_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    manifest_path.write_text("".join(cve + "\n" for cve in selected_list), encoding="utf-8")
    return len(rows)


def patch_bytes(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def classify_result(cve: str, inference_root: Path) -> Dict[str, Any]:
    process_path = inference_root / "process_logs" / f"{cve}.process.json"
    patch_path = inference_root / "patches" / f"{cve}.patch"
    process: Dict[str, Any] = {}
    if process_path.exists():
        try:
            loaded = read_json(process_path)
            if isinstance(loaded, dict):
                process = loaded
        except Exception:
            process = {"error_message": "process.json is unreadable"}
    error = str(process.get("error_message") or "")
    stage = str(process.get("stage") or "")
    success = bool(process.get("is_success"))
    has_patch = patch_bytes(patch_path) > 0
    retryable = (not success) and (
        bool(RETRYABLE_RE.search(error))
        or stage in INFRA_STAGES
        or not process_path.exists()
    )
    if success and has_patch:
        status = "valid_success"
        retryable = False
    elif has_patch:
        status = "valid_with_patch"
        retryable = False
    elif retryable:
        status = "retryable_env_fail"
    else:
        status = "valid_model_fail"
    return {
        "cve": cve,
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
    }


def snapshot_round(round_dir: Path, inference_root: Path, cves: List[str]) -> None:
    dest_logs = round_dir / "process_logs"
    dest_patches = round_dir / "patches"
    dest_logs.mkdir(parents=True, exist_ok=True)
    dest_patches.mkdir(parents=True, exist_ok=True)
    for cve in cves:
        src_log = inference_root / "process_logs" / f"{cve}.process.json"
        src_patch = inference_root / "patches" / f"{cve}.patch"
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
    fields = [
        "cve",
        "included_in_stats",
        "status",
        "source_round",
        "is_success",
        "has_patch",
        "patch_bytes",
        "eval_result",
        "stage",
        "error",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    retry_path = ledger_dir / "retry_queue.txt"
    retry_path.write_text(
        "".join(row["cve"] + "\n" for row in rows if row.get("retryable")),
        encoding="utf-8",
    )


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
    manifest_path: Path,
    model: str,
    base_url: str,
    max_workers: int,
    log_path: Path,
) -> int:
    command = [
        str(py),
        str(BATCH_PY),
        "--cve-list",
        str(manifest_path),
        "--dataset",
        str(dataset_path),
        "--outputs-root",
        str(inference_root),
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
        "--skip-postprocess",
        "--container-name-suffix",
        "deepseek_patcheval",
    ]
    return run_cmd(command, D_ROOT, env, log_path)


def build_eval_input(valid_rows: List[Dict[str, Any]], inference_root: Path, out_path: Path) -> int:
    dataset = read_json(VERIFIED_DATASET)
    cve2lang = {item["cve_id"]: item["programing_language"] for item in dataset}
    cve2image = {item["cve_id"]: item.get("image_url", "") for item in dataset}
    rows = []
    for item in valid_rows:
        cve = item["cve"]
        patch = ""
        patch_path = Path(item.get("patch_path") or inference_root / "patches" / f"{cve}.patch")
        if patch_path.exists():
            patch = patch_path.read_text(encoding="utf-8", errors="replace")
        image = cve2image.get(cve, "")
        tag = image.rsplit(":", 1)[-1] if ":" in str(image) else cve.lower()
        rows.append(
            {
                "cve": cve,
                "language": cve2lang[cve],
                "image_url": f"{VERIFIED_IMAGE_PREFIX}:{tag}",
                "fix_patch": patch,
            }
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return len(rows)


def run_official_eval(
    *,
    py: Path,
    env: Dict[str, str],
    exp_root: Path,
    patch_file: Path,
    max_workers: int,
) -> int:
    eval_dir = exp_root / "evaluation"
    eval_dir.mkdir(parents=True, exist_ok=True)
    command = [
        str(py),
        str(EVAL_SCRIPT),
        "--output",
        "official",
        "--patch_file",
        str(patch_file),
        "--input_file",
        str(VERIFIED_DATASET),
        "--max_workers",
        str(max_workers),
        "--log_level",
        "INFO",
    ]
    return run_cmd(command, eval_dir, env, exp_root / "logs" / "official_eval.log")


def attach_eval_results(rows: List[Dict[str, Any]], exp_root: Path) -> List[Dict[str, Any]]:
    summary_path = exp_root / "evaluation" / "evaluation_output" / "official" / "summary.json"
    if not summary_path.exists():
        return rows
    summary = read_json(summary_path)
    success = set()
    for cves in (summary.get("poc_evaluation") or {}).get("successful_cves", {}).values():
        success.update(cves)
    failed = set()
    for cves in (summary.get("failure_analysis") or {}).get("failed_cves", {}).values():
        failed.update(cves)
    for row in rows:
        cve = row["cve"]
        if cve in success:
            row["eval_result"] = "pass"
        elif cve in failed:
            row["eval_result"] = "fail"
        elif not row.get("included_in_stats"):
            row["eval_result"] = "excluded"
        else:
            row["eval_result"] = "unknown"
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exp-root", type=Path, default=DEFAULT_EXP_ROOT)
    parser.add_argument("--python", type=Path, default=DEFAULT_PY)
    parser.add_argument("--model", default=os.environ.get("PATCHEVAL_REMOTE_MODEL", "deepseek-v4.1-flash"))
    parser.add_argument("--agent-model", default=os.environ.get("MODEL", "openai/deepseek-v4.1-flash"))
    parser.add_argument("--base-url", default=os.environ.get("GLM_API_BASE", "http://api.example.invalid/v1"))
    parser.add_argument("--max-workers", type=int, default=int(os.environ.get("MAX_WORKERS", "30")))
    parser.add_argument("--eval-max-workers", type=int, default=int(os.environ.get("EVAL_MAX_WORKERS", "30")))
    parser.add_argument("--max-rounds", type=int, default=4)
    parser.add_argument("--skip-smoke", action="store_true")
    parser.add_argument("--smoke-cve", default="CVE-2021-23376")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    keys = [item.strip() for item in os.environ.get("PATCHEVAL_API_KEYS", "").split(",") if item.strip()]
    if not keys:
        raise SystemExit("PATCHEVAL_API_KEYS must contain the rotating API keys")
    if not os.environ.get("OPEN_SANDBOX_API_KEY"):
        raise SystemExit("OPEN_SANDBOX_API_KEY is required")

    exp_root = args.exp_root.resolve()
    inference_root = exp_root / "aggregated" / "inference"
    logs_dir = exp_root / "logs"
    inference_root.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    write_json(
        exp_root / "experiment_config.json",
        {
            "benchmark": "patcheval",
            "model": args.model,
            "agent_model": args.agent_model,
            "base_url": args.base_url,
            "key_count": len(keys),
            "max_workers": args.max_workers,
            "eval_max_workers": args.eval_max_workers,
            "runtime": "sandbox_api",
            "sandbox_project": os.environ.get("SANDBOX_PROJECT"),
            "image_prefix": VERIFIED_IMAGE_PREFIX,
            "case_list": str(CVE_LIST_230),
            "evaluator": str(EVAL_SCRIPT),
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
        print("API preflight failed; not starting the 230-case run.", flush=True)
        print(json.dumps(preflight, ensure_ascii=False, indent=2), flush=True)
        return 2
    print(f"API preflight ok for {len(keys)} keys; model={args.model}", flush=True)

    env = os.environ.copy()
    env["GLM_API_KEY"] = keys[0]
    env["PATCHEVAL_API_KEYS"] = ",".join(keys)
    env["PATCHEVAL_RUNTIME"] = "sandbox_api"
    env["PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY"] = "0"
    env["PATCHEVAL_SANDBOX_INTERNAL_PROXY"] = "0"
    env["PATCHEVAL_OPENCODE_REASONING"] = env.get("PATCHEVAL_OPENCODE_REASONING", "0")
    env["PATCH_EVAL_DROP_REASONING_EFFORT"] = env.get("PATCH_EVAL_DROP_REASONING_EFFORT", "1")
    env.pop("PATCHEVAL_OPENCODE_HEADERS_JSON", None)
    env["PATCHEVAL_SANDBOX_STOP_AFTER"] = "1"
    env["PATCHEVAL_SANDBOX_CPU"] = env.get("PATCHEVAL_SANDBOX_CPU", "4")
    env["PATCHEVAL_SANDBOX_MEMORY"] = env.get("PATCHEVAL_SANDBOX_MEMORY", "8Gi")
    env["PATCHEVAL_SANDBOX_INSTANCE_CAPACITY"] = env.get("PATCHEVAL_SANDBOX_INSTANCE_CAPACITY", "230")
    env["PATCHEVAL_SANDBOX_ENV_CACHE"] = str(exp_root / "sandbox_env_cache.json")
    env["PATCHEVAL_SANDBOX_ENV_NAME_SUFFIX"] = "deepseek-patcheval-d14"
    env["PATCHEVAL_OPENCODE_SETUP_MAX_CONCURRENCY"] = str(args.max_workers)
    env["PATCHEVAL_PRE_MAS_MAX_CONCURRENCY"] = str(args.max_workers)
    env["PATCHEVAL_OPENCODE_RUN_MAX_CONCURRENCY"] = str(args.max_workers)
    env["PYTHONPATH"] = str(PATCH_EVAL / "patcheval/exp_agent/opencode") + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )

    all_cves = read_cve_list(CVE_LIST_230)
    if len(all_cves) != 230:
        raise SystemExit(f"expected 230 CVEs, got {len(all_cves)}")

    if not args.skip_smoke:
        print(f"==== smoke inference {args.smoke_cve} ====", flush=True)
        smoke_root = exp_root / "smoke"
        smoke_infer = smoke_root / "inference"
        smoke_dataset = smoke_root / "dataset.jsonl"
        smoke_manifest = smoke_root / "manifest.txt"
        prepare_dataset(smoke_dataset, smoke_manifest, [args.smoke_cve])
        rc = run_inference_round(
            py=args.python,
            env=env,
            inference_root=smoke_infer,
            dataset_path=smoke_dataset,
            manifest_path=smoke_manifest,
            model=args.agent_model,
            base_url=args.base_url,
            max_workers=1,
            log_path=logs_dir / "smoke_inference.log",
        )
        smoke_class = classify_result(args.smoke_cve, smoke_infer)
        write_json(smoke_root / "classification.json", smoke_class)
        print(json.dumps({"smoke_rc": rc, **smoke_class}, ensure_ascii=False), flush=True)
        if smoke_class["status"] == "retryable_env_fail" and not smoke_class.get("container_id"):
            print("Smoke failed before a sandbox was created. Stopping.", flush=True)
            return 3

    dataset_path = exp_root / "datasets" / "patcheval_230.jsonl"
    manifest_path = exp_root / "manifests" / "patcheval_230.txt"
    prepare_dataset(dataset_path, manifest_path, all_cves)

    latest_rows: Dict[str, Dict[str, Any]] = {}
    for round_idx in range(1, args.max_rounds + 1):
        if round_idx == 1:
            todo = all_cves
        else:
            todo = [row["cve"] for row in latest_rows.values() if row.get("retryable")]
            if not todo:
                break
            round_dir = exp_root / "rounds" / f"round{round_idx:02d}"
            archived = round_dir / "cleared_before_retry"
            archived.mkdir(parents=True, exist_ok=True)
            for cve in todo:
                for rel in (f"process_logs/{cve}.process.json", f"patches/{cve}.patch"):
                    src = inference_root / rel
                    if src.exists():
                        dest = archived / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dest)
                        src.unlink()

        print(f"==== inference round {round_idx} count={len(todo)} ====", flush=True)
        round_manifest = exp_root / "manifests" / f"round{round_idx:02d}.txt"
        round_dataset = exp_root / "datasets" / f"round{round_idx:02d}.jsonl"
        prepare_dataset(round_dataset, round_manifest, todo)
        rc = run_inference_round(
            py=args.python,
            env=env,
            inference_root=inference_root,
            dataset_path=round_dataset,
            manifest_path=round_manifest,
            model=args.agent_model,
            base_url=args.base_url,
            max_workers=args.max_workers if round_idx > 1 or len(todo) > 1 else min(args.max_workers, len(todo)),
            log_path=logs_dir / f"round{round_idx:02d}_inference.log",
        )
        snapshot_round(exp_root / "rounds" / f"round{round_idx:02d}", inference_root, todo)
        for cve in todo:
            row = classify_result(cve, inference_root)
            row["source_round"] = f"round{round_idx:02d}"
            row["included_in_stats"] = not row["retryable"]
            row["eval_result"] = ""
            row["inference_rc"] = rc
            latest_rows[cve] = row
        # Keep previously valid rows.
        for cve in all_cves:
            latest_rows.setdefault(
                cve,
                {
                    "cve": cve,
                    "status": "missing",
                    "retryable": True,
                    "included_in_stats": False,
                    "source_round": "",
                    "is_success": False,
                    "has_patch": False,
                    "patch_bytes": 0,
                    "eval_result": "",
                    "stage": "",
                    "error": "not run yet",
                },
            )
        ordered = [latest_rows[cve] for cve in all_cves]
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

    ordered = [latest_rows[cve] for cve in all_cves]
    valid_rows = [row for row in ordered if row.get("included_in_stats")]
    patch_file = exp_root / "aggregated" / "official_eval_input.jsonl"
    build_eval_input(valid_rows, inference_root, patch_file)
    write_json(
        exp_root / "ledger" / "stats_pre_eval.json",
        {
            "listed": len(all_cves),
            "valid_for_stats": len(valid_rows),
            "still_retryable": sum(1 for row in ordered if row.get("retryable")),
            "valid_success": sum(1 for row in valid_rows if row["status"] == "valid_success"),
            "valid_with_patch": sum(1 for row in valid_rows if row["status"] == "valid_with_patch"),
            "valid_model_fail": sum(1 for row in valid_rows if row["status"] == "valid_model_fail"),
        },
    )
    print(f"==== official eval on {len(valid_rows)} valid entries ====", flush=True)
    eval_rc = run_official_eval(
        py=args.python,
        env=env,
        exp_root=exp_root,
        patch_file=patch_file,
        max_workers=args.eval_max_workers,
    )
    ordered = attach_eval_results(ordered, exp_root)
    write_ledger(exp_root, ordered)
    write_json(
        exp_root / "ledger" / "final_summary.json",
        {
            "listed": len(all_cves),
            "valid_for_stats": sum(1 for row in ordered if row.get("included_in_stats")),
            "eval_pass": sum(1 for row in ordered if row.get("eval_result") == "pass"),
            "eval_fail": sum(1 for row in ordered if row.get("eval_result") == "fail"),
            "excluded_env_fail": sum(1 for row in ordered if not row.get("included_in_stats")),
            "official_eval_rc": eval_rc,
            "eval_dir": str(exp_root / "evaluation" / "evaluation_output" / "official"),
        },
    )
    print(f"official_eval_rc={eval_rc}", flush=True)
    print(f"exp_root={exp_root}", flush=True)
    return 0 if eval_rc == 0 else eval_rc


if __name__ == "__main__":
    raise SystemExit(main())
