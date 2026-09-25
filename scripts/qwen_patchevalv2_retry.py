#!/usr/bin/env python3
"""Initialize and update the qwen_patchevalv2 retry ledger.

Successful retries are recorded with artifact paths and are omitted from
retry_todo.txt so later rounds do not rerun them.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


V1_ROOT = Path(
    "<REPOSITORY_ROOT>/"
    "d14-opencode-morebasemodel/outputs/qwen_patcheval"
)
V2_ROOT = Path(
    "<REPOSITORY_ROOT>/"
    "d14-opencode-morebasemodel/outputs/qwen_patchevalv2"
)
DEFAULT_LEDGER = V2_ROOT / "retry_list.json"
DEFAULT_TODO = V2_ROOT / "retry_todo.txt"
DEFAULT_CSV = V2_ROOT / "retry_list.csv"

PATH_PROMPT_TARGETS = [
    "CVE-2024-3848",
    "CVE-2021-31542",
    "CVE-2024-39330",
    "CVE-2021-32804",
    "CVE-2024-25620",
    "CVE-2021-36157",
    "CVE-2018-12976",
    "CVE-2024-23334",
    "CVE-2020-4053",
    "CVE-2021-33203",
]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _is_apply_fail(cve: str) -> bool:
    log = V1_ROOT / "evaluation/evaluation_output/official/logs" / cve / "error_output.log"
    if not log.exists():
        return False
    text = log.read_text(encoding="utf-8", errors="replace").lower()
    return "git apply" in text and "fail" in text


def _cluster(cve: str, infer_status: str, apply_fail: bool, cwe_ids: List[str]) -> str:
    if infer_status == "valid_model_fail":
        return "analysis_json_or_model_fail"
    if apply_fail or infer_status == "valid_with_patch":
        return "unapplyable_or_corrupt_patch"
    if cve in PATH_PROMPT_TARGETS or ({"CWE-22", "CWE-73"} & set(cwe_ids)):
        return "path_wrong_layer_or_incomplete"
    if "CWE-601" in cwe_ids:
        return "open_redirect"
    if {"CWE-862", "CWE-863", "CWE-285", "CWE-639"} & set(cwe_ids):
        return "authorization"
    return "other_functional_fail"


def init_ledger(ledger_path: Path = DEFAULT_LEDGER) -> Dict[str, Any]:
    summary = read_json(V1_ROOT / "evaluation/evaluation_output/official/summary.json")
    ledger_v1 = {row["cve"]: row for row in read_json(V1_ROOT / "ledger/valid_entries.json")}
    dataset = {
        item["cve_id"]: item
        for item in read_json(
            Path(
                "/path/to/local/resource"
                "patcheval-verified/patcheval/datasets/patcheval_verified.json"
            )
        )
    }
    failed: Dict[str, str] = {}
    for kind, cves in (summary.get("failure_analysis") or {}).get("failed_cves", {}).items():
        for cve in cves:
            failed[cve] = kind
    cases = []
    for cve in sorted(failed):
        v1 = ledger_v1.get(cve, {})
        info = dataset.get(cve, {})
        cwe_ids = sorted((info.get("cwe_info") or {}).keys())
        apply_fail = _is_apply_fail(cve)
        infer_status = str(v1.get("status") or "")
        cases.append(
            {
                "cve": cve,
                "retry_status": "todo",
                "source_eval_result": "fail",
                "official_fail_type": failed[cve],
                "infer_status_v1": infer_status,
                "cluster": _cluster(cve, infer_status, apply_fail, cwe_ids),
                "cwes": cwe_ids,
                "language": info.get("programing_language") or "",
                "repo": info.get("repo") or "",
                "prompt_target": cve in PATH_PROMPT_TARGETS,
                "success_round": "",
                "success_records": {},
                "attempts": [],
            }
        )
    payload = {
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_eval": str(V1_ROOT / "evaluation/evaluation_output/official/summary.json"),
        "source_ledger": str(V1_ROOT / "ledger/valid_entries.json"),
        "listed": len(cases),
        "note": (
            "Retry only these eval-failed cases. Once a case is retry_status=success, "
            "later rounds must skip it. success_records point at the winning artifacts."
        ),
        "cases": cases,
    }
    write_ledger_files(payload, ledger_path)
    return payload


def load_ledger(ledger_path: Path = DEFAULT_LEDGER) -> Dict[str, Any]:
    if not ledger_path.exists():
        return init_ledger(ledger_path)
    return read_json(ledger_path)


def write_ledger_files(payload: Dict[str, Any], ledger_path: Path = DEFAULT_LEDGER) -> None:
    write_json(ledger_path, payload)
    todo_path = ledger_path.parent / DEFAULT_TODO.name
    csv_path = ledger_path.parent / DEFAULT_CSV.name
    todo = [row["cve"] for row in payload["cases"] if row.get("retry_status") != "success"]
    todo_path.write_text("".join(cve + "\n" for cve in todo), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "cve",
                "retry_status",
                "cluster",
                "official_fail_type",
                "infer_status_v1",
                "prompt_target",
                "success_round",
                "success_patch",
                "success_eval",
            ],
        )
        writer.writeheader()
        for row in payload["cases"]:
            rec = row.get("success_records") or {}
            writer.writerow(
                {
                    "cve": row["cve"],
                    "retry_status": row.get("retry_status"),
                    "cluster": row.get("cluster"),
                    "official_fail_type": row.get("official_fail_type"),
                    "infer_status_v1": row.get("infer_status_v1"),
                    "prompt_target": row.get("prompt_target"),
                    "success_round": row.get("success_round") or "",
                    "success_patch": rec.get("patch") or "",
                    "success_eval": rec.get("eval_dir") or rec.get("eval_log") or "",
                }
            )


def pending_cves(payload: Dict[str, Any], only: List[str] | None = None) -> List[str]:
    allowed = set(only) if only is not None else None
    out = []
    for row in payload["cases"]:
        if row.get("retry_status") == "success":
            continue
        if allowed is not None and row["cve"] not in allowed:
            continue
        out.append(row["cve"])
    return out


def update_from_exp(
    exp_root: Path,
    *,
    round_name: str,
    ledger_path: Path = DEFAULT_LEDGER,
    eval_output_name: str = "official",
) -> Dict[str, Any]:
    payload = load_ledger(ledger_path)
    by_cve = {row["cve"]: row for row in payload["cases"]}
    exp_root = exp_root.resolve()
    infer = exp_root / "aggregated" / "inference"
    eval_dir = exp_root / "evaluation" / "evaluation_output" / eval_output_name
    local_ledger = exp_root / "ledger" / "valid_entries.json"
    rows = read_json(local_ledger) if local_ledger.exists() else []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for item in rows:
        cve = item.get("cve")
        if cve not in by_cve:
            continue
        rec = by_cve[cve]
        process_path = item.get("process_path") or str(infer / "process_logs" / f"{cve}.process.json")
        patch_path = item.get("patch_path") or str(infer / "patches" / f"{cve}.patch")
        eval_log = eval_dir / "logs" / cve
        attempt = {
            "round": round_name,
            "at": now,
            "exp_root": str(exp_root),
            "infer_status": item.get("status"),
            "eval_result": item.get("eval_result"),
            "process_log": process_path,
            "patch": patch_path,
            "eval_dir": str(eval_log) if eval_log.exists() else str(eval_dir),
        }
        rec.setdefault("attempts", []).append(attempt)
        if item.get("eval_result") == "pass" and rec.get("retry_status") != "success":
            rec["retry_status"] = "success"
            rec["success_round"] = round_name
            rec["success_records"] = {
                "exp_root": str(exp_root),
                "process_log": process_path,
                "patch": patch_path,
                "eval_dir": str(eval_log) if eval_log.exists() else str(eval_dir),
                "ledger_row": str(local_ledger),
                "official_summary": str(eval_dir / "summary.json"),
            }
    payload["updated_at"] = now
    write_ledger_files(payload, ledger_path)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--update-from", type=Path)
    parser.add_argument("--round-name", default="")
    parser.add_argument("--eval-output-name", default="official")
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    args = parser.parse_args()
    if args.init:
        payload = init_ledger(args.ledger)
        print(json.dumps({"init": True, "listed": payload["listed"], "ledger": str(args.ledger)}, ensure_ascii=False))
        return 0
    if args.update_from:
        payload = update_from_exp(
            args.update_from,
            round_name=args.round_name or args.update_from.name,
            ledger_path=args.ledger,
            eval_output_name=args.eval_output_name,
        )
        success = sum(1 for row in payload["cases"] if row.get("retry_status") == "success")
        print(
            json.dumps(
                {"updated": True, "success": success, "todo": payload["listed"] - success, "ledger": str(args.ledger)},
                ensure_ascii=False,
            )
        )
        return 0
    raise SystemExit("use --init or --update-from EXP_ROOT")


if __name__ == "__main__":
    raise SystemExit(main())
