#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List

import run_full_no_knowledge_chain_smoke as single

LOGGER = logging.getLogger('full-no-knowledge-chain-batch')


def read_task_list(path: Path) -> List[str]:
    task_ids: List[str] = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        task_ids.append(line)
    return task_ids


def load_existing_result(path: Path) -> Dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def _assign_rotated_key(args: argparse.Namespace, launch_index: int) -> argparse.Namespace:
    raw = os.environ.get('PATCHEVAL_API_KEYS', '').strip()
    keys = [item.strip() for item in raw.split(',') if item.strip()]
    ns = argparse.Namespace(**vars(args))
    if keys:
        ns.agent_api_key = keys[launch_index % len(keys)]
        ns.agent_key_index = launch_index % len(keys)
    return ns


def run_one(args: argparse.Namespace, task_id: str, launch_index: int = 0) -> Dict[str, Any]:
    outputs = Path(args.outputs_root)
    process_log = outputs / 'process_logs' / f'{task_id}.process.json'
    final_patch = outputs / 'patches' / f'{task_id}.patch'
    if args.resume:
        existing = load_existing_result(process_log)
        if existing and existing.get('is_success') and final_patch.exists() and final_patch.stat().st_size > 0:
            skipped = dict(existing)
            skipped['skipped_resume'] = True
            return skipped
    jitter_seconds = float(getattr(args, 'worker_launch_jitter_seconds', 0) or 0)
    if jitter_seconds > 0 and args.max_workers > 0:
        delay = jitter_seconds * (launch_index % args.max_workers)
        if delay > 0:
            LOGGER.info('worker launch jitter task=%s index=%s delay=%.2fs', task_id, launch_index, delay)
            time.sleep(delay)
    ns = _assign_rotated_key(args, launch_index)
    ns.cve_id = task_id
    return single.run(ns)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Batch runner for the no-knowledge full Test Case/Reproduction/Repair/Postprocess chain.')
    parser.add_argument('--cve-list', '--task-list', dest='task_list', type=Path, required=True)
    parser.add_argument('--max-workers', type=int, default=1)
    parser.add_argument('--worker-launch-jitter-seconds', type=float, default=float(os.getenv('PATCHEVAL_WORKER_LAUNCH_JITTER_SECONDS', '0')), help='Stagger worker start within each max-workers wave without reducing max_workers.')
    parser.add_argument('--resume', action='store_true')
    single.add_common_args(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    start = time.time()
    task_ids = read_task_list(args.task_list)
    outputs = Path(args.outputs_root)
    outputs.mkdir(parents=True, exist_ok=True)
    summary_path = outputs / 'batch_summary.json'
    print(json.dumps({'event': 'batch_start', 'count': len(task_ids), 'max_workers': args.max_workers, 'worker_launch_jitter_seconds': args.worker_launch_jitter_seconds, 'outputs_root': str(outputs)}, ensure_ascii=False), flush=True)

    results: List[Dict[str, Any]] = []
    with futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_task = {executor.submit(run_one, args, task_id, idx): task_id for idx, task_id in enumerate(task_ids)}
        completed = 0
        for fut in futures.as_completed(future_to_task):
            task_id = future_to_task[fut]
            try:
                result = fut.result()
            except Exception as exc:
                result = {'cve_id': task_id, 'task_id': task_id, 'problem_id': task_id, 'is_success': False, 'stage': 'batch_exception', 'error_message': str(exc)}
                LOGGER.exception('batch exception for %s', task_id)
            results.append(result)
            completed += 1
            event = {
                'event': 'record_done',
                'completed': completed,
                'total': len(task_ids),
                'cve_id': task_id,
                'task_id': task_id,
                'is_success': bool(result.get('is_success')),
                'stage': result.get('stage'),
                'error': str(result.get('error_message', ''))[:300],
            }
            print(json.dumps(event, ensure_ascii=False), flush=True)
            summary = {
                'count': len(task_ids),
                'completed': completed,
                'success': sum(1 for item in results if item.get('is_success')),
                'failed': sum(1 for item in results if not item.get('is_success')),
                'max_workers': args.max_workers,
                'worker_launch_jitter_seconds': args.worker_launch_jitter_seconds,
                'duration_seconds_so_far': time.time() - start,
                'outputs_root': str(outputs),
                'results': results,
            }
            summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    final = {
        'count': len(task_ids),
        'success': sum(1 for item in results if item.get('is_success')),
        'failed': sum(1 for item in results if not item.get('is_success')),
        'max_workers': args.max_workers,
        'worker_launch_jitter_seconds': args.worker_launch_jitter_seconds,
        'duration_seconds': time.time() - start,
        'outputs_root': str(outputs),
        'results': results,
    }
    summary_path.write_text(json.dumps(final, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'event': 'batch_complete', **{k: final[k] for k in ['count', 'success', 'failed', 'duration_seconds', 'outputs_root']}}, ensure_ascii=False), flush=True)
    return 0 if final['success'] > 0 or final['count'] == 0 else 2


if __name__ == '__main__':
    raise SystemExit(main())
