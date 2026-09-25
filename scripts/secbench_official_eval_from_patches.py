#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures as futures
import importlib
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

SANDBOX_RUNTIMES = {'sandbox', 'sandbox_api', 'brainbox'}
DEFAULT_SECBENCH_IMAGE_TEMPLATE = os.getenv(
    'SECBENCH_IMAGE_TEMPLATE',
    'registry-v2.h.example.invalid/ailab-ai4good1/secbench:{instance_id}-{task_type}',
)


def read_task_ids(path: Path) -> List[str]:
    return [
        line.strip()
        for line in path.read_text(encoding='utf-8').splitlines()
        if line.strip() and not line.lstrip().startswith('#')
    ]


def load_dataset_jsonl(path: Path) -> Dict[str, Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    with path.open(encoding='utf-8') as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            instance_id = str(row.get('instance_id') or '').strip()
            if not instance_id:
                raise SystemExit(f'{path}:{line_no} missing instance_id')
            rows[instance_id] = row
    return rows


def write_smolagent_patch_input(task_ids: Iterable[str], patches_dir: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_jsonl = output_dir / 'output.jsonl'
    with output_jsonl.open('w', encoding='utf-8') as handle:
        for task_id in task_ids:
            patch_path = patches_dir / f'{task_id}.patch'
            patch_text = patch_path.read_text(encoding='utf-8', errors='replace') if patch_path.exists() else ''
            row = {
                'instance_id': task_id,
                'test_result': {
                    'git_patch': patch_text,
                },
            }
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')
    return output_jsonl


def load_sandbox_client(runtime: str):
    os.environ['PATCHEVAL_RUNTIME'] = runtime
    patch_eval = Path(os.environ.get(
        'PATCH_EVAL',
        '/path/to/local/resource
    )).resolve()
    opencode_dir = Path(os.environ.get(
        'OPENCODE',
        str(patch_eval / 'patcheval' / 'exp_agent' / 'opencode'),
    )).resolve()
    if str(opencode_dir) not in sys.path:
        sys.path.insert(0, str(opencode_dir))
    patch_eval_venv = patch_eval / '.venv'
    if patch_eval_venv.exists():
        for site_packages in patch_eval_venv.glob('lib/python*/site-packages'):
            site_packages_str = str(site_packages.resolve())
            if site_packages_str not in sys.path:
                sys.path.append(site_packages_str)
    try:
        from patcheval import sandbox_api_client
    except Exception as exc:
        raise RuntimeError('failed to import patcheval.sandbox_api_client for SEC-bench official eval') from exc
    if not sandbox_api_client.enabled():
        raise RuntimeError(f'sandbox_api_client is not enabled for PATCHEVAL_RUNTIME={runtime}')
    return sandbox_api_client


def render_official_eval_script(secbench_root: Path, task_type: str, work_dir: str) -> str:
    template_path = secbench_root / 'secb' / 'evaluator' / 'templates' / f'eval_{task_type}_script.j2'
    template = template_path.read_text(encoding='utf-8')
    return template.replace('{{ work_dir }}', work_dir).replace('{{work_dir}}', work_dir)


def secbench_image_name(image_template: str, image_prefix: str, instance_id: str, task_type: str) -> str:
    template = str(image_template or '').strip()
    if template:
        return template.format(instance_id=instance_id, task_id=instance_id, task_type=task_type)
    return f'{image_prefix.rstrip(".")}.{instance_id}:{task_type}'


def run_sandbox_evaluation_single(
    *,
    evaluator: Any,
    sandbox_client: Any,
    secbench_root: Path,
    instance_id: str,
    model_input: str,
    dataset_dict: Dict[str, Dict[str, Any]],
    image_template: str,
    image_prefix: str,
    task_type: str,
    eval_timeout_seconds: int,
) -> Any:
    work_dir = str(dataset_dict[instance_id]['work_dir'])
    expected_exit_code = dataset_dict[instance_id].get('exit_code')
    image = secbench_image_name(image_template, image_prefix, instance_id, task_type)
    container_id = ''
    try:
        if task_type != 'patch':
            raise RuntimeError('sandbox official eval wrapper currently supports SEC-bench patch tasks only')
        model_input = (model_input or '').replace('\r\n', '\n')
        container_id = sandbox_client.create_sandbox(image, instance_id, f'secbench-official-eval-{task_type}')
        sandbox_client.write_file(container_id, '/tmp/model_patch.diff', model_input + '\n')
        script = render_official_eval_script(secbench_root, task_type, work_dir)
        command = f'cd {shlex.quote(work_dir)} && bash -lc {shlex.quote(script)}'
        rc, stdout, stderr = sandbox_client.exec_shell(container_id, command, timeout=eval_timeout_seconds)
        logs = stdout + stderr
        sanitizer_report = evaluator.extract_sanitizer_report(logs)
        is_timeout = (
            rc in evaluator.TIMEOUT_EXIT_CODES
            or 'Run PoC exit code: 124' in logs
            or 'Run PoC exit code: 137' in logs
        )
        return evaluator.EvaluationResult(
            instance_id=instance_id,
            git_patch=model_input,
            poc=None,
            exit_code=rc,
            logs=logs,
            final_step_executed='Step 3: Run PoC' in logs,
            is_timeout=is_timeout,
            sanitizer_report=sanitizer_report,
            expected_exit_code=expected_exit_code,
            model_name='unknown_model',
        )
    except TimeoutError as exc:
        return evaluator.EvaluationResult(
            instance_id=instance_id,
            git_patch=model_input if task_type == 'patch' else None,
            poc=None,
            exit_code=124,
            logs=f'Sandbox official eval timed out after {eval_timeout_seconds}s: {exc}',
            final_step_executed=False,
            is_timeout=True,
            sanitizer_report=None,
            expected_exit_code=expected_exit_code,
            model_name='unknown_model',
        )
    except Exception as exc:
        return evaluator.EvaluationResult(
            instance_id=instance_id,
            git_patch=model_input if task_type == 'patch' else None,
            poc=None,
            exit_code=-1,
            logs=f'Sandbox official eval failed: {exc}',
            final_step_executed=False,
            is_timeout=False,
            sanitizer_report=None,
            expected_exit_code=expected_exit_code,
            model_name='unknown_model',
        )
    finally:
        if container_id:
            try:
                sandbox_client.stop(container_id)
            except Exception:
                pass


def run_sandbox_evaluation(
    *,
    evaluator: Any,
    sandbox_client: Any,
    secbench_root: Path,
    input_dir: Path,
    task_ids: List[str],
    dataset_dict: Dict[str, Dict[str, Any]],
    image_template: str,
    image_prefix: str,
    num_workers: int,
    task_type: str,
    eval_timeout_seconds: int,
) -> List[Any]:
    if task_type != 'patch':
        raise RuntimeError('sandbox official eval wrapper currently supports SEC-bench patch tasks only')
    processed_inputs = evaluator.preprocess_smolagent_patch(input_dir)
    results: List[Any] = []
    tasks = []
    for instance_id in task_ids:
        instance_exists = instance_id in dataset_dict
        model_input = processed_inputs.get(instance_id, '')
        if not model_input:
            results.append(evaluator.EvaluationResult(
                instance_id=instance_id,
                git_patch=None,
                poc=None,
                exit_code=-1,
                logs='',
                final_step_executed=False,
                is_timeout=False,
                sanitizer_report=None,
                expected_exit_code=dataset_dict.get(instance_id, {}).get('exit_code') if instance_exists else None,
                model_name='unknown_model',
            ))
        elif not instance_exists:
            results.append(evaluator.EvaluationResult(
                instance_id=instance_id,
                git_patch=model_input,
                poc=None,
                exit_code=-1,
                logs='Instance not found in dataset',
                final_step_executed=False,
                is_timeout=False,
                sanitizer_report=None,
                expected_exit_code=None,
                model_name='unknown_model',
            ))
        else:
            tasks.append((instance_id, model_input))
    if num_workers <= 1 or not tasks:
        for instance_id, model_input in tasks:
            results.append(run_sandbox_evaluation_single(
                evaluator=evaluator,
                sandbox_client=sandbox_client,
                secbench_root=secbench_root,
                instance_id=instance_id,
                model_input=model_input,
                dataset_dict=dataset_dict,
                image_template=image_template,
                image_prefix=image_prefix,
                task_type=task_type,
                eval_timeout_seconds=eval_timeout_seconds,
            ))
        return results

    with futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_id = {
            executor.submit(
                run_sandbox_evaluation_single,
                evaluator=evaluator,
                sandbox_client=sandbox_client,
                secbench_root=secbench_root,
                instance_id=instance_id,
                model_input=model_input,
                dataset_dict=dataset_dict,
                image_template=image_template,
                image_prefix=image_prefix,
                task_type=task_type,
                eval_timeout_seconds=eval_timeout_seconds,
            ): instance_id
            for instance_id, model_input in tasks
        }
        for future in futures.as_completed(future_to_id):
            try:
                results.append(future.result())
            except Exception as exc:
                instance_id = future_to_id[future]
                results.append(evaluator.EvaluationResult(
                    instance_id=instance_id,
                    git_patch=None,
                    poc=None,
                    exit_code=-1,
                    logs=f'Sandbox official eval worker failed: {exc}',
                    final_step_executed=False,
                    is_timeout=False,
                    sanitizer_report=None,
                    expected_exit_code=dataset_dict.get(instance_id, {}).get('exit_code'),
                    model_name='unknown_model',
                ))
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run SEC-bench official patch evaluator on patches generated by the D workflow.'
    )
    parser.add_argument('--task-list', type=Path, required=True)
    parser.add_argument('--dataset-jsonl', type=Path, required=True)
    parser.add_argument('--patches-dir', type=Path, required=True)
    parser.add_argument('--eval-input-dir', type=Path, required=True)
    parser.add_argument('--official-output-dir', type=Path, required=True)
    parser.add_argument('--secbench-root', type=Path, required=True)
    parser.add_argument('--image-prefix', default='hwiwonlee/secb.eval.x86_64')
    parser.add_argument('--image-template', default=DEFAULT_SECBENCH_IMAGE_TEMPLATE)
    parser.add_argument('--num-workers', type=int, default=1)
    parser.add_argument('--mode', choices=['strict', 'medium', 'generous', 'all'], default='all')
    parser.add_argument('--runtime', default=os.environ.get('PATCHEVAL_RUNTIME', 'sandbox_api'))
    parser.add_argument('--eval-timeout-seconds', type=int, default=int(os.environ.get('SECBENCH_OFFICIAL_EVAL_TIMEOUT_SECONDS', '600')))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.secbench_root.exists():
        raise SystemExit(f'SEC-bench source root missing: {args.secbench_root}')
    if not args.dataset_jsonl.exists():
        raise SystemExit(f'SEC-bench dataset JSONL missing: {args.dataset_jsonl}')
    if not args.task_list.exists():
        raise SystemExit(f'task list missing: {args.task_list}')

    task_ids = read_task_ids(args.task_list)
    dataset_dict = load_dataset_jsonl(args.dataset_jsonl)
    missing_records = [task_id for task_id in task_ids if task_id not in dataset_dict]
    if missing_records:
        raise SystemExit(f'task IDs missing from dataset JSONL: {missing_records[:20]}')
    runtime = str(args.runtime or '').strip().lower()
    if runtime not in SANDBOX_RUNTIMES:
        raise SystemExit(
            f'SEC-bench official eval requires sandbox runtime; got {args.runtime!r}. '
            'Set PATCHEVAL_RUNTIME=sandbox_api.'
        )

    output_jsonl = write_smolagent_patch_input(task_ids, args.patches_dir, args.eval_input_dir)
    print(json.dumps({
        'event': 'secbench_official_eval_input_written',
        'path': str(output_jsonl),
        'count': len(task_ids),
    }, ensure_ascii=False), flush=True)

    sys.path.insert(0, str(args.secbench_root))
    try:
        evaluator = importlib.import_module('secb.evaluator.eval_instances')
    except Exception as exc:
        raise SystemExit(f'failed to import official SEC-bench evaluator from {args.secbench_root}: {exc}') from exc

    evaluator.SECB_IMAGE_PREFIX = args.image_prefix
    sandbox_client = load_sandbox_client(runtime)
    raw_results = run_sandbox_evaluation(
        evaluator=evaluator,
        sandbox_client=sandbox_client,
        secbench_root=args.secbench_root,
        input_dir=args.eval_input_dir,
        task_ids=task_ids,
        dataset_dict=dataset_dict,
        image_template=args.image_template,
        image_prefix=args.image_prefix,
        num_workers=args.num_workers,
        task_type='patch',
        eval_timeout_seconds=args.eval_timeout_seconds,
    )

    modes = ['strict', 'medium', 'generous'] if args.mode == 'all' else [args.mode]
    summary: Dict[str, Any] = {
        'schema_version': 'secbench.official_eval.summary.v1',
        'task_count': len(task_ids),
        'patch_input': str(output_jsonl),
        'official_output_dir': str(args.official_output_dir),
        'image_prefix': args.image_prefix,
        'image_template': args.image_template,
        'num_workers': args.num_workers,
        'runtime': runtime,
        'eval_timeout_seconds': args.eval_timeout_seconds,
        'modes': {},
    }
    for mode in modes:
        interpreted = evaluator.interpret_patch_results(raw_results, mode)
        evaluator.save_results(interpreted, args.eval_input_dir, mode, 'smolagent', args.official_output_dir)
        summary['modes'][mode] = {
            'count': len(interpreted),
            'success': sum(1 for item in interpreted if item.success),
            'failed': sum(1 for item in interpreted if not item.success),
            'report': str(args.official_output_dir / f'report_{mode}.jsonl'),
        }

    args.official_output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.official_output_dir / 'official_eval_summary.json'
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({
        'event': 'secbench_official_eval_complete',
        'summary': str(summary_path),
        'modes': summary['modes'],
    }, ensure_ascii=False), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
