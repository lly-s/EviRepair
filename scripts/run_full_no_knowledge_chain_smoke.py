#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import concurrent.futures as futures
import fcntl
import hashlib
import io
import json
import logging
import math
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import tarfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

from patch_path_normalize import normalize_candidate_patch_paths
from v6_runtime_guards import (
    StageMissingArtifact,
    StageSoftTimeout,
    artifact_watchdog_action,
    build_opencode_run_command,
    extract_root_session_id_from_log,
    extract_root_session_id_from_session_list,
    forced_closeout_reserve,
    host_write_optional,
    host_write_optional_files,
    install_command_budget_plugin,
)

ROOT = Path(__file__).resolve().parents[1]
PATCH_EVAL = Path(os.environ.get('PATCH_EVAL', '/path/to/local/resource)).resolve()
OPENCODE_DIR = Path(os.environ.get('OPENCODE', str(PATCH_EVAL / 'patcheval' / 'exp_agent' / 'opencode'))).resolve()
POSTPROCESS_DIR = Path(os.environ.get('POSTPROCESS_DIR', str(PATCH_EVAL / 'mas_patch_postprocess_20260624'))).resolve()

if str(OPENCODE_DIR) not in sys.path:
    sys.path.insert(0, str(OPENCODE_DIR))
if str(POSTPROCESS_DIR / 'scripts') not in sys.path:
    sys.path.insert(0, str(POSTPROCESS_DIR / 'scripts'))

from patcheval.dataset import load_dataset  # noqa: E402
from patcheval.docker_image_cache import remove_local_image  # noqa: E402
from patcheval.docker_utils import pull_image_with_retry, run_work_container_no_mount, stop_container  # noqa: E402
from patcheval.opencode_runner import DEFAULT_API_KEY, DEFAULT_BASE_URL, DEFAULT_MODEL, DEFAULT_OPENCODE_VERSION, OpenCodeRunner  # noqa: E402
_SANDBOX_IMPORT_ERROR: Exception | None = None
try:
    from patcheval import sandbox_api_client  # noqa: E402
except Exception as exc:  # pragma: no cover - optional runtime adapter
    _SANDBOX_IMPORT_ERROR = exc
    sandbox_api_client = None  # type: ignore[assignment]

if os.getenv('PATCHEVAL_RUNTIME', '').strip().lower() == 'sandbox_api':
    if sandbox_api_client is None:
        raise RuntimeError(
            'PATCHEVAL_RUNTIME=sandbox_api was requested, but patcheval.sandbox_api_client '
            'could not be imported. Refusing to fall back to local Docker.'
        ) from _SANDBOX_IMPORT_ERROR
    if not sandbox_api_client.enabled():
        raise RuntimeError(
            'PATCHEVAL_RUNTIME=sandbox_api was requested, but sandbox_api_client.enabled() '
            'returned false. Refusing to fall back to local Docker.'
        )
    _orig_wait_for_running = sandbox_api_client.wait_for_running

    def _wait_for_running_respect_unlimited(sid: str):
        raw = str(os.getenv('PATCHEVAL_SANDBOX_START_TIMEOUT', '900')).strip()
        timeout = int(raw) if raw else 900
        if timeout > 0:
            return _orig_wait_for_running(sid)
        last = {}
        last_log = 0.0
        while True:
            last = sandbox_api_client.get_sandbox(sid)
            state = sandbox_api_client._state_of(last).lower()
            if state in {'running', 'ready', 'started'} or str(last.get('runState', '')).lower() == 'running':
                return last
            if state in {'failed', 'error', 'terminated', 'stopped'}:
                raise RuntimeError(f'Sandbox {sid} entered state {state}: {last}')
            now = time.time()
            if now - last_log >= 60:
                LOGGER.info('Waiting indefinitely for sandbox %s; last state=%s', sid, state)
                last_log = now
            time.sleep(5)

    sandbox_api_client.wait_for_running = _wait_for_running_respect_unlimited  # type: ignore[method-assign]

import run_mas_llm_smoke as postprocess_runner  # noqa: E402

LOGGER = logging.getLogger('full-no-knowledge-chain')
TIMEOUT_PROFILE_KEYS = (
    'total_timeout_seconds',
    'analysis_timeout_seconds',
    'repair_timeout_seconds',
    'stage_timeout_seconds',
    'reproducer_timeout_seconds',
)
PATCH_EVAL_TIMEOUT_DEFAULTS = {
    # D14 PatchEval launcher semantics: no whole-run wall-clock cap; cap
    # analysis/repair/generic stages independently.
    'total_timeout_seconds': 0,
    'analysis_timeout_seconds': 10800,
    'repair_timeout_seconds': 7200,
    'stage_timeout_seconds': 7200,
    'reproducer_timeout_seconds': 300,
}
SEC_BENCH_TIMEOUT_DEFAULTS = dict(PATCH_EVAL_TIMEOUT_DEFAULTS)
SECBENCH_SANDBOX_IMAGE_REPOSITORY_DEFAULT = os.getenv(
    'SECBENCH_SANDBOX_IMAGE_REPOSITORY',
    'registry-v2.h.example.invalid/ailab-ai4good1/secbench',
)
SECBENCH_SANDBOX_IMAGE_TEMPLATE_DEFAULT = os.getenv(
    'SECBENCH_SANDBOX_IMAGE_TEMPLATE',
    f'{SECBENCH_SANDBOX_IMAGE_REPOSITORY_DEFAULT}:{{instance_id}}-patch',
)
SECBENCH_IMAGE_TEMPLATE_DEFAULT = os.getenv('SECBENCH_IMAGE_TEMPLATE', SECBENCH_SANDBOX_IMAGE_TEMPLATE_DEFAULT)
SECBENCH_IMAGE_PREFIX_DEFAULT = os.getenv('SECBENCH_IMAGE_PREFIX', 'hwiwonlee/secb.eval.x86_64')
_OPENCODE_SETUP_SEMAPHORE_LOCK = threading.Lock()
_OPENCODE_SETUP_SEMAPHORES: Dict[int, threading.BoundedSemaphore] = {}
_PRE_MAS_SEMAPHORE_LOCK = threading.Lock()
_PRE_MAS_SEMAPHORES: Dict[int, threading.BoundedSemaphore] = {}
_OPENCODE_RUN_SEMAPHORE_LOCK = threading.Lock()
_OPENCODE_RUN_SEMAPHORES: Dict[int, threading.BoundedSemaphore] = {}


def get_opencode_setup_semaphore() -> tuple[threading.BoundedSemaphore | None, int]:
    raw = os.getenv('PATCHEVAL_OPENCODE_SETUP_MAX_CONCURRENCY', '').strip()
    if not raw:
        return None, 0
    try:
        limit = int(raw)
    except ValueError:
        LOGGER.warning('invalid PATCHEVAL_OPENCODE_SETUP_MAX_CONCURRENCY=%r; ignoring', raw)
        return None, 0
    if limit <= 0:
        return None, 0
    with _OPENCODE_SETUP_SEMAPHORE_LOCK:
        semaphore = _OPENCODE_SETUP_SEMAPHORES.get(limit)
        if semaphore is None:
            semaphore = threading.BoundedSemaphore(limit)
            _OPENCODE_SETUP_SEMAPHORES[limit] = semaphore
    return semaphore, limit


def get_pre_mas_semaphore() -> tuple[threading.BoundedSemaphore | None, int]:
    raw = os.getenv('PATCHEVAL_PRE_MAS_MAX_CONCURRENCY', '').strip()
    if not raw:
        return None, 0
    try:
        limit = int(raw)
    except ValueError:
        LOGGER.warning('invalid PATCHEVAL_PRE_MAS_MAX_CONCURRENCY=%r; ignoring', raw)
        return None, 0
    if limit <= 0:
        return None, 0
    with _PRE_MAS_SEMAPHORE_LOCK:
        semaphore = _PRE_MAS_SEMAPHORES.get(limit)
        if semaphore is None:
            semaphore = threading.BoundedSemaphore(limit)
            _PRE_MAS_SEMAPHORES[limit] = semaphore
    return semaphore, limit



def get_opencode_run_semaphore() -> tuple[threading.BoundedSemaphore | None, int]:
    raw = os.getenv('PATCHEVAL_OPENCODE_RUN_MAX_CONCURRENCY', '').strip()
    if not raw:
        return None, 0
    try:
        limit = int(raw)
    except ValueError:
        LOGGER.warning('invalid PATCHEVAL_OPENCODE_RUN_MAX_CONCURRENCY=%r; ignoring', raw)
        return None, 0
    if limit <= 0:
        return None, 0
    with _OPENCODE_RUN_SEMAPHORE_LOCK:
        semaphore = _OPENCODE_RUN_SEMAPHORES.get(limit)
        if semaphore is None:
            semaphore = threading.BoundedSemaphore(limit)
            _OPENCODE_RUN_SEMAPHORES[limit] = semaphore
    return semaphore, limit


def render_template(text: str, values: Dict[str, str]) -> str:
    rendered = text
    for key, value in values.items():
        rendered = rendered.replace('{{' + key + '}}', value)
    return rendered


def read_text(path: Path) -> str:
    return path.read_text(encoding='utf-8')


def tail_chars(text: str, limit: int = 20000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:] + '\n[truncated to last %d chars]\n' % limit


def is_sandbox_container(container_id: str) -> bool:
    return str(container_id).startswith('sandbox://') and sandbox_api_client is not None


def shell_join(args: List[str]) -> str:
    return ' '.join(shlex.quote(str(arg)) for arg in args)


def docker_exec(
    container_id: str,
    args: List[str],
    *,
    input_text: Optional[str] = None,
    timeout: int = 120,
    use_sandbox_min_timeout: bool = True,
) -> subprocess.CompletedProcess[str]:
    if is_sandbox_container(container_id):
        requested_timeout = timeout
        min_timeout = int(os.getenv("PATCHEVAL_SANDBOX_MIN_EXEC_TIMEOUT", "180"))
        min_applies_to_small = os.getenv('PATCHEVAL_SANDBOX_MIN_EXEC_APPLIES_TO_SMALL', '0').strip().lower() in {'1', 'true', 'yes', 'on'}
        if use_sandbox_min_timeout and (requested_timeout >= min_timeout or min_applies_to_small):
            timeout = max(timeout, min_timeout)
        command = shell_join(args)
        if input_text is not None:
            encoded = base64.b64encode(input_text.encode('utf-8')).decode('ascii')
            command = f"base64 -d <<'PATCHEVAL_STDIN' | {command}\n{encoded}\nPATCHEVAL_STDIN"
        retries = int(os.getenv('PATCHEVAL_SANDBOX_SMALL_EXEC_RETRIES', '1')) if requested_timeout <= 120 else 0
        delay = float(os.getenv('PATCHEVAL_SANDBOX_SMALL_EXEC_RETRY_DELAY_SECONDS', '2'))
        for attempt in range(retries + 1):
            try:
                rc, stdout, stderr = sandbox_api_client.exec_shell(container_id, command, timeout=timeout)
                break
            except TimeoutError:
                if attempt >= retries:
                    raise
                LOGGER.warning(
                    'sandbox small exec timed out; retrying',
                    extra={'requested_timeout': requested_timeout, 'effective_timeout': timeout, 'attempt': attempt + 1},
                )
                time.sleep(delay)
        return subprocess.CompletedProcess(args=args, returncode=rc, stdout=stdout, stderr=stderr)
    return subprocess.run(['docker', 'exec', '-i', container_id, *args], input=input_text, text=True, capture_output=True, timeout=timeout)


def docker_write_text(container_id: str, content: str, dest_path: str) -> None:
    if is_sandbox_container(container_id):
        sandbox_api_client.write_file(container_id, dest_path, content)
        return
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False) as handle:
        handle.write(content)
        tmp_name = handle.name
    try:
        docker_exec(container_id, ['bash', '-lc', f'mkdir -p {shlex.quote(str(Path(dest_path).parent))}'], timeout=30)
        subprocess.run(['docker', 'cp', tmp_name, f'{container_id}:{dest_path}'], check=True, capture_output=True, text=True, timeout=60)
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def docker_write_text_files(container_id: str, files: Dict[str, str], *, mode: int = 0o644) -> Dict[str, Any]:
    written = sorted(files)
    if not files:
        return {'written_files': [], 'transfer': 'none'}
    if not is_sandbox_container(container_id):
        for dest_path, content in files.items():
            docker_write_text(container_id, content, dest_path)
        return {'written_files': written, 'transfer': 'per_file_docker_cp'}

    members: List[Tuple[str, bytes]] = []
    parent_dirs = set()
    for dest_path, content in files.items():
        path = PurePosixPath(dest_path)
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError(f'container destination must be an absolute safe path: {dest_path}')
        parent_dirs.add(str(path.parent))
        members.append((str(path).lstrip('/'), content.encode('utf-8')))

    with tempfile.NamedTemporaryFile('wb', delete=False) as handle:
        archive_path = Path(handle.name)
    try:
        with tarfile.open(archive_path, 'w:gz') as archive:
            for arcname, content in members:
                info = tarfile.TarInfo(arcname)
                info.size = len(content)
                info.mode = mode
                info.uid = info.gid = 0
                info.uname = info.gname = 'root'
                archive.addfile(info, io.BytesIO(content))
        encoded = base64.b64encode(archive_path.read_bytes()).decode('ascii')
    finally:
        try:
            archive_path.unlink()
        except OSError:
            pass

    mkdirs = ' '.join(shlex.quote(path) for path in sorted(parent_dirs))
    cmd = f"""set -euo pipefail
mkdir -p {mkdirs}
base64 -d <<'PATCHEVAL_TAR' | tar -C / -xzf -
{encoded}
PATCHEVAL_TAR
"""
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=120)
    if result.returncode != 0:
        raise RuntimeError('failed to bulk-write container text files: ' + tail_chars(result.stdout + result.stderr, 3000))
    return {'written_files': written, 'transfer': 'single_base64_tar_exec'}


def common_posix_parent(paths: List[str]) -> str:
    if not paths:
        return 'text_files'
    parts = [PurePosixPath(path).parts for path in paths]
    common: List[str] = []
    for column in zip(*parts):
        if len(set(column)) != 1:
            break
        common.append(column[0])
    if len(common) <= 1:
        return PurePosixPath(paths[0]).name
    return str(PurePosixPath(*common))


def env_flag(name: str, default: str = '0') -> bool:
    return os.getenv(name, default).lower() not in {'', '0', 'false', 'no', 'off'}


_BRAINBOX_BRIDGE_WORKERS: Dict[str, threading.Thread] = {}


def _bridge_proxy_script() -> str:
    return r'''#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(os.environ.get("BRAINBOX_PROXY_PORT", "18104"))
ROOT = Path(os.environ.get("PATCHEVAL_BRIDGE_ROOT", "/tmp/patcheval_model_bridge"))
REQUEST_DIR = ROOT / "requests"
RESPONSE_DIR = ROOT / "responses"
REQUEST_DIR.mkdir(parents=True, exist_ok=True)
RESPONSE_DIR.mkdir(parents=True, exist_ok=True)
WAIT_SECONDS = float(os.environ.get("PATCHEVAL_BRIDGE_WAIT_SECONDS", "1200"))


class Handler(BaseHTTPRequestHandler):
    server_version = "PatchEvalModelBridge/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _send_bytes(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        headers = headers or {}
        self.send_response(status)
        sent_content_type = False
        for key, value in headers.items():
            lower = key.lower()
            if lower in {"content-length", "transfer-encoding", "connection", "content-encoding"}:
                continue
            if lower == "content-type":
                sent_content_type = True
            self.send_header(key, value)
        if not sent_content_type:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_bytes(200, json.dumps({"ok": True, "mode": "host_bridge"}).encode("utf-8"))
            return
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def _handle(self) -> None:
        request_id = f"{int(time.time() * 1000)}-{os.getpid()}-{threading.get_ident()}-{uuid.uuid4().hex}"
        body_len = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(body_len) if body_len else b""
        request_payload = {
            "id": request_id,
            "method": self.command,
            "path": self.path,
            "headers": {key: value for key, value in self.headers.items()},
            "body_b64": base64.b64encode(body).decode("ascii"),
            "created_at": time.time(),
        }
        tmp_path = REQUEST_DIR / f"{request_id}.json.tmp"
        req_path = REQUEST_DIR / f"{request_id}.json"
        tmp_path.write_text(json.dumps(request_payload, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(req_path)

        resp_path = RESPONSE_DIR / f"{request_id}.json"
        deadline = time.time() + WAIT_SECONDS
        while time.time() < deadline:
            if resp_path.exists():
                try:
                    response_payload = json.loads(resp_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    time.sleep(0.1)
                    continue
                try:
                    body_bytes = base64.b64decode(response_payload.get("body_b64") or "")
                    headers = response_payload.get("headers") or {}
                    self._send_bytes(int(response_payload.get("status") or 502), body_bytes, headers)
                    return
                finally:
                    for path in (req_path, resp_path):
                        try:
                            path.unlink()
                        except OSError:
                            pass
            time.sleep(0.2)
        self._send_bytes(504, json.dumps({"error": "host bridge response timeout"}).encode("utf-8"))


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"bridge_ready http://127.0.0.1:{PORT}/v1 root={ROOT}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _bridge_request_url(host_base_url: str, path: str) -> str:
    base = host_base_url.rstrip('/')
    if path.startswith('/v1/'):
        suffix = path[3:]
    else:
        suffix = path if path.startswith('/') else '/' + path
    return base + suffix


def _call_host_model_proxy(host_base_url: str, request_payload: Dict[str, Any]) -> Dict[str, Any]:
    body = base64.b64decode(request_payload.get('body_b64') or '')
    headers_in = request_payload.get('headers') or {}
    headers = {
        'Content-Type': headers_in.get('Content-Type') or headers_in.get('content-type') or 'application/json',
        'Accept': headers_in.get('Accept') or headers_in.get('accept') or 'application/json',
    }
    if 'authorization' in {str(key).lower() for key in headers_in}:
        headers['Authorization'] = headers_in.get('Authorization') or headers_in.get('authorization') or 'Bearer bridge'
    method = str(request_payload.get('method') or 'POST').upper()
    data = body if method != 'GET' else None
    req = urllib.request.Request(
        _bridge_request_url(host_base_url, str(request_payload.get('path') or '/')),
        data=data,
        headers=headers,
        method=method,
    )
    timeout = float(os.getenv('PATCHEVAL_BRIDGE_UPSTREAM_TIMEOUT_SECONDS', '900'))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            response_body = resp.read()
            response_headers = {
                key: value for key, value in resp.headers.items()
                if key.lower() not in {'content-length', 'transfer-encoding', 'connection'}
            }
            return {
                'status': int(resp.status),
                'headers': response_headers,
                'body_b64': base64.b64encode(response_body).decode('ascii'),
            }
    except urllib.error.HTTPError as exc:
        response_body = exc.read()
        response_headers = {
            key: value for key, value in exc.headers.items()
            if key.lower() not in {'content-length', 'transfer-encoding', 'connection'}
        }
        return {
            'status': int(exc.code),
            'headers': response_headers,
            'body_b64': base64.b64encode(response_body).decode('ascii'),
        }
    except Exception as exc:
        body_json = json.dumps({'error': f'host bridge upstream error: {exc}'}, ensure_ascii=False).encode('utf-8')
        return {
            'status': 502,
            'headers': {'Content-Type': 'application/json'},
            'body_b64': base64.b64encode(body_json).decode('ascii'),
        }


def _start_host_bridge_worker(container_id: str, bridge_root: str, host_base_url: str) -> None:
    if container_id in _BRAINBOX_BRIDGE_WORKERS:
        return

    def worker() -> None:
        request_dir = PurePosixPath(bridge_root) / 'requests'
        response_dir = PurePosixPath(bridge_root) / 'responses'
        idle_sleep = float(os.getenv('PATCHEVAL_BRIDGE_POLL_SECONDS', '0.5'))
        consecutive_poll_errors = 0
        while True:
            try:
                list_cmd = (
                    f"find {shlex.quote(str(request_dir))} -maxdepth 1 -type f -name '*.json' "
                    f"-printf '%f\\n' 2>/dev/null | sort | head -20"
                )
                listed = docker_exec(container_id, ['bash', '-lc', list_cmd], timeout=10)
                consecutive_poll_errors = 0
                if listed.returncode != 0:
                    time.sleep(idle_sleep)
                    continue
                names = [line.strip() for line in listed.stdout.splitlines() if line.strip().endswith('.json')]
                if not names:
                    time.sleep(idle_sleep)
                    continue
                for name in names:
                    req_path = str(request_dir / name)
                    resp_path = str(response_dir / name)
                    try:
                        if docker_exec(container_id, ['bash', '-lc', f'test -f {shlex.quote(resp_path)}'], timeout=5).returncode == 0:
                            continue
                        raw = docker_read_text(container_id, req_path, missing_ok=True, timeout=15)
                        if not raw.strip():
                            continue
                        request_payload = json.loads(raw)
                        response_payload = _call_host_model_proxy(host_base_url, request_payload)
                    except Exception as exc:
                        body_json = json.dumps({'error': f'host bridge worker error: {exc}'}, ensure_ascii=False).encode('utf-8')
                        response_payload = {
                            'status': 502,
                            'headers': {'Content-Type': 'application/json'},
                            'body_b64': base64.b64encode(body_json).decode('ascii'),
                        }
                    docker_write_text(container_id, json.dumps(response_payload, ensure_ascii=False), resp_path)
            except Exception as exc:
                consecutive_poll_errors += 1
                if consecutive_poll_errors == 1 or consecutive_poll_errors % 10 == 0:
                    LOGGER.warning(
                        'host bridge worker poll error for %s count=%s: %s',
                        container_id,
                        consecutive_poll_errors,
                        exc,
                    )
                time.sleep(min(max(idle_sleep, 1.0) * min(consecutive_poll_errors, 5), 10.0))

    thread = threading.Thread(target=worker, name=f'brainbox-bridge-{uuid.uuid4().hex[:8]}', daemon=True)
    _BRAINBOX_BRIDGE_WORKERS[container_id] = thread
    thread.start()


def start_brainbox_host_bridge_proxy(container_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
    port = os.getenv('BRAINBOX_PROXY_PORT', '18104')
    bridge_root = os.getenv('PATCHEVAL_BRIDGE_ROOT', '/tmp/patcheval_model_bridge')
    bridge_script_path = '/tmp/patcheval_model_bridge_proxy.py'
    log_path = '/tmp/patcheval_model_bridge_proxy.log'
    pid_path = '/tmp/patcheval_model_bridge_proxy.pid'
    docker_write_text_files(container_id, {bridge_script_path: _bridge_proxy_script()}, mode=0o700)
    start_cmd = f"""
set -e
proxy_py=$(command -v python3 || command -v python || true)
if [ -z "$proxy_py" ]; then
  echo no_python_for_bridge_proxy >&2
  exit 127
fi
export BRAINBOX_PROXY_PORT={shlex.quote(port)}
export PATCHEVAL_BRIDGE_ROOT={shlex.quote(bridge_root)}
export PATCHEVAL_BRIDGE_WAIT_SECONDS={shlex.quote(os.getenv('PATCHEVAL_BRIDGE_WAIT_SECONDS', '1200'))}
if command -v setsid >/dev/null 2>&1; then
  setsid "$proxy_py" {shlex.quote(bridge_script_path)} < /dev/null > {shlex.quote(log_path)} 2>&1 &
else
  nohup "$proxy_py" {shlex.quote(bridge_script_path)} < /dev/null > {shlex.quote(log_path)} 2>&1 &
fi
echo $! > {shlex.quote(pid_path)}
disown 2>/dev/null || true
cat {shlex.quote(pid_path)}
"""
    start = docker_exec(container_id, ['bash', '-lc', start_cmd], timeout=30)
    if start.returncode != 0:
        raise RuntimeError('failed to start sandbox host bridge proxy: ' + tail_chars(start.stdout + start.stderr, 2000))
    health_cmd = f"""
python3 - <<'PYHEALTH'
import urllib.request
with urllib.request.urlopen('http://127.0.0.1:{port}/healthz', timeout=5) as resp:
    print(resp.status, resp.read().decode('utf-8')[:200])
PYHEALTH
"""
    last = ''
    for _ in range(30):
        probe = docker_exec(container_id, ['bash', '-lc', health_cmd], timeout=10)
        last = tail_chars(probe.stdout + probe.stderr, 1000)
        if probe.returncode == 0 and '200' in probe.stdout:
            host_base_url = os.getenv('PATCHEVAL_HOST_AGENT_BASE_URL') or f'http://127.0.0.1:{port}/v1'
            _start_host_bridge_worker(container_id, bridge_root, host_base_url)
            info = {
                'enabled': True,
                'mode': 'host_bridge',
                'url': f'http://127.0.0.1:{port}/v1',
                'pid': start.stdout.strip().splitlines()[-1] if start.stdout.strip() else '',
                'log_path': log_path,
                'host_base_url': host_base_url,
            }
            result['brainbox_container_proxy'] = info
            return info
        time.sleep(1)
    bridge_log = docker_read_text(container_id, log_path, missing_ok=True, timeout=15)
    raise RuntimeError('sandbox host bridge proxy health check failed: ' + tail_chars(last + '\n' + bridge_log, 3000))


def start_brainbox_container_proxy(container_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Start a model API proxy inside the work sandbox so OpenCode can use 127.0.0.1."""
    if not env_flag('PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY'):
        return {}
    proxy_mode = os.getenv('PATCHEVAL_BRAINBOX_PROXY_MODE', 'host_bridge').strip().lower()
    if proxy_mode in {'host_bridge', 'bridge'} and is_sandbox_container(container_id):
        return start_brainbox_host_bridge_proxy(container_id, result)
    required = {
        'OPEN_SANDBOX_API_KEY': os.getenv('OPEN_SANDBOX_API_KEY') or os.getenv('SANDBOX_API_KEY') or '',
        'BRAINBOX_SUB2API_KEY': os.getenv('BRAINBOX_SUB2API_KEY') or '',
        'BRAINBOX_SANDBOX_ID': os.getenv('BRAINBOX_SANDBOX_ID', 'sbx-ec349971-c4f'),
        'SANDBOX_PROJECT': os.getenv('SANDBOX_PROJECT', 'anonymous-model'),
        'SANDBOX_API_BASE': os.getenv('SANDBOX_API_BASE', 'https://h.example.invalid/brainbox/v1'),
        'BRAINBOX_PROXY_PORT': os.getenv('BRAINBOX_PROXY_PORT', '18104'),
    }
    missing = [key for key in ['OPEN_SANDBOX_API_KEY', 'BRAINBOX_SUB2API_KEY'] if not required.get(key)]
    if missing:
        raise RuntimeError('PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY missing env: ' + ', '.join(missing))
    script_path = '/tmp/patcheval_brainbox_openai_proxy.py'
    env_path = '/tmp/patcheval_brainbox_proxy_env.sh'
    log_path = '/tmp/patcheval_brainbox_openai_proxy.log'
    pid_path = '/tmp/patcheval_brainbox_openai_proxy.pid'
    proxy_script = ROOT / 'scripts' / 'brainbox_openai_proxy.py'
    hosts_ip = os.getenv('BRAINBOX_HOSTS_IP', '').strip()
    hosts_name = os.getenv('BRAINBOX_HOSTS_NAME', 'h.example.invalid').strip()
    if hosts_ip and hosts_name:
        hosts_cmd = f"""
set -e
if ! grep -q {shlex.quote(hosts_name)} /etc/hosts 2>/dev/null; then
  printf '\\n%s %s\\n' {shlex.quote(hosts_ip)} {shlex.quote(hosts_name)} >> /etc/hosts
fi
getent hosts {shlex.quote(hosts_name)} >/dev/null 2>&1 || true
"""
        host_result = docker_exec(container_id, ['bash', '-lc', hosts_cmd], timeout=30)
        if host_result.returncode != 0:
            raise RuntimeError('failed to prepare Brainbox hosts entry: ' + tail_chars(host_result.stdout + host_result.stderr, 1000))
        result['brainbox_hosts_entry'] = {'host': hosts_name, 'ip': hosts_ip}
    env_lines = [f'export {key}={shlex.quote(value)}' for key, value in required.items()]
    docker_write_text_files(
        container_id,
        {
            script_path: proxy_script.read_text(encoding='utf-8'),
            env_path: '\n'.join(env_lines) + '\n',
        },
        mode=0o600,
    )
    start_cmd = f"""
set -e
proxy_py=$(command -v python3 || command -v python || true)
if [ -z "$proxy_py" ]; then
  echo no_python_for_brainbox_proxy >&2
  exit 127
fi
chmod 700 {shlex.quote(script_path)}
chmod 600 {shlex.quote(env_path)}
set -a
. {shlex.quote(env_path)}
set +a
rm -f {shlex.quote(env_path)}
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
nohup "$proxy_py" {shlex.quote(script_path)} > {shlex.quote(log_path)} 2>&1 &
echo $! > {shlex.quote(pid_path)}
cat {shlex.quote(pid_path)}
"""
    start = docker_exec(container_id, ['bash', '-lc', start_cmd], timeout=30)
    if start.returncode != 0:
        raise RuntimeError('failed to start in-container Brainbox proxy: ' + tail_chars(start.stdout + start.stderr, 2000))
    port = required['BRAINBOX_PROXY_PORT']
    health_cmd = f"""
proxy_py=$(command -v python3 || command -v python || true)
if [ -z "$proxy_py" ]; then exit 127; fi
"$proxy_py" - <<'PYHEALTH'
import urllib.request
with urllib.request.urlopen('http://127.0.0.1:{port}/healthz', timeout=5) as resp:
    print(resp.status, resp.read().decode('utf-8')[:200])
PYHEALTH
"""
    last = ''
    for _ in range(60):
        probe = docker_exec(container_id, ['bash', '-lc', health_cmd], timeout=15)
        last = tail_chars(probe.stdout + probe.stderr, 1000)
        if probe.returncode == 0 and '200' in probe.stdout:
            info = {
                'enabled': True,
                'url': f'http://127.0.0.1:{port}/v1',
                'pid': start.stdout.strip().splitlines()[-1] if start.stdout.strip() else '',
                'log_path': log_path,
            }
            result['brainbox_container_proxy'] = info
            return info
        time.sleep(2)
    proxy_log = docker_read_text(container_id, log_path, missing_ok=True, timeout=15)
    raise RuntimeError('in-container Brainbox proxy health check failed: ' + tail_chars(last + '\n' + proxy_log, 3000))


def docker_read_text(container_id: str, path: str, *, missing_ok: bool = False, timeout: int = 60) -> str:
    if is_sandbox_container(container_id):
        command = f'test -f {shlex.quote(path)} && base64 {shlex.quote(path)} | tr -d "\\n"'
        result = docker_exec(container_id, ['bash', '-lc', command], timeout=timeout)
        if result.returncode != 0:
            if missing_ok:
                return ''
            raise RuntimeError(f'missing container file {path}: {(result.stdout + result.stderr).strip()}')
        if not result.stdout:
            return ''
        return base64.b64decode(result.stdout.encode('ascii')).decode('utf-8', errors='replace')
    result = docker_exec(container_id, ['bash', '-lc', f'test -f {shlex.quote(path)} && cat {shlex.quote(path)}'], timeout=timeout)
    if result.returncode != 0:
        if missing_ok:
            return ''
        raise RuntimeError(f'missing container file {path}: {(result.stdout + result.stderr).strip()}')
    return result.stdout


def git_reset_clean_command(work_dir: str, excludes: List[str]) -> str:
    exclude_args = ' '.join(f'-e {shlex.quote(item)}' for item in excludes)
    quoted_work_dir = shlex.quote(work_dir)
    return f'''
set -euo pipefail
cd {quoted_work_dir}
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git init -q
    git config user.email anonymous@example.invalid
    git config user.name PatchEval
    git add -A
    if git diff --cached --quiet; then
        git commit --allow-empty -qm 'PatchEval prepared baseline'
    else
        git commit -qm 'PatchEval prepared baseline'
    fi
fi
git reset --hard HEAD >/dev/null
git clean -fd {exclude_args} >/dev/null
'''


def reset_worktree(container_id: str, work_dir: str, timeout: int = 180) -> Tuple[bool, str]:
    cmd = git_reset_clean_command(work_dir, ['opencode.json'])
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=timeout)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def reset_worktree_preserve(container_id: str, work_dir: str, preserve: List[str], timeout: int = 180) -> Tuple[bool, str]:
    cmd = git_reset_clean_command(work_dir, ['opencode.json', *preserve])
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=timeout)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def ensure_container_dir(container_id: str, path: str) -> None:
    result = docker_exec(container_id, ['bash', '-lc', f'mkdir -p {shlex.quote(path)}'], timeout=30)
    if result.returncode != 0:
        raise RuntimeError((result.stdout + result.stderr).strip())


def ensure_agent_writable_dir(container_id: str, path: str) -> None:
    quoted = shlex.quote(path)
    cmd = f"""
set -euo pipefail
mkdir -p {quoted}
if ! id opencode_user >/dev/null 2>&1; then
    echo 'opencode_user does not exist; run OpenCode setup before agent-writable dirs' >&2
    exit 2
fi
chown -R opencode_user:opencode_user {quoted}
find {quoted} -type d -exec chmod u+rwx {{}} +
"""
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=60)
    if result.returncode != 0:
        raise RuntimeError('failed to prepare agent-writable directory ' + path + ': ' + (result.stdout + result.stderr).strip())


def list_workspace_oracle_files(container_id: str, work_dir: str = '/workspace') -> List[str]:
    cmd = "set -euo pipefail\nwork_dir=" + shlex.quote(work_dir or '/workspace') + r"""

work_dir="${work_dir%/}"
if [ "$work_dir" = "/workspace" ]; then
    if [ -e /workspace/fix.patch ] || [ -L /workspace/fix.patch ]; then
        printf '%s\n' /workspace/fix.patch
    fi
    exit 0
fi

case "$work_dir" in
    /workspace/*) ;;
    *)
        printf '%s\n' "invalid-workdir:$work_dir"
        exit 0
        ;;
esac

top_name="${work_dir#/workspace/}"
top_name="${top_name%%/*}"
if [ -d /workspace ]; then
    find /workspace -mindepth 1 -maxdepth 1 ! -name "$top_name" -printf '%p\n' | sort
fi
"""
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=120)
    if result.returncode != 0:
        raise RuntimeError('failed to list workspace oracle files: ' + (result.stdout + result.stderr).strip())
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def remove_workspace_oracle_files(container_id: str, work_dir: str = '/workspace') -> Dict[str, Any]:
    """Apply the official PatchEval runner's workspace payload hiding.

    This matches bytedance/PatchEval's patch_agent_runner._hide_workspace_payload:
    remove /workspace/fix.patch; when the target repo is /workspace/<repo>, also
    remove all first-level /workspace entries other than that repo directory.
    It does not recursively clean inside the repo and does not rewrite Git
    history. Changes affect only the running inference container's writable layer.
    """
    cmd = "set -euo pipefail\nwork_dir=" + shlex.quote(work_dir or '/workspace') + r"""

emit_removed() {
    printf '%s\t%s\n' "$1" "$2"
}

remove_path() {
    local path="$1"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    if [ -d "$path" ] && [ ! -L "$path" ]; then
        rm -rf -- "$path"
        emit_removed removed_dir "$path"
    else
        rm -f -- "$path"
        emit_removed removed_file "$path"
    fi
}

work_dir="${work_dir%/}"
remove_path /workspace/fix.patch

if [ "$work_dir" = "/workspace" ]; then
    emit_removed mode "workspace-root"
    exit 0
fi

case "$work_dir" in
    /workspace/*) ;;
    *)
        echo "target workdir is outside /workspace: $work_dir" >&2
        exit 2
        ;;
esac

top_name="${work_dir#/workspace/}"
top_name="${top_name%%/*}"
emit_removed mode "workspace-subdir:$top_name"
if [ -d /workspace ]; then
    while IFS= read -r -d '' src; do
        remove_path "$src"
    done < <(find /workspace -mindepth 1 -maxdepth 1 ! -name "$top_name" -print0)
fi
"""
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=300)
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        raise RuntimeError('failed to remove benchmark oracle files: ' + output)
    removed_files: List[str] = []
    removed_dirs: List[str] = []
    modes: List[str] = []
    unparsed: List[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        kind, sep, value = line.partition('\t')
        if not sep:
            unparsed.append(line)
        elif kind == 'removed_file':
            removed_files.append(value)
        elif kind == 'removed_dir':
            removed_dirs.append(value)
        elif kind == 'mode':
            modes.append(value)
        else:
            unparsed.append(line)
    return {
        'removed_files': removed_files,
        'removed_dirs': removed_dirs,
        'modes': modes,
        'unparsed_output': unparsed,
        'policy': 'aligned with official PatchEval patch_agent_runner._hide_workspace_payload: remove /workspace/fix.patch; if work_dir is /workspace/<repo>, remove first-level /workspace entries except that repo',
        'scope': 'current container writable layer only; original image and fresh evaluation containers are not modified',
    }


PATCH_EVAL_RUNTIME_TOOLS = (
    'python',
    'python3',
    'python2',
    'pip',
    'pip3',
    'virtualenv',
    'pytest',
    'tox',
    'poetry',
    'pipenv',
    'conda',
    'mamba',
    'node',
    'npm',
    'npx',
    'yarn',
    'pnpm',
    'corepack',
    'go',
    'gofmt',
    'java',
    'javac',
    'mvn',
    'gradle',
    'gcc',
    'g++',
    'cc',
    'c++',
    'make',
    'cmake',
    'autoconf',
    'automake',
    'libtool',
    'pkg-config',
    'rustc',
    'cargo',
    'ruby',
    'gem',
    'bundle',
    'bundler',
    'php',
    'composer',
    'perl',
    'cpan',
    'lua',
    'luarocks',
    'R',
    'Rscript',
    'git',
    'svn',
    'hg',
    'curl',
    'wget',
    'unzip',
    'zip',
    'tar',
    'gzip',
    'xz',
    'bzip2',
    'patch',
    'diff',
    'sed',
    'awk',
    'grep',
    'find',
)


def ensure_opencode_user_runtime(container_id: str) -> Dict[str, Any]:
    """Expose image-provided runtimes to opencode_user and verify parity.

    The agent still runs as opencode_user. Any common runtime tool that root can
    execute must also be found and executable after opencode_user sources
    ~/.bashrc. Root-only runtime installs are copied to /opt/patcheval-runtimes;
    root configuration, caches, and credential files are intentionally not
    copied.
    """
    tool_words = ' '.join(shlex.quote(tool) for tool in PATCH_EVAL_RUNTIME_TOOLS)
    cmd = "set -euo pipefail\nTOOLS=(" + tool_words + r''')
runtime_root="/opt/patcheval-runtimes"
profile_path="/etc/profile.d/patcheval-opencode-runtime.sh"
mkdir -p "$runtime_root"
chmod 755 /opt "$runtime_root" 2>/dev/null || true

if ! id opencode_user >/dev/null 2>&1; then
    adduser --disabled-password --gecos '' opencode_user >/dev/null
fi
mkdir -p /path/to/local/resource
chown opencode_user:opencode_user /path/to/local/resource 2>/dev/null || true

path_seen=""
declare -a runtime_paths=()
declare -A root_tool_paths=()

add_path() {
    local path="$1"
    [ -n "$path" ] || return 0
    [ -d "$path" ] || return 0
    case ":$path_seen:" in
        *":$path:"*) return 0 ;;
    esac
    path_seen="${path_seen}:$path"
    runtime_paths+=("$path")
}

copy_dir_contents() {
    local src="$1"
    local dst="$2"
    [ -d "$src" ] || return 0
    local tmp="${dst}.tmp.$$"
    if [ ! -e "$dst/.patcheval-runtime-ready" ]; then
        rm -rf "$tmp"
        mkdir -p "$tmp"
        copy_mode="hardlink"
        if ! cp -al "$src"/. "$tmp"/ 2>/tmp/patcheval-runtime-copy.err; then
            copy_mode="copy"
            rm -rf "$tmp"
            mkdir -p "$tmp"
            cp -a "$src"/. "$tmp"/
        fi
        chmod -R a+rX "$tmp" 2>/dev/null || true
        rm -rf "$dst"
        mkdir -p "$(dirname "$dst")"
        mv "$tmp" "$dst"
        touch "$dst/.patcheval-runtime-ready"
        chmod a+r "$dst/.patcheval-runtime-ready" 2>/dev/null || true
        printf 'RUNTIME_COPY\t%s\t%s\t%s\n' "$src" "$dst" "$copy_mode"
    fi
}

copy_file_if_exists() {
    local src="$1"
    local dst="$2"
    [ -f "$src" ] || return 0
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
    chmod a+r "$dst" 2>/dev/null || true
    printf 'RUNTIME_COPY\t%s\t%s\n' "$src" "$dst"
}

rewrite_bin_shebangs() {
    local src="$1"
    local dst="$2"
    [ -d "$dst/bin" ] || return 0
    while IFS= read -r -d '' file; do
        if ! LC_ALL=C grep -Iq . "$file" 2>/dev/null; then
            continue
        fi
        first_line="$(sed -n '1p' "$file" 2>/dev/null || true)"
        case "$first_line" in
            "#!$src/bin/"*)
                sed -i "1 s|^#!$src/bin/|#!$dst/bin/|" "$file" 2>/dev/null || true
                ;;
        esac
    done < <(find "$dst/bin" -maxdepth 1 -type f -print0 2>/dev/null)
}

copy_runtime_tree() {
    local src="$1"
    local dst="$2"
    local rels="$3"
    local rel
    copy_dir_contents "$src" "$dst"
    [ -d "$dst" ] || return 0
    rewrite_bin_shebangs "$src" "$dst"
    IFS=':' read -r -a rel_array <<< "$rels"
    for rel in "${rel_array[@]}"; do
        [ -n "$rel" ] || continue
        shopt -s nullglob
        for candidate in "$dst"/$rel; do
            add_path "$candidate"
        done
        shopt -u nullglob
    done
}

copy_runtime_subdir() {
    local src="$1"
    local dst="$2"
    local path_to_add="$3"
    copy_dir_contents "$src" "$dst"
    if [ -n "$path_to_add" ]; then
        add_path "$path_to_add"
    fi
    return 0
}

# Explicit runtime installs. These are executable runtimes, not root configs.
copy_runtime_tree /root/miniconda3 "$runtime_root/miniconda3" 'bin:condabin'
copy_runtime_tree /root/anaconda3 "$runtime_root/anaconda3" 'bin:condabin'
copy_runtime_tree /root/mambaforge "$runtime_root/mambaforge" 'bin:condabin'
copy_runtime_subdir /root/go/bin "$runtime_root/root-go/bin" "$runtime_root/root-go/bin"
copy_runtime_subdir /root/.cargo/bin "$runtime_root/root-cargo/bin" "$runtime_root/root-cargo/bin"
copy_runtime_subdir /root/.rustup/toolchains "$runtime_root/root-rustup/toolchains" ''
copy_file_if_exists /root/.rustup/settings.toml "$runtime_root/root-rustup/settings.toml"
copy_runtime_subdir /root/.nvm/versions "$runtime_root/root-nvm/versions" ''
copy_runtime_subdir /root/.sdkman/candidates "$runtime_root/root-sdkman/candidates" ''
copy_runtime_subdir /root/.pyenv/versions "$runtime_root/root-pyenv/versions" ''
copy_runtime_subdir /root/.rbenv/versions "$runtime_root/root-rbenv/versions" ''
copy_runtime_subdir /root/.local/bin "$runtime_root/root-local/bin" "$runtime_root/root-local/bin"
copy_runtime_subdir /root/perl5/bin "$runtime_root/root-perl5/bin" "$runtime_root/root-perl5/bin"
copy_runtime_subdir /root/.gem/ruby "$runtime_root/root-gem/ruby" ''

shopt -s nullglob
for candidate in "$runtime_root"/root-rustup/toolchains/*/bin; do add_path "$candidate"; done
for candidate in "$runtime_root"/root-nvm/versions/node/*/bin; do add_path "$candidate"; done
for candidate in "$runtime_root"/root-sdkman/candidates/*/current/bin; do add_path "$candidate"; done
for candidate in "$runtime_root"/root-pyenv/versions/*/bin; do add_path "$candidate"; done
for candidate in "$runtime_root"/root-rbenv/versions/*/bin; do add_path "$candidate"; done
for candidate in "$runtime_root"/root-gem/ruby/*/bin; do add_path "$candidate"; done
shopt -u nullglob

map_root_dir() {
    local dir="$1"
    case "$dir" in
        /root/miniconda3) printf '%s\n' "$runtime_root/miniconda3" ;;
        /root/miniconda3/*) printf '%s\n' "$runtime_root/miniconda3/${dir#/root/miniconda3/}" ;;
        /root/anaconda3) printf '%s\n' "$runtime_root/anaconda3" ;;
        /root/anaconda3/*) printf '%s\n' "$runtime_root/anaconda3/${dir#/root/anaconda3/}" ;;
        /root/mambaforge) printf '%s\n' "$runtime_root/mambaforge" ;;
        /root/mambaforge/*) printf '%s\n' "$runtime_root/mambaforge/${dir#/root/mambaforge/}" ;;
        /root/go/bin) printf '%s\n' "$runtime_root/root-go/bin" ;;
        /root/.cargo/bin) printf '%s\n' "$runtime_root/root-cargo/bin" ;;
        /root/.rustup/toolchains/*/bin) printf '%s\n' "$runtime_root/root-rustup/toolchains/${dir#/root/.rustup/toolchains/}" ;;
        /root/.nvm/versions/*) printf '%s\n' "$runtime_root/root-nvm/versions/${dir#/root/.nvm/versions/}" ;;
        /root/.sdkman/candidates/*) printf '%s\n' "$runtime_root/root-sdkman/candidates/${dir#/root/.sdkman/candidates/}" ;;
        /root/.pyenv/versions/*) printf '%s\n' "$runtime_root/root-pyenv/versions/${dir#/root/.pyenv/versions/}" ;;
        /root/.rbenv/versions/*) printf '%s\n' "$runtime_root/root-rbenv/versions/${dir#/root/.rbenv/versions/}" ;;
        /root/.local/bin) printf '%s\n' "$runtime_root/root-local/bin" ;;
        /root/perl5/bin) printf '%s\n' "$runtime_root/root-perl5/bin" ;;
        /root/.gem/ruby/*) printf '%s\n' "$runtime_root/root-gem/ruby/${dir#/root/.gem/ruby/}" ;;
        *) return 1 ;;
    esac
}

IFS=':' read -r -a root_path_dirs <<< "${PATH:-}"
for dir in "${root_path_dirs[@]}"; do
    [ -n "$dir" ] || continue
    if mapped="$(map_root_dir "$dir" 2>/dev/null)"; then
        add_path "$mapped"
    elif [ -d "$dir" ]; then
        add_path "$dir"
    fi
done

for tool in "${TOOLS[@]}"; do
    tool_path="$(command -v "$tool" 2>/dev/null || true)"
    [ -n "$tool_path" ] || continue
    root_tool_paths["$tool"]="$tool_path"
    printf 'ROOT_TOOL\t%s\t%s\n' "$tool" "$tool_path"
    tool_dir="$(dirname "$tool_path")"
    if mapped="$(map_root_dir "$tool_dir" 2>/dev/null)"; then
        add_path "$mapped"
    else
        add_path "$tool_dir"
    fi
done

path_value=""
for path in "${runtime_paths[@]}"; do
    [ -d "$path" ] || continue
    if [ -z "$path_value" ]; then
        path_value="$path"
    else
        path_value="$path_value:$path"
    fi
    printf 'RUNTIME_PATH\t%s\n' "$path"
done

{
    printf 'export PATCHEVAL_RUNTIME_PATHS=%q\n' "$path_value"
    printf 'export CARGO_HOME=%q\n' "$runtime_root/root-cargo"
    printf 'export RUSTUP_HOME=%q\n' "$runtime_root/root-rustup"
    printf 'export NVM_DIR=%q\n' "$runtime_root/root-nvm"
    printf 'export PYENV_ROOT=%q\n' "$runtime_root/root-pyenv"
    printf 'export RBENV_ROOT=%q\n' "$runtime_root/root-rbenv"
    cat <<'PROFILEEOF'
if [ -n "${PATCHEVAL_RUNTIME_PATHS:-}" ]; then
    export PATH="${PATCHEVAL_RUNTIME_PATHS}:$PATH"
fi
export PYTHONPATH="/tmp/peval-tools:${PYTHONPATH:-}"
PROFILEEOF
} > "$profile_path"
chmod 0644 "$profile_path"

touch /path/to/local/resource
if ! grep -q 'patcheval-opencode-runtime.sh' /path/to/local/resource 2>/dev/null; then
    cat >> /path/to/local/resource <<'BASHRCEOF'

if [ -f /etc/profile.d/patcheval-opencode-runtime.sh ]; then
    . /etc/profile.d/patcheval-opencode-runtime.sh
fi
BASHRCEOF
fi
chown opencode_user:opencode_user /path/to/local/resource 2>/dev/null || true

missing=0
for tool in "${TOOLS[@]}"; do
    [ -n "${root_tool_paths[$tool]:-}" ] || continue
    qtool="$(printf '%q' "$tool")"
    user_path="$(su - opencode_user -c "source ~/.bashrc >/dev/null 2>&1 || true; command -v $qtool" 2>/dev/null || true)"
    if [ -z "$user_path" ]; then
        printf 'MISSING_TOOL\t%s\t%s\n' "$tool" "${root_tool_paths[$tool]}"
        missing=1
        continue
    fi
    printf 'USER_TOOL\t%s\t%s\n' "$tool" "$user_path"
    probe_cmd='source ~/.bashrc >/dev/null 2>&1 || true
run_limited() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 25s "$@"
    else
        "$@"
    fi
}
tool='"$qtool"'
case "$tool" in
    python|python3|python2|pip|pip3|virtualenv|pytest|tox|poetry|pipenv|conda|mamba|node|npm|npx|yarn|pnpm|corepack|mvn|gradle|gcc|g++|cc|c++|make|cmake|autoconf|automake|libtool|pkg-config|rustc|cargo|ruby|gem|bundle|bundler|php|composer|perl|luarocks|R|Rscript|git|svn|hg|curl|wget)
        run_limited "$tool" --version >/dev/null 2>&1
        ;;
    go)
        run_limited "$tool" version >/dev/null 2>&1
        ;;
    java|javac)
        run_limited "$tool" -version >/dev/null 2>&1
        ;;
    lua)
        run_limited "$tool" -v >/dev/null 2>&1
        ;;
    awk)
        run_limited "$tool" "BEGIN { print 1 }" >/dev/null 2>&1
        ;;
    *)
        command -v "$tool" >/dev/null 2>&1
        ;;
esac'
    if ! su - opencode_user -c "$probe_cmd" >/dev/null 2>&1; then
        printf 'PROBE_FAILED\t%s\t%s\t%s\n' "$tool" "${root_tool_paths[$tool]}" "$user_path"
        missing=1
    fi
done

if [ "$missing" -ne 0 ]; then
    exit 42
fi
printf 'RUNTIME_ALIGNMENT_OK\t%s\n' "$path_value"
'''
    timeout = max(300, int(os.getenv('PATCHEVAL_RUNTIME_ALIGN_TIMEOUT', '1800')))
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=timeout)
    output = (result.stdout or '') + (result.stderr or '')
    summary: Dict[str, Any] = {
        'runtime_root': '/opt/patcheval-runtimes',
        'profile_path': '/etc/profile.d/patcheval-opencode-runtime.sh',
        'root_tools': {},
        'user_tools': {},
        'missing_tools': {},
        'probe_failed_tools': {},
        'runtime_paths': [],
        'copied_runtimes': [],
        'ok': result.returncode == 0,
        'returncode': result.returncode,
    }
    for line in result.stdout.splitlines():
        parts = line.rstrip('\n').split('\t')
        if not parts:
            continue
        tag = parts[0]
        if tag == 'ROOT_TOOL' and len(parts) >= 3:
            summary['root_tools'][parts[1]] = parts[2]
        elif tag == 'USER_TOOL' and len(parts) >= 3:
            summary['user_tools'][parts[1]] = parts[2]
        elif tag == 'MISSING_TOOL' and len(parts) >= 3:
            summary['missing_tools'][parts[1]] = parts[2]
        elif tag == 'PROBE_FAILED' and len(parts) >= 4:
            summary['probe_failed_tools'][parts[1]] = {'root_path': parts[2], 'user_path': parts[3]}
        elif tag == 'RUNTIME_PATH' and len(parts) >= 2:
            summary['runtime_paths'].append(parts[1])
        elif tag == 'RUNTIME_COPY' and len(parts) >= 3:
            item = {'source': parts[1], 'dest': parts[2]}
            if len(parts) >= 4:
                item['mode'] = parts[3]
            summary['copied_runtimes'].append(item)
        elif tag == 'RUNTIME_ALIGNMENT_OK' and len(parts) >= 2:
            summary['runtime_path_value'] = parts[1]
    summary['root_tool_count'] = len(summary['root_tools'])
    summary['user_tool_count'] = len(summary['user_tools'])
    summary['missing_tool_count'] = len(summary['missing_tools'])
    summary['probe_failed_tool_count'] = len(summary['probe_failed_tools'])
    summary['raw_output_tail'] = tail_chars(output, 4000)
    if result.returncode != 0:
        raise RuntimeError('opencode_user runtime alignment failed: ' + tail_chars(output, 4000))
    return summary


def write_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.write(json.dumps(obj, ensure_ascii=False) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle, fcntl.LOCK_UN)


def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def copy_text_tree_to_container(container_id: str, source_dir: Path, dest_dir: str) -> Dict[str, Any]:
    source_dir = source_dir.resolve()
    copied: List[str] = []
    if not source_dir.exists():
        return {'source_dir': str(source_dir), 'dest_dir': dest_dir, 'copied_files': copied, 'exists': False}
    members: List[Tuple[Path, str]] = []
    for path in sorted(source_dir.rglob('*')):
        if not path.is_file() or path.name.startswith('._') or path.name == '.DS_Store' or '__pycache__' in path.parts:
            continue
        rel = path.relative_to(source_dir).as_posix()
        members.append((path, rel))
        copied.append(rel)
    with tempfile.NamedTemporaryFile('wb', delete=False) as handle:
        archive_path = Path(handle.name)
    try:
        with tarfile.open(archive_path, 'w:gz') as archive:
            for path, rel in members:
                info = archive.gettarinfo(str(path), arcname=rel)
                info.uid = info.gid = 0
                info.uname = info.gname = 'root'
                if info.isfile():
                    info.mode = 0o444
                with path.open('rb') as stream:
                    archive.addfile(info, stream)
        encoded = base64.b64encode(archive_path.read_bytes()).decode('ascii')
    finally:
        try:
            archive_path.unlink()
        except OSError:
            pass
    cmd = f"""set -euo pipefail
mkdir -p {shlex.quote(dest_dir)}
base64 -d <<'PATCHEVAL_TAR' | tar -C {shlex.quote(dest_dir)} -xzf -
{encoded}
PATCHEVAL_TAR
chmod -R a+rX,ugo-w {shlex.quote(dest_dir)}
"""
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=120)
    if result.returncode != 0:
        raise RuntimeError('failed to copy text tree into container: ' + tail_chars(result.stdout + result.stderr, 3000))
    return {'source_dir': str(source_dir), 'dest_dir': dest_dir, 'copied_files': copied, 'exists': True, 'transfer': 'single_base64_tar_exec'}


def load_raw_dataset_record(dataset_path: Path, cve_id: str) -> Dict[str, Any]:
    for line in dataset_path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        pid = obj.get('cve_id') or obj.get('problem_id') or obj.get('instance_id') or obj.get('id')
        if pid == cve_id:
            return obj
    raise RuntimeError(f'expected one raw record for {cve_id}, got 0')


def benchmark_name(args: argparse.Namespace) -> str:
    return str(getattr(args, 'benchmark', 'patcheval') or 'patcheval').strip().lower()


def benchmark_timeout_defaults(args: argparse.Namespace) -> Dict[str, int]:
    if benchmark_name(args) == 'secbench':
        return dict(SEC_BENCH_TIMEOUT_DEFAULTS)
    return dict(PATCH_EVAL_TIMEOUT_DEFAULTS)


def resolve_benchmark_timeouts(args: argparse.Namespace) -> Dict[str, int]:
    timeouts = benchmark_timeout_defaults(args)
    for key in TIMEOUT_PROFILE_KEYS:
        value = getattr(args, key, None)
        if value is not None:
            timeouts[key] = int(value)
    legacy_secbench_total = getattr(args, 'secbench_total_timeout_seconds', None)
    if benchmark_name(args) == 'secbench' and legacy_secbench_total is not None:
        timeouts['total_timeout_seconds'] = int(legacy_secbench_total)
    return timeouts


def apply_benchmark_timeouts(args: argparse.Namespace) -> Dict[str, int]:
    timeouts = resolve_benchmark_timeouts(args)
    for key, value in timeouts.items():
        setattr(args, key, value)
    return timeouts


def benchmark_total_deadline(args: argparse.Namespace, start: float) -> Optional[float]:
    seconds = int(getattr(args, 'total_timeout_seconds', 0) or 0)
    if seconds <= 0:
        return None
    return start + seconds


def deadline_limited_timeout(requested_seconds: int, deadline: Optional[float], label: str) -> int:
    requested = max(1, int(requested_seconds))
    if deadline is None:
        return requested
    remaining = deadline - time.time()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(label, requested)
    return max(1, min(requested, int(math.ceil(remaining))))


def enforce_deadline(deadline: Optional[float], label: str) -> None:
    if deadline is not None and time.time() >= deadline:
        raise subprocess.TimeoutExpired(label, 0)


def benchmark_profile(args: argparse.Namespace) -> Dict[str, str]:
    benchmark = benchmark_name(args)
    final_patch_path = str(getattr(args, 'final_patch_path', '/workspace/fix.patch') or '/workspace/fix.patch')
    if benchmark == 'secbench':
        return {
            'BENCHMARK_NAME': 'SEC-bench',
            'TASK_KIND': 'vulnerability instance',
            'FINAL_PATCH_PATH': final_patch_path,
            'PATH_POLICY': (
                f'- Target workdir: {{WORK_DIR}}\n'
                '- Source inspection and production source edits should stay under this directory.\n'
                '- It is allowed to run benchmark-provided commands such as `secb build` and `secb repro` from the target workdir.\n'
                '- Start exploration from this workspace root instead of guessing a path under /workspace.'
            ),
            'REPAIR_SOURCE_RESTRICTIONS': (
                '- Do not search the web for this vulnerability, advisory, issue, pull request, or upstream patch.\n'
                '- Do not run network commands such as curl, wget, git fetch, git pull, git ls-remote, package/advisory lookups, or web searches to find the fix.\n'
                '- Do not read or rely on SEC-bench reference patch data. The initial task input is limited to the repository, bug description, and sanitizer report.'
            ),
            'VALIDATION_INSTRUCTIONS': (
                '- Change to the target workdir and run `secb build` to check compilation.\n'
                '- If the build succeeds, run `secb repro` to check whether the sanitizer crash is gone.\n'
                '- The benchmark success criterion is that the selected patch applies cleanly, `secb build` succeeds, and `secb repro` no longer triggers sanitizer errors for the reported crash.\n'
                '- Treat non-source or test-only edits as invalid unless they are required by the production repair and explicitly justified.'
            ),
            'FINAL_PATCH_INSTRUCTIONS': (
                f'- Before stopping, write the selected final unified diff to `{final_patch_path}` from the target workdir.\n'
                f'- The outer SEC-bench adapter will submit `{final_patch_path}` as `model_patch.diff` for official evaluation.'
            ),
            'ANALYSIS_DELEGATION_INSTRUCTIONS': (
                '- SEC-bench inputs often describe native sanitizer crashes with a stack trace rather than an application-level security scenario.\n'
                '- Use `secb build` and `secb repro` for benchmark-grounded runtime evidence, but keep long sanitizer, debugger, and fuzzing logs in artifact files and pass only concise summaries plus paths to workers.\n'
                '- After a plausible source path, reproducer/oracle, and controls exist, invoke `evidence_review_worker` before writing the final vulnerability model unless execution constraints make review impossible.\n'
                '- If source/runtime exploration has already taken multiple rounds without narrowing the final model, delegate one narrow question to `source_reachability_worker`, `reproducer_worker`, or `boundary_control_worker` instead of continuing broad solo analysis.'
            ),
        }
    if benchmark != 'patcheval':
        raise ValueError(f'unsupported benchmark: {benchmark}')
    return {
        'BENCHMARK_NAME': 'PatchEval',
        'TASK_KIND': 'CVE',
        'FINAL_PATCH_PATH': final_patch_path,
        'PATH_POLICY': (
            f'- Target workdir: {{WORK_DIR}}\n'
            '- All tool path arguments must stay under this directory.\n'
            '- Start exploration from this workspace root instead of guessing a path under /workspace.'
        ),
        'REPAIR_SOURCE_RESTRICTIONS': (
            '- Do not search the web for this vulnerability, CVE, advisory, GHSA, release note, issue, pull request, or upstream patch.\n'
            '- Do not run network commands such as curl, wget, git fetch, git pull, git ls-remote, npm view, pip index, or package/advisory lookups to find the fix.'
        ),
        'VALIDATION_INSTRUCTIONS': (
            '- Prefer repository-native general build, test, and load checks under the target workdir.\n'
            '- Use phase-aware oracle semantics for repository-local validation scripts; treat baseline-oriented scripts according to their intended phase rather than by exit code alone.\n'
            '- Verify patch coupling: a post-patch security claim must come from a test that executes or imports the current patched worktree, or from an explicitly limited source-qualified substitute recorded in the matrix.'
        ),
        'FINAL_PATCH_INSTRUCTIONS': (
            f'- Before stopping, write the selected final unified diff to `{final_patch_path}` from the target workdir.\n'
            '- This workflow submits that generated patch directly to PatchEval evaluation.'
        ),
        'ANALYSIS_DELEGATION_INSTRUCTIONS': '',
    }


def apply_profile_to_record(record: Any, args: argparse.Namespace) -> Any:
    profile = benchmark_profile(args)
    for key, value in profile.items():
        setattr(record, key.lower(), value)
    setattr(record, 'benchmark', benchmark_name(args))
    setattr(record, 'task_id', getattr(record, 'cve_id', getattr(record, 'problem_id', '')))
    return record


def load_patcheval_record(dataset_path: Path, cve_id: str, args: argparse.Namespace):
    records = load_dataset(dataset_path, include_ids={cve_id})
    if len(records) != 1:
        raise RuntimeError(f'expected one record for {cve_id}, got {len(records)}')
    record = records[0]
    raw_record = load_raw_dataset_record(dataset_path, cve_id)
    cve_description = str(raw_record.get('cve_description') or '').strip()
    if not cve_description:
        raise ValueError(
            f'dataset record {cve_id} missing official field cve_description; '
            'cannot render CVE_DESCRIPTION'
        )
    setattr(record, 'cve_description', cve_description)
    setattr(record, 'raw_record', raw_record)
    return apply_profile_to_record(record, args)


def load_secbench_record(dataset_path: Path, instance_id: str, args: argparse.Namespace):
    raw_record = load_raw_dataset_record(dataset_path, instance_id)
    record_instance_id = str(raw_record.get('instance_id') or instance_id).strip()
    if record_instance_id != instance_id:
        raise RuntimeError(f'expected SEC-bench instance {instance_id}, got {record_instance_id}')
    bug_description = str(raw_record.get('bug_description') or '').strip()
    sanitizer_report = str(raw_record.get('sanitizer_report') or '').strip()
    work_dir = str(raw_record.get('work_dir') or '').strip()
    if not bug_description:
        raise ValueError(f'SEC-bench record {instance_id} missing bug_description')
    if not sanitizer_report:
        raise ValueError(f'SEC-bench record {instance_id} missing sanitizer_report')
    if not work_dir:
        raise ValueError(f'SEC-bench record {instance_id} missing work_dir')
    problem_statement = f'{bug_description}\n---\n{sanitizer_report}'
    image_name = str(raw_record.get('image_name') or raw_record.get('image_url') or '').strip()
    if not image_name:
        template = str(getattr(args, 'secbench_image_template', SECBENCH_IMAGE_TEMPLATE_DEFAULT) or '').strip()
        if template:
            image_name = template.format(instance_id=instance_id, task_id=instance_id, task_type='patch')
        else:
            prefix = str(getattr(args, 'secbench_image_prefix', SECBENCH_IMAGE_PREFIX_DEFAULT) or SECBENCH_IMAGE_PREFIX_DEFAULT).rstrip('.')
            image_name = f'{prefix}.{instance_id}:patch'
    record = SimpleNamespace(
        cve_id=instance_id,
        problem_id=instance_id,
        task_id=instance_id,
        image_name=image_name,
        image_url=image_name,
        work_dir=work_dir,
        problem_statement=problem_statement,
        cve_description=problem_statement,
        repo=str(raw_record.get('repo') or ''),
        raw_record=raw_record,
        base_commit=str(raw_record.get('base_commit') or 'HEAD'),
    )
    return apply_profile_to_record(record, args)


def load_record(dataset_path: Path, cve_id: str, args: argparse.Namespace):
    benchmark = benchmark_name(args)
    if benchmark == 'secbench':
        return load_secbench_record(dataset_path, cve_id, args)
    return load_patcheval_record(dataset_path, cve_id, args)


def docker_image_exists(image_name: str) -> bool:
    result = subprocess.run(['docker', 'image', 'inspect', image_name], text=True, capture_output=True, timeout=60)
    return result.returncode == 0


def ensure_secbench_image_loaded(record: Any, args: argparse.Namespace, total_deadline: Optional[float] = None) -> Dict[str, Any]:
    image_name = str(record.image_name)
    status: Dict[str, Any] = {
        'image_name': image_name,
        'source': '',
        'archive': '',
        'loaded': False,
        'already_present': False,
    }
    if docker_image_exists(image_name):
        status['source'] = 'local_docker'
        status['already_present'] = True
        return status

    manifest_path = Path(getattr(args, 'secbench_image_manifest', '') or '')
    if not manifest_path.exists():
        raise RuntimeError(
            f'SEC-bench image {image_name} is not loaded and manifest is missing: {manifest_path}. '
            'Load the image or provide --secbench-image-manifest.'
        )
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    match = None
    for item in manifest.get('images', []):
        if item.get('image') == image_name:
            match = item
            break
    if not match:
        raise RuntimeError(f'SEC-bench image {image_name} is not listed in manifest: {manifest_path}')
    archive_path = manifest_path.parent / str(match.get('archive', ''))
    if not archive_path.exists():
        raise RuntimeError(f'SEC-bench archive for {image_name} is missing: {archive_path}')

    cmd = f'gzip -dc {shlex.quote(str(archive_path))} | docker load'
    timeout = deadline_limited_timeout(3600, total_deadline, 'benchmark total timeout before SEC-bench image load')
    result = subprocess.run(['bash', '-lc', cmd], text=True, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError('failed to load SEC-bench image archive: ' + tail_chars(result.stdout + result.stderr, 4000))
    if not docker_image_exists(image_name):
        raise RuntimeError(
            f'SEC-bench archive loaded but expected image is still unavailable: {image_name}. '
            + tail_chars(result.stdout + result.stderr, 2000)
        )
    status.update({
        'source': 'local_archive_manifest',
        'archive': str(archive_path),
        'loaded': True,
    })
    return status


def container_files_nonempty(container_id: str, paths: List[str], timeout: int = 30) -> bool:
    if not paths:
        return False
    checks = ' && '.join(f'test -s {shlex.quote(path)}' for path in paths)
    try:
        result = docker_exec(container_id, ['bash', '-lc', checks], timeout=timeout)
        return result.returncode == 0
    except Exception:
        return False


def container_file_size(container_id: str, path: str, timeout: int = 20) -> Optional[int]:
    try:
        result = docker_exec(
            container_id,
            ['bash', '-lc', f'test -f {shlex.quote(path)} && stat -c %s {shlex.quote(path)}'],
            timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
    except Exception:
        return None
    return None


def sandbox_process_running(container_id: str, pattern: str, timeout: int = 20) -> bool:
    quoted = shlex.quote(pattern or 'opencode run')
    cmd = f"""
pattern={quoted}
self=$$
pgrep -f -- "$pattern" | awk -v self="$self" '$1 != self' | head -n 1 | grep -q .
"""
    try:
        result = docker_exec(
            container_id,
            ['bash', '-lc', cmd],
            timeout=timeout,
        )
        return result.returncode == 0
    except Exception:
        return True


def kill_opencode_stage_in_container(container_id: str, container_kill_pattern: str = '', timeout: int = 20) -> None:
    pattern = shlex.quote(container_kill_pattern or 'opencode run')
    kill_cmd = f"""
pattern={pattern}
self=$$
pids=$(pgrep -f -- "$pattern" | awk -v self="$self" '$1 != self' || true)
if [ -n "$pids" ]; then
    kill -TERM $pids || true
fi
sleep 2
pids=$(pgrep -f -- "$pattern" | awk -v self="$self" '$1 != self' || true)
if [ -n "$pids" ]; then
    kill -KILL $pids || true
fi
"""
    docker_exec(container_id, ['bash', '-lc', kill_cmd], timeout=timeout)


def sandbox_exec_shell_with_artifact_watch(
    opencode: OpenCodeRunner,
    *,
    command: str,
    timeout_seconds: int,
    expected_artifacts: Optional[List[str]],
    stage_name: str,
    container_kill_pattern: str = '',
    artifact_grace_seconds: int = 30,
    live_log_path: Optional[str] = None,
    before_timeout_callback: Optional[Callable[[str], None]] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    closeout_reserve_seconds: int = 0,
) -> Tuple[int, str, str]:
    watchdog_disabled = os.getenv('PATCHEVAL_SANDBOX_EXEC_ARTIFACT_WATCHDOG', '1').strip().lower() in {'0', 'false', 'no', 'off'}
    # Same-session closeout depends on the soft deadline, so it keeps the
    # watchdog active even if artifact-based monitoring was otherwise disabled.
    if watchdog_disabled and closeout_reserve_seconds <= 0:
        return sandbox_api_client.exec_shell(opencode.container_id, command, timeout=timeout_seconds)

    poll_seconds = max(5, int(os.getenv('PATCHEVAL_SANDBOX_EXEC_WATCHDOG_POLL_SECONDS', '30')))
    grace_seconds = max(5, int(os.getenv('PATCHEVAL_SANDBOX_EXEC_RETURN_GRACE_SECONDS', '15')))
    artifact_grace_seconds = max(5, int(os.getenv('PATCHEVAL_SANDBOX_EXEC_ARTIFACT_READY_GRACE_SECONDS', str(artifact_grace_seconds))))
    progress_seconds = max(30, int(os.getenv('PATCHEVAL_SANDBOX_EXEC_WATCHDOG_PROGRESS_SECONDS', '120')))
    pattern = container_kill_pattern or 'opencode run'
    result: Dict[str, Any] = {}
    done = threading.Event()

    def _exec() -> None:
        try:
            rc, stdout, stderr = sandbox_api_client.exec_shell(opencode.container_id, command, timeout=timeout_seconds)
            result.update({'ok': True, 'rc': rc, 'stdout': stdout, 'stderr': stderr})
        except BaseException as exc:
            result.update({'ok': False, 'error_type': type(exc).__name__, 'error': str(exc)})
        finally:
            done.set()

    thread = threading.Thread(target=_exec, name=f'{stage_name}-sandbox-exec', daemon=True)
    thread.start()
    artifact_absent_logged = False
    artifact_seen_at: Optional[float] = None
    done_seen_at: Optional[float] = None
    last_progress_log = 0.0
    last_progress_callback = 0.0
    progress_callback_seconds = max(0, int(os.getenv('PATCHEVAL_OPENCODE_TRACE_SNAPSHOT_SECONDS', '5')))
    deadline = time.monotonic() + timeout_seconds
    closeout_reserve_seconds = forced_closeout_reserve(timeout_seconds, closeout_reserve_seconds)
    if closeout_reserve_seconds > 0:
        # Periodic full session snapshots can block for minutes through the
        # sandbox API. The live JSONL is salvaged at the soft deadline, and the
        # resumed stage performs normal trace archival after closeout.
        progress_callback_seconds = 0
    before_timeout_called = False
    checkpoint_logged = False

    def call_before_timeout(reason: str) -> None:
        nonlocal before_timeout_called
        if before_timeout_callback is None or before_timeout_called:
            return
        before_timeout_called = True
        try:
            before_timeout_callback(reason)
        except Exception as exc:
            opencode._log_process_step(f'{stage_name}_before_timeout_callback_failed', {'reason': reason, 'error': str(exc)})

    wait_seconds = poll_seconds
    if progress_callback is not None and progress_callback_seconds > 0:
        wait_seconds = min(wait_seconds, max(1, progress_callback_seconds))
    while not done.wait(timeout=wait_seconds):
        now = time.monotonic()
        remaining = deadline - now
        ready = bool(expected_artifacts and container_files_nonempty(opencode.container_id, expected_artifacts, timeout=20))
        if progress_callback is not None and progress_callback_seconds > 0 and now - last_progress_callback >= progress_callback_seconds:
            last_progress_callback = now
            try:
                progress_callback('periodic_watchdog')
            except Exception as exc:
                opencode._log_process_step(f'{stage_name}_progress_callback_failed', {'reason': 'periodic_watchdog', 'error': str(exc)})
        if now - last_progress_log >= progress_seconds:
            last_progress_log = now
            opencode._log_process_step(
                f'{stage_name}_sandbox_exec_watchdog_progress',
                {
                    'elapsed_seconds': round(timeout_seconds - max(0.0, remaining), 1),
                    'remaining_seconds': round(max(0.0, remaining), 1),
                    'artifact_ready': ready,
                    'live_log_path': live_log_path or '',
                    'live_log_bytes': container_file_size(opencode.container_id, live_log_path, timeout=15) if live_log_path else None,
                },
            )
        watchdog_action = artifact_watchdog_action(
            artifact_ready=ready,
            remaining_seconds=remaining,
            closeout_reserve_seconds=closeout_reserve_seconds,
        )
        if watchdog_action == 'same_session_closeout':
            # The reserve belongs to the resumed lead session. Full container
            # and session snapshots can take minutes over the sandbox API, so
            # never synchronously capture them before stopping the old run.
            kill_opencode_stage_in_container(opencode.container_id, pattern, timeout=20)
            # Let the in-flight sandbox exec return before starting the resumed
            # command. This avoids overlapping two exec channels for one stage.
            done.wait(timeout=min(20, grace_seconds))
            opencode._log_process_step(
                f'{stage_name}_sandbox_exec_soft_deadline',
                {
                    'remaining_seconds': round(max(0.0, remaining), 1),
                    'closeout_reserve_seconds': closeout_reserve_seconds,
                    'artifact_ready': False,
                    'pattern': pattern,
                },
            )
            raise StageSoftTimeout(command, timeout_seconds - closeout_reserve_seconds, output=f'{stage_name} exploration budget ended without an artifact')
        if watchdog_action in {'complete_with_artifact', 'hard_timeout'}:
            call_before_timeout('sandbox_exec_deadline')
            if watchdog_action == 'complete_with_artifact':
                kill_opencode_stage_in_container(opencode.container_id, pattern, timeout=20)
                opencode._log_process_step(
                    f'{stage_name}_sandbox_exec_deadline_but_artifact_ready',
                    {'artifact_ready': True, 'pattern': pattern, 'live_log_path': live_log_path or ''},
                )
                return 0, f'[{stage_name}] expected artifact ready at deadline; continuing with artifact-based completion.\n', ''
            raise subprocess.TimeoutExpired(command, timeout_seconds, output=f'{stage_name} sandbox exec exceeded timeout')
        if ready:
            if artifact_seen_at is None:
                artifact_seen_at = now
                opencode._log_process_step(
                    f'{stage_name}_sandbox_exec_artifacts_seen',
                    {
                        'expected_artifacts': expected_artifacts,
                        'artifact_grace_seconds': artifact_grace_seconds,
                        'live_log_path': live_log_path or '',
                        'live_log_bytes': container_file_size(opencode.container_id, live_log_path, timeout=15) if live_log_path else None,
                    },
                )
            running = sandbox_process_running(opencode.container_id, pattern, timeout=20)
            if not running:
                if done_seen_at is None:
                    done_seen_at = now
                    opencode._log_process_step(
                        f'{stage_name}_sandbox_exec_return_wait',
                        {'artifact_ready': True, 'process_running': False, 'grace_seconds': grace_seconds, 'pattern': pattern},
                    )
                elif now - done_seen_at >= grace_seconds or remaining <= grace_seconds:
                    message = (
                        f'[{stage_name}] sandbox exec return channel hung after artifact readiness; '
                        f'expected artifacts exist and process pattern {pattern!r} is absent. '
                        'Continuing with artifact-based completion.\n'
                    )
                    opencode._log_process_step(
                        f'{stage_name}_sandbox_exec_return_hung_but_artifact_ready',
                        {'artifact_ready': True, 'pattern': pattern, 'grace_seconds': grace_seconds},
                    )
                    return 0, message, ''
            else:
                done_seen_at = None
                if artifact_seen_at is not None and now - artifact_seen_at >= artifact_grace_seconds:
                    if not checkpoint_logged:
                        checkpoint_logged = True
                        opencode._log_process_step(
                            f'{stage_name}_sandbox_exec_artifact_checkpoint',
                            {
                                'artifact_ready': True,
                                'process_continues': True,
                                'pattern': pattern,
                                'live_log_path': live_log_path or '',
                            },
                        )
        else:
            artifact_seen_at = None
            done_seen_at = None
            if not artifact_absent_logged:
                artifact_absent_logged = True
                opencode._log_process_step(f'{stage_name}_sandbox_exec_watchdog_started', {'poll_seconds': poll_seconds})

    if result.get('ok'):
        return int(result.get('rc', 1)), str(result.get('stdout') or ''), str(result.get('stderr') or '')
    error = f"{result.get('error_type', 'SandboxExecError')}: {result.get('error', '')}".strip()
    if result.get('error_type') == 'TimeoutError':
        call_before_timeout('sandbox_exec_api_timeout')
        raise subprocess.TimeoutExpired(command, timeout_seconds, output=error)
    raise RuntimeError(error)


def stop_opencode_stage_process(opencode: OpenCodeRunner, process: subprocess.Popen[str], container_kill_pattern: str = '') -> None:
    try:
        kill_opencode_stage_in_container(opencode.container_id, container_kill_pattern, timeout=10)
    except Exception:
        pass
    try:
        process.terminate()
        process.wait(timeout=10)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


BENCHMARK_ENV_EXACT_KEYS = {
    'ARCHITECTURE',
    'AR',
    'CC',
    'CFLAGS',
    'CMAKE_PREFIX_PATH',
    'CUSTOM_LIBFUZZER_PATH',
    'CUSTOM_LIBFUZZER_STD_CXX',
    'CXX',
    'CXXFLAGS',
    'CXXFLAGS_EXTRA',
    'FUZZING_ENGINE',
    'FUZZING_LANGUAGE',
    'FUZZINTRO_OUTDIR',
    'GOFLAGS',
    'GOPATH',
    'LANG',
    'LD',
    'LDFLAGS',
    'LD_LIBRARY_PATH',
    'LIB_FUZZING_ENGINE',
    'LIB_FUZZING_ENGINE_DEPRECATED',
    'NM',
    'OSS_FUZZ_ON_DEMAND',
    'OUT',
    'PKG_CONFIG_PATH',
    'PROJECT_NAME',
    'RANLIB',
    'RUSTFLAGS',
    'SANITIZER',
    'SRC',
    'WORK',
}
BENCHMARK_ENV_PREFIXES = (
    'COVERAGE_FLAGS_',
    'SANITIZER_FLAGS_',
)


def benchmark_env_export_prefix(container_id: str) -> Tuple[str, List[str]]:
    # Avoid NUL-delimited stdout here. Some sandbox exec transports can leave
    # the caller waiting even after the command has completed when stdout
    # contains NUL bytes.
    result = docker_exec(container_id, ['bash', '-lc', 'env'], timeout=30)
    if result.returncode != 0:
        return '', []
    exports: List[str] = []
    keys: List[str] = []
    for item in result.stdout.splitlines():
        if not item or '=' not in item:
            continue
        key, value = item.split('=', 1)
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
            continue
        if key not in BENCHMARK_ENV_EXACT_KEYS and not key.startswith(BENCHMARK_ENV_PREFIXES):
            continue
        exports.append(f'export {key}={shlex.quote(value)}')
        keys.append(key)
    if not exports:
        return '', []
    return '; '.join(exports) + '; ', sorted(keys)


def should_run_opencode_stage_as_root(preserved_env_keys: List[str]) -> bool:
    # SEC-bench follows OSS-Fuzz images whose build scripts expect root plus
    # image-level ENV such as SANITIZER/FUZZING_ENGINE. PatchEval keeps the
    # lower-privilege opencode_user path.
    return {'ARCHITECTURE', 'FUZZING_ENGINE', 'SANITIZER'}.issubset(set(preserved_env_keys))


def format_epoch_ms(value: Any) -> str:
    try:
        raw = float(value)
    except (TypeError, ValueError):
        return ''
    if raw <= 0:
        return ''
    seconds = raw / 1000.0 if raw > 100000000000 else raw
    return time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(seconds))


def parse_task_result_wrapper(output: str) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    task_match = re.search(r'<task\s+id="([^"]+)"\s+state="([^"]+)"[^>]*>', output)
    if task_match:
        parsed['task_id'] = task_match.group(1)
        parsed['task_state'] = task_match.group(2)
    result_match = re.search(r'<task_result>\s*(.*?)\s*</task_result>', output, re.DOTALL)
    if result_match:
        result_text = result_match.group(1).strip()
        parsed['task_result_chars'] = len(result_text)
        parsed['task_result_preview'] = tail_chars(result_text, 3000)
    return parsed


def summarize_subagent_task_calls(task_calls: List[Dict[str, Any]]) -> Dict[str, Any]:
    status_counts: Dict[str, int] = {}
    subagent_type_counts: Dict[str, int] = {}
    session_ids: List[str] = []
    durations: List[float] = []
    for call in task_calls:
        status = str(call.get('status') or 'unknown')
        status_counts[status] = status_counts.get(status, 0) + 1
        subagent_type = str(call.get('subagent_type') or 'unknown')
        subagent_type_counts[subagent_type] = subagent_type_counts.get(subagent_type, 0) + 1
        child_session_id = str(call.get('child_session_id') or '')
        if child_session_id and child_session_id not in session_ids:
            session_ids.append(child_session_id)
        duration = call.get('duration_seconds')
        if isinstance(duration, (int, float)):
            durations.append(float(duration))
    summary: Dict[str, Any] = {
        'task_call_count': len(task_calls),
        'status_counts': status_counts,
        'subagent_type_counts': subagent_type_counts,
        'child_session_ids': session_ids,
    }
    if durations:
        summary['duration_seconds'] = {
            'min': min(durations),
            'max': max(durations),
            'total': sum(durations),
            'mean': sum(durations) / len(durations),
        }
    return summary


def extract_subagent_trace_index(
    stage_log_path: Path,
    *,
    stage_name: str,
    cve_id: str,
    output_path: Path,
) -> Dict[str, Any]:
    index: Dict[str, Any] = {
        'schema_version': '1.0',
        'cve_id': cve_id,
        'stage_name': stage_name,
        'parent_log_path': str(stage_log_path),
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'log_exists': stage_log_path.exists(),
        'json_line_count': 0,
        'parse_error_count': 0,
        'tool_event_count': 0,
        'task_call_count': 0,
        'task_calls': [],
    }
    if not stage_log_path.exists():
        index['note'] = 'Stage log file does not exist, so no Task tool-use events can be indexed.'
        write_json(output_path, index)
        return index

    task_calls: List[Dict[str, Any]] = []
    with stage_log_path.open('r', encoding='utf-8', errors='replace') as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                index['parse_error_count'] += 1
                continue
            index['json_line_count'] += 1
            part = event.get('part') if isinstance(event, dict) else {}
            if not isinstance(part, dict):
                part = {}
            if event.get('type') != 'tool_use':
                continue
            index['tool_event_count'] += 1
            if part.get('tool') != 'task':
                continue
            state = part.get('state') if isinstance(part.get('state'), dict) else {}
            input_data = state.get('input') if isinstance(state.get('input'), dict) else {}
            metadata = state.get('metadata') if isinstance(state.get('metadata'), dict) else {}
            model = metadata.get('model') if isinstance(metadata.get('model'), dict) else {}
            timing = state.get('time') if isinstance(state.get('time'), dict) else {}
            start_ms = timing.get('start')
            end_ms = timing.get('end')
            duration_seconds: Optional[float] = None
            if isinstance(start_ms, (int, float)) and isinstance(end_ms, (int, float)) and end_ms >= start_ms:
                duration_seconds = (float(end_ms) - float(start_ms)) / 1000.0
            output = str(state.get('output') or '')
            parsed_task = parse_task_result_wrapper(output)
            prompt = str(input_data.get('prompt') or '')
            task_call: Dict[str, Any] = {
                'line_no': line_no,
                'event_timestamp_ms': event.get('timestamp'),
                'event_timestamp_iso': format_epoch_ms(event.get('timestamp')),
                'parent_session_id': metadata.get('parentSessionId') or event.get('sessionID') or part.get('sessionID') or '',
                'child_session_id': metadata.get('sessionId') or parsed_task.get('task_id', ''),
                'call_id': part.get('callID') or '',
                'status': state.get('status') or '',
                'subagent_type': input_data.get('subagent_type') or '',
                'description': input_data.get('description') or state.get('title') or '',
                'title': state.get('title') or '',
                'model_id': model.get('modelID') or '',
                'provider_id': model.get('providerID') or '',
                'time_start_ms': start_ms,
                'time_start_iso': format_epoch_ms(start_ms),
                'time_end_ms': end_ms,
                'time_end_iso': format_epoch_ms(end_ms),
                'duration_seconds': duration_seconds,
                'prompt_chars': len(prompt),
                'prompt_preview': tail_chars(prompt, 2000),
                'output_chars': len(output),
                'output_preview': tail_chars(output, 4000),
                'metadata_truncated': bool(metadata.get('truncated')),
            }
            task_call.update(parsed_task)
            task_calls.append(task_call)

    index['task_calls'] = task_calls
    index['task_call_count'] = len(task_calls)
    index['summary'] = summarize_subagent_task_calls(task_calls)
    if not task_calls:
        index['note'] = (
            'No Task tool-use events were present in this stage log. The lead did not delegate, '
            'or the run stopped before a delegated Task call emitted a result.'
        )
    write_json(output_path, index)
    return index


def run_opencode_stage(
    opencode: OpenCodeRunner,
    *,
    stage_name: str,
    prompt_text: str,
    prompt_path: str,
    message: str,
    timeout_seconds: int,
    host_log_path: Path,
    expected_artifacts: Optional[List[str]] = None,
    require_expected_artifacts: bool = True,
    artifact_poll_seconds: int = 10,
    artifact_grace_seconds: int = 8,
    container_kill_pattern: str = '',
    container_live_log_path: Optional[str] = None,
    subagent_trace_index_path: Optional[Path] = None,
    cve_id: str = '',
    artifact_dir: str = '',
    closeout_reserve_seconds: int = 0,
    resume_session_id: str = '',
    forced_closeout: bool = False,
) -> str:
    if prompt_path:
        opencode._log_process_step(f'{stage_name}_prompt_write', prompt_path)
        opencode._write_file_to_container(prompt_path, prompt_text)
        opencode._exec_in_container('chown', f'opencode_user:opencode_user {shlex.quote(prompt_path)}')
    opencode_bin = os.getenv('PATCHEVAL_OPENCODE_BIN', '/path/to/local/resource)
    cmd = build_opencode_run_command(
        opencode_bin=opencode_bin,
        model=opencode.model,
        message=message,
        prompt_path=prompt_path,
        resume_session_id=resume_session_id,
    )
    stage_cmd = cmd
    if is_sandbox_container(opencode.container_id) and container_live_log_path:
        live_log_dir = str(PurePosixPath(container_live_log_path).parent)
        stage_cmd = (
            f'mkdir -p {shlex.quote(live_log_dir)} && '
            f': > {shlex.quote(container_live_log_path)} && '
            f'set -o pipefail && ({cmd}) 2>&1 | tee -a {shlex.quote(container_live_log_path)}'
        )
        opencode._log_process_step(f'{stage_name}_live_log', container_live_log_path)
    env_prefix, preserved_env_keys = benchmark_env_export_prefix(opencode.container_id)
    if preserved_env_keys:
        opencode._log_process_step(f'{stage_name}_benchmark_env_preserved', {'keys': preserved_env_keys})
    budget_stage_name = re.sub(r'_closeout$', '', stage_name)
    command_budget_state = f'{artifact_dir}/command_budget/{budget_stage_name}.json' if artifact_dir else f'/tmp/{budget_stage_name}.command_budget.json'
    runtime_env = {
        'PATCHEVAL_STAGE_NAME': stage_name,
        'PATCHEVAL_FORCE_CLOSEOUT': '1' if forced_closeout else '0',
        'PATCHEVAL_COMMAND_BUDGET_STATE': command_budget_state,
        'PATCHEVAL_DEPENDENCY_SINGLE_COMMAND_SECONDS': os.getenv('PATCHEVAL_DEPENDENCY_SINGLE_COMMAND_SECONDS', '300'),
        'PATCHEVAL_DEPENDENCY_TOTAL_SECONDS': os.getenv('PATCHEVAL_DEPENDENCY_TOTAL_SECONDS', '900'),
        'PATCHEVAL_DEPENDENCY_MAX_CONSECUTIVE_FAILURES': os.getenv('PATCHEVAL_DEPENDENCY_MAX_CONSECUTIVE_FAILURES', '2'),
    }
    runtime_env_prefix = ''.join(
        f'export {key}={shlex.quote(value)}; '
        for key, value in runtime_env.items()
    )
    if should_run_opencode_stage_as_root(preserved_env_keys):
        shell_body = f'{runtime_env_prefix}{env_prefix}cd {shlex.quote(opencode.work_dir)} && {stage_cmd}'
        switch_user_cmd = f'bash -lc {shlex.quote(shell_body)}'
        opencode._log_process_step(f'{stage_name}_run_user', 'root')
    else:
        shell_body = f'source ~/.bashrc >/dev/null 2>&1 || true; {runtime_env_prefix}{env_prefix}cd {shlex.quote(opencode.work_dir)} && {stage_cmd}'
        switch_user_cmd = f'su - opencode_user -c {shlex.quote(shell_body)}'
        opencode._log_process_step(f'{stage_name}_run_user', 'opencode_user')
    full_cmd = f'docker exec {opencode.container_id} {switch_user_cmd}'
    opencode._log_process_step(f'{stage_name}_command', cmd)
    start = time.time()
    output_parts: List[str] = []
    artifact_ready = False
    artifacts_seen_at: Optional[float] = None
    stream_stats = {'lines': 0, 'chars': 0, 'last_progress_log': 0.0}
    host_log_path.parent.mkdir(parents=True, exist_ok=True)
    host_log_path.write_text('', encoding='utf-8')

    def write_subagent_trace_index() -> Dict[str, Any]:
        if subagent_trace_index_path is None:
            return {}
        try:
            index = extract_subagent_trace_index(
                host_log_path,
                stage_name=stage_name,
                cve_id=cve_id,
                output_path=subagent_trace_index_path,
            )
            opencode._log_process_step(
                f'{stage_name}_subagent_trace_index',
                {'path': str(subagent_trace_index_path), 'task_call_count': index.get('task_call_count', 0)},
            )
            return index
        except Exception as trace_exc:
            opencode._log_process_step(f'{stage_name}_subagent_trace_index_failed', str(trace_exc))
            return {}

    timeout_snapshot_done = False
    session_trace_lock = threading.Lock()
    session_trace_seen_event_keys: set[str] = set()

    def salvage_live_log_to_host(timeout: int = 30) -> None:
        if not container_live_log_path:
            return
        try:
            live_output = docker_read_text(opencode.container_id, container_live_log_path, missing_ok=True, timeout=timeout)
            if live_output:
                host_log_path.write_text(live_output, encoding='utf-8')
        except Exception as log_exc:
            opencode._log_process_step(f'{stage_name}_live_log_salvage_failed', str(log_exc))

    def capture_session_trace(reason: str) -> None:
        if not cve_id:
            return
        persist_raw = str(os.getenv('PATCHEVAL_PERSIST_OPENCODE_SESSION_TRACE', '1')).strip().lower()
        if persist_raw in {'0', 'false', 'no', 'off'}:
            return
        if not session_trace_lock.acquire(blocking=False):
            return
        try:
            outputs_root = host_log_path.parent.parent
            salvage_live_log_to_host(timeout=30)
            write_subagent_trace_index()
            manifest = capture_opencode_session_trace(
                container_id=opencode.container_id,
                cve_id=cve_id,
                stage_name=stage_name,
                outputs_root=outputs_root,
                work_dir=opencode.work_dir,
                stage_log_path=host_log_path,
                subagent_trace_index_path=subagent_trace_index_path,
                reason=reason,
                stream_seen_event_keys=session_trace_seen_event_keys,
                persist_snapshot=reason != 'periodic_watchdog',
            )
            appended_events = int(manifest.get('stream_appended_event_count') or 0)
            if reason != 'periodic_watchdog' or appended_events:
                opencode._log_process_step(
                    f'{stage_name}_opencode_session_trace',
                    {
                        'reason': reason,
                        'trace_root': manifest.get('trace_root', ''),
                        'persist_snapshot': manifest.get('persist_snapshot'),
                        'subagent_log_manifest_path': manifest.get('subagent_log_manifest_path', ''),
                        'stream_manifest_path': manifest.get('stream_manifest_path', ''),
                        'stream_appended_event_count': appended_events,
                        'materialized_session_count': (manifest.get('materialized_session_log_summary') or {}).get('materialized_session_count'),
                    },
                )
        except Exception as trace_exc:
            opencode._log_process_step(f'{stage_name}_opencode_session_trace_failed', {'reason': reason, 'error': str(trace_exc)})
        finally:
            session_trace_lock.release()

    def capture_stage_trace_snapshot(reason: str) -> None:
        nonlocal timeout_snapshot_done
        if timeout_snapshot_done or not artifact_dir or not cve_id:
            return
        timeout_snapshot_done = True
        salvage_live_log_to_host(timeout=30)
        write_subagent_trace_index()
        capture_session_trace(reason)
        try:
            outputs_root = host_log_path.parent.parent
            snapshot_path = copy_container_artifacts(
                opencode.container_id,
                cve_id,
                outputs_root,
                artifact_dir,
                extra_paths=workflow_snapshot_extra_paths(opencode.work_dir),
            )
            manifest_path = outputs_root / 'timeout_trace_snapshots' / f'{cve_id}.{stage_name}.{int(time.time())}.json'
            write_json(
                manifest_path,
                {
                    'cve_id': cve_id,
                    'stage_name': stage_name,
                    'reason': reason,
                    'snapshot_path': snapshot_path,
                    'stage_log_path': str(host_log_path),
                    'subagent_trace_index_path': str(subagent_trace_index_path) if subagent_trace_index_path else '',
                    'captured_before_process_kill': True,
                    'created_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                },
            )
            opencode._log_process_step(
                f'{stage_name}_pre_timeout_trace_snapshot',
                {'reason': reason, 'snapshot_path': snapshot_path, 'manifest_path': str(manifest_path)},
            )
        except Exception as snapshot_exc:
            opencode._log_process_step(f'{stage_name}_pre_timeout_trace_snapshot_failed', {'reason': reason, 'error': str(snapshot_exc)})

    if is_sandbox_container(opencode.container_id):
        run_semaphore, run_limit = get_opencode_run_semaphore()
        run_slot_acquired = False
        if run_semaphore is not None:
            opencode._log_process_step(f'{stage_name}_run_wait', {'limit': run_limit, 'runtime': 'sandbox_api'})
            run_semaphore.acquire()
            run_slot_acquired = True
            opencode._log_process_step(f'{stage_name}_run_slot_acquired', {'limit': run_limit, 'runtime': 'sandbox_api'})
        try:
            try:
                rc, stdout, stderr = sandbox_exec_shell_with_artifact_watch(
                    opencode,
                    command=switch_user_cmd,
                    timeout_seconds=timeout_seconds,
                    expected_artifacts=expected_artifacts,
                    stage_name=stage_name,
                    container_kill_pattern=container_kill_pattern,
                    artifact_grace_seconds=artifact_grace_seconds,
                    live_log_path=container_live_log_path,
                    before_timeout_callback=None if forced_closeout else capture_stage_trace_snapshot,
                    progress_callback=None if forced_closeout else capture_session_trace,
                    closeout_reserve_seconds=closeout_reserve_seconds,
                )
                output = stdout + stderr
            except StageSoftTimeout:
                # Keep this path deliberately small: the caller needs the live
                # parent log to recover the root session ID, not a full trace
                # snapshot. The resumed stage performs normal trace archival.
                kill_opencode_stage_in_container(opencode.container_id, container_kill_pattern, timeout=20)
                salvage_live_log_to_host(timeout=30)
                write_subagent_trace_index()
                raise
            except (TimeoutError, subprocess.TimeoutExpired) as exc:
                if not forced_closeout:
                    capture_stage_trace_snapshot('sandbox_timeout_except_before_kill')
                kill_opencode_stage_in_container(opencode.container_id, container_kill_pattern, timeout=20)
                if container_live_log_path:
                    try:
                        live_output = docker_read_text(opencode.container_id, container_live_log_path, missing_ok=True, timeout=30)
                        if live_output:
                            host_log_path.write_text(live_output, encoding='utf-8')
                            opencode._log_process_step(f'{stage_name}_live_log_salvaged', {'log': str(host_log_path), 'bytes': len(live_output.encode('utf-8'))})
                    except Exception as log_exc:
                        opencode._log_process_step(f'{stage_name}_live_log_salvage_failed', str(log_exc))
                if forced_closeout:
                    write_subagent_trace_index()
                else:
                    capture_session_trace('sandbox_timeout_exception')
                raise subprocess.TimeoutExpired(switch_user_cmd, timeout_seconds, output=str(exc)) from exc
            if container_live_log_path:
                try:
                    live_output = docker_read_text(opencode.container_id, container_live_log_path, missing_ok=True, timeout=60)
                    if live_output and (not output or len(live_output) >= len(output)):
                        output = live_output
                except Exception as log_exc:
                    opencode._log_process_step(f'{stage_name}_live_log_read_failed', str(log_exc))
            host_log_path.write_text(output, encoding='utf-8')
            write_subagent_trace_index()
            capture_session_trace('stage_complete')
            artifact_ready = bool(expected_artifacts and container_files_nonempty(opencode.container_id, expected_artifacts))
            if rc != 0 and not artifact_ready:
                raise RuntimeError(output[-4000:] or f'OpenCode exited with {rc}')
            if expected_artifacts and not artifact_ready and require_expected_artifacts:
                raise StageMissingArtifact(f'{stage_name} finished without expected artifacts: {expected_artifacts}')
            duration = time.time() - start
            opencode._log_process_step(f'{stage_name}_done', {'duration_seconds': duration, 'log': str(host_log_path), 'artifact_ready': artifact_ready, 'runtime': 'sandbox_api'})
            return output
        finally:
            if run_slot_acquired:
                run_semaphore.release()
                opencode._log_process_step(f'{stage_name}_run_slot_released', {'limit': run_limit, 'runtime': 'sandbox_api'})
    process = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    def drain_output() -> None:
        if process.stdout is None:
            return
        try:
            with host_log_path.open('a', encoding='utf-8') as stream_log:
                for line in process.stdout:
                    output_parts.append(line)
                    stream_log.write(line)
                    stream_log.flush()
                    stream_stats['lines'] += 1
                    stream_stats['chars'] += len(line)
                    now = time.time()
                    if now - stream_stats['last_progress_log'] >= 30:
                        stream_stats['last_progress_log'] = now
                        opencode._log_process_step(
                            f'{stage_name}_stream_progress',
                            {'lines': stream_stats['lines'], 'chars': stream_stats['chars'], 'log': str(host_log_path)},
                        )
        except Exception as exc:
            output_parts.append(f'\n[output-drain-error] {exc}\n')

    reader = threading.Thread(target=drain_output, daemon=True)
    reader.start()
    local_trace_snapshot_seconds = max(0, int(os.getenv('PATCHEVAL_OPENCODE_TRACE_SNAPSHOT_SECONDS', '5')))
    last_local_trace_snapshot = 0.0
    try:
        while True:
            return_code = process.poll()
            if return_code is not None:
                break
            now = time.time()
            if local_trace_snapshot_seconds > 0 and now - last_local_trace_snapshot >= local_trace_snapshot_seconds:
                last_local_trace_snapshot = now
                capture_session_trace('periodic_watchdog')
            if expected_artifacts and container_files_nonempty(opencode.container_id, expected_artifacts):
                if artifacts_seen_at is None:
                    artifacts_seen_at = now
                    opencode._log_process_step(f'{stage_name}_artifacts_seen', expected_artifacts)
                if now - artifacts_seen_at >= artifact_grace_seconds and not artifact_ready:
                    artifact_ready = True
                    opencode._log_process_step(
                        f'{stage_name}_artifact_checkpoint',
                        {'expected_artifacts': expected_artifacts, 'process_continues': True},
                    )
            else:
                artifacts_seen_at = None
                artifact_ready = False
            elapsed_seconds = now - start
            reserve_seconds = forced_closeout_reserve(timeout_seconds, closeout_reserve_seconds)
            local_watchdog_action = artifact_watchdog_action(
                artifact_ready=artifact_ready,
                remaining_seconds=timeout_seconds - elapsed_seconds,
                closeout_reserve_seconds=reserve_seconds,
            )
            if local_watchdog_action == 'same_session_closeout':
                stop_opencode_stage_process(opencode, process, container_kill_pattern)
                raise StageSoftTimeout(full_cmd, timeout_seconds - reserve_seconds, output=''.join(output_parts))
            if local_watchdog_action in {'complete_with_artifact', 'hard_timeout'}:
                capture_stage_trace_snapshot('local_timeout_before_kill')
                stop_opencode_stage_process(opencode, process, container_kill_pattern)
                if local_watchdog_action == 'complete_with_artifact':
                    break
                raise subprocess.TimeoutExpired(full_cmd, timeout_seconds, output=''.join(output_parts))
            time.sleep(max(1, min(artifact_poll_seconds, timeout_seconds - int(now - start))))
        reader.join(timeout=5)
        output = ''.join(output_parts)
        return_code = process.poll()
        if return_code not in (0, None) and not artifact_ready:
            raise RuntimeError(output[-4000:] or f'OpenCode exited with {return_code}')
    except StageSoftTimeout:
        output = ''.join(output_parts)
        host_log_path.parent.mkdir(parents=True, exist_ok=True)
        host_log_path.write_text(output, encoding='utf-8')
        write_subagent_trace_index()
        raise
    except Exception as exc:
        output = ''.join(output_parts) or str(exc)
        host_log_path.parent.mkdir(parents=True, exist_ok=True)
        host_log_path.write_text(output, encoding='utf-8')
        write_subagent_trace_index()
        capture_session_trace('stage_exception')
        raise
    duration = time.time() - start
    host_log_path.parent.mkdir(parents=True, exist_ok=True)
    host_log_path.write_text(output, encoding='utf-8')
    write_subagent_trace_index()
    capture_session_trace('stage_complete')
    artifact_ready = bool(expected_artifacts and container_files_nonempty(opencode.container_id, expected_artifacts))
    if expected_artifacts and not artifact_ready and require_expected_artifacts:
        raise StageMissingArtifact(f'{stage_name} finished without expected artifacts: {expected_artifacts}')
    opencode._log_process_step(f'{stage_name}_done', {'duration_seconds': duration, 'log': str(host_log_path), 'artifact_ready': artifact_ready})
    return output


def run_same_session_closeout(
    opencode: OpenCodeRunner,
    *,
    stage_name: str,
    original_log_path: Path,
    closeout_log_path: Path,
    message: str,
    timeout_seconds: int,
    expected_artifacts: List[str],
    require_expected_artifacts: bool,
    container_kill_pattern: str,
    container_live_log_path: str,
    cve_id: str,
    artifact_dir: str,
) -> str:
    session_id = extract_root_session_id_from_log(original_log_path)
    if not session_id:
        opencode_bin = os.getenv('PATCHEVAL_OPENCODE_BIN', '/path/to/local/resource)
        list_inner = (
            'source ~/.bashrc >/dev/null 2>&1 || true; '
            f'cd {shlex.quote(opencode.work_dir)} && '
            f'{shlex.quote(opencode_bin)} session list --format json --max-count 20 --pure'
        )
        try:
            listed = docker_exec(
                opencode.container_id,
                ['bash', '-lc', f'su - opencode_user -c {shlex.quote(list_inner)}'],
                timeout=45,
            )
            list_output = (listed.stdout or '') + (listed.stderr or '')
            session_id = extract_root_session_id_from_session_list(list_output, opencode.work_dir)
            opencode._log_process_step(
                f'{stage_name}_same_session_discovery',
                {
                    'source': 'opencode_session_list',
                    'session_id': session_id,
                    'returncode': listed.returncode,
                    'output_chars': len(list_output),
                },
            )
        except Exception as exc:
            opencode._log_process_step(
                f'{stage_name}_same_session_discovery_failed',
                {'source': 'opencode_session_list', 'error': str(exc)},
            )
    if not session_id:
        raise RuntimeError(f'{stage_name} cannot resume the original lead session: root session id was not found in {original_log_path}')
    opencode._log_process_step(
        f'{stage_name}_same_session_closeout_start',
        {'session_id': session_id, 'timeout_seconds': timeout_seconds, 'original_log_path': str(original_log_path)},
    )
    run_opencode_stage(
        opencode,
        stage_name=f'{stage_name}_closeout',
        prompt_text='',
        prompt_path='',
        message=message,
        timeout_seconds=max(1, int(timeout_seconds)),
        host_log_path=closeout_log_path,
        expected_artifacts=expected_artifacts,
        require_expected_artifacts=require_expected_artifacts,
        artifact_grace_seconds=30,
        container_kill_pattern=container_kill_pattern,
        container_live_log_path=container_live_log_path,
        subagent_trace_index_path=None,
        cve_id=cve_id,
        artifact_dir=artifact_dir,
        resume_session_id=session_id,
        forced_closeout=True,
    )
    opencode._log_process_step(
        f'{stage_name}_same_session_closeout_done',
        {'session_id': session_id, 'log': str(closeout_log_path)},
    )
    return session_id


def run_reproducer(container_id: str, work_dir: str, reproducer_path: str, timeout_seconds: int) -> Tuple[int, str]:
    cmd = (
        f'cd {shlex.quote(work_dir)} && '
        f'chmod +x {shlex.quote(reproducer_path)} && '
        f'timeout {int(timeout_seconds)} bash {shlex.quote(reproducer_path)}'
    )
    try:
        result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=timeout_seconds + 30)
        output = (result.stdout + result.stderr).strip()
        return result.returncode, output
    except subprocess.TimeoutExpired as exc:
        output = ''
        if isinstance(exc.stdout, str):
            output += exc.stdout
        if isinstance(exc.stderr, str):
            output += exc.stderr
        return 124, output.strip() + f'\nREPRODUCER_TIMEOUT after {timeout_seconds}s'


def run_model_shell_command(container_id: str, work_dir: str, command: str, timeout_seconds: int) -> Tuple[int, str]:
    text = str(command or '').strip()
    if not text:
        return 127, 'empty model command'
    if re.fullmatch(r'[/A-Za-z0-9._:+@%=-]+', text):
        return run_reproducer(container_id, work_dir, text, timeout_seconds)
    cmd = f'cd {shlex.quote(work_dir)} && timeout {int(timeout_seconds)} bash -lc {shlex.quote(text)}'
    try:
        result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=timeout_seconds + 30)
        output = (result.stdout + result.stderr).strip()
        return result.returncode, output
    except subprocess.TimeoutExpired as exc:
        output = ''
        if isinstance(exc.stdout, str):
            output += exc.stdout
        if isinstance(exc.stderr, str):
            output += exc.stderr
        return 124, output.strip() + f'\nREPRODUCER_TIMEOUT after {timeout_seconds}s'


def parse_json_lenient(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        match = re.search(r'\{.*\}', text, flags=re.S)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                return {}
    return {}


def parse_reproduction_feedback(feedback_json: str, return_code: int, output: str) -> Tuple[str, Dict[str, Any]]:
    parsed = parse_json_lenient(feedback_json)
    status = str(parsed.get('status', '')).strip().lower()
    if return_code != 0:
        return 'needs_refine', parsed
    if status in {'needs_refine', 'unusable'}:
        return status, parsed
    if status in {'reproduced', 'reproduced_but_weak'}:
        return status, parsed
    if 'VULNERABILITY_REPRODUCED' in output:
        return 'reproduced_but_weak', parsed
    return 'needs_refine', parsed


def parse_json_any_lenient(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        match = re.search(r'(\{.*\}|\[.*\])', text or '', flags=re.S)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                return {}
    return {}


def sanitize_direction_id(value: str, fallback: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(value or '').strip()).strip('_')
    return safe or fallback


def parse_poc_directions(text: str, cve_id: str, max_directions: int) -> List[Dict[str, Any]]:
    parsed = parse_json_any_lenient(text)
    if isinstance(parsed, list):
        raw = parsed
    elif isinstance(parsed, dict):
        raw = parsed.get('directions') or parsed.get('poc_directions') or parsed.get('candidate_directions') or []
    else:
        raw = []
    directions: List[Dict[str, Any]] = []
    for idx, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            continue
        direction = dict(item)
        direction['direction_id'] = sanitize_direction_id(str(direction.get('direction_id', '')), f'dir_{idx}')
        directions.append(direction)
        if len(directions) >= max(1, max_directions):
            break
    if not directions:
        directions.append({
            'direction_id': 'dir_1',
            'title': 'fallback direction from report and static trace',
            'source_api': 'unknown',
            'sink_api': 'unknown',
            'call_chain': [],
            'input_class': 'reported vulnerable input class',
            'payload_family': [],
            'vulnerable_signal': 'reported vulnerable behavior is observable',
            'patched_expected_signal': 'reported vulnerable behavior is blocked while compatibility is preserved',
            'compatibility_controls': [],
            'oracle_strength': 'weak',
            'oracle_risk': 'planner did not produce structured directions; testcase agent must ground this fallback in source',
            'root_cause_hint': 'infer the invariant from the report, static trace, and local code',
            'confidence': 0.2,
        })
    return directions


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {'true', 'yes', 'y', '1'}:
        return True
    if text in {'false', 'no', 'n', '0'}:
        return False
    return None


def _lookup_nested(mapping: Any, keys: Tuple[str, ...]) -> Any:
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        if key in mapping:
            return mapping.get(key)
    for nested_key in ('entrypoint_coverage', 'coverage', 'coverage_assessment', 'repair_fit', 'validation'):
        nested = mapping.get(nested_key)
        value = _lookup_nested(nested, keys)
        if value is not None:
            return value
    return None


def _parse_run_poc_spec(run: Dict[str, Any]) -> Dict[str, Any]:
    parsed = parse_json_lenient(str(run.get('poc_spec', '') or ''))
    return parsed if isinstance(parsed, dict) else {}


def run_field(run: Dict[str, Any], *keys: str) -> Any:
    feedback = run.get('feedback') if isinstance(run.get('feedback'), dict) else {}
    for source in (feedback, _parse_run_poc_spec(run), run.get('direction') if isinstance(run.get('direction'), dict) else {}):
        value = _lookup_nested(source, tuple(keys))
        if value is not None:
            return value
    return None


def run_bool(run: Dict[str, Any], *keys: str) -> Optional[bool]:
    return _as_bool(run_field(run, *keys))


def compact_repair_fit_run(run: Dict[str, Any]) -> Dict[str, Any]:
    poc_spec = _parse_run_poc_spec(run)
    direction = run.get('direction') if isinstance(run.get('direction'), dict) else {}
    return {
        'direction_id': run.get('direction_id'),
        'status': run.get('status'),
        'return_code': run.get('return_code'),
        'oracle_quality': run_field(run, 'oracle_quality') or '',
        'public_entrypoint_ok': run_bool(run, 'public_entrypoint_ok'),
        'is_direct_sink_only': run_bool(run, 'is_direct_sink_only', 'direct_sink_only'),
        'compatibility_controls_ok': run_bool(run, 'compatibility_controls_ok'),
        'source_api': poc_spec.get('source_api') or direction.get('source_api') or '',
        'sink_api': poc_spec.get('sink_api') or direction.get('sink_api') or '',
        'call_chain': poc_spec.get('call_chain') or direction.get('call_chain') or [],
        'tested_entrypoints': run_field(run, 'tested_entrypoints') or [],
        'untested_public_entrypoints': run_field(run, 'untested_public_entrypoints') or [],
        'weak_reason': run_field(run, 'weak_reason') or '',
        'evidence': run_field(run, 'evidence') or '',
    }


def direction_score(run: Dict[str, Any]) -> float:
    status = str(run.get('status', '')).lower()
    score = {'reproduced': 100.0, 'reproduced_but_weak': 75.0, 'needs_refine': 25.0, 'unusable': 0.0}.get(status, 0.0)
    oracle_quality = str(run_field(run, 'oracle_quality') or '').lower()
    if oracle_quality == 'strong':
        score += 12.0
    elif oracle_quality == 'weak':
        score -= 4.0
    public_ok = run_bool(run, 'public_entrypoint_ok')
    direct_only = run_bool(run, 'is_direct_sink_only', 'direct_sink_only')
    compatibility_ok = run_bool(run, 'compatibility_controls_ok')
    if public_ok is True:
        score += 24.0
    elif public_ok is False:
        score -= 8.0
    if direct_only is True:
        score -= 35.0
    if compatibility_ok is True:
        score += 8.0
    elif compatibility_ok is False:
        score -= 4.0
    if status == 'reproduced_but_weak' and public_ok is not True:
        score -= 10.0
    try:
        score += float(run.get('direction', {}).get('confidence', 0)) * 3.0
    except Exception:
        pass
    return score


def choose_direction_run(direction_runs: List[Dict[str, Any]], selected_direction_id: str = '') -> Dict[str, Any]:
    if not direction_runs:
        return {}
    ranked = sorted(direction_runs, key=direction_score, reverse=True)
    selected = None
    if selected_direction_id:
        for run in direction_runs:
            if str(run.get('direction_id')) == selected_direction_id:
                selected = run
                break
    if not selected:
        return ranked[0]
    best = ranked[0]
    if best is selected:
        return selected
    if direction_score(best) >= direction_score(selected) + 20.0:
        return best
    return selected


def direction_is_repair_primary(run: Dict[str, Any]) -> bool:
    # C2: every reproduced direction is a repair-primary gate.
    status = str(run.get('status', '')).strip().lower()
    return status == 'reproduced'


def choose_primary_direction_runs(direction_runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    primary = [run for run in direction_runs if direction_is_repair_primary(run)]
    if not primary:
        primary = [run for run in direction_runs if str(run.get('status', '')).strip().lower() == 'reproduced_but_weak']
    return sorted(primary, key=direction_score, reverse=True)


def safe_path_segment(value: Any, fallback: str = 'direction') -> str:
    raw = str(value or '').strip() or fallback
    cleaned = re.sub(r'[^A-Za-z0-9_.-]+', '_', raw).strip('._-')
    return (cleaned or fallback)[:80]


def primary_direction_id_set(primary_runs: List[Dict[str, Any]]) -> set:
    return {str(run.get('direction_id', '')).strip() for run in primary_runs if str(run.get('direction_id', '')).strip()}


def build_repair_fit_context(
    *,
    selected_direction_id: str,
    selected_run: Dict[str, Any],
    direction_runs: List[Dict[str, Any]],
    primary_runs: List[Dict[str, Any]],
    static_trace: Dict[str, Any],
    invariant: Dict[str, Any],
) -> str:
    legacy_selected_fit = compact_repair_fit_run(selected_run)
    ranked_runs = sorted(direction_runs, key=direction_score, reverse=True)
    primary_fits = [compact_repair_fit_run(run) for run in primary_runs]
    all_fits = [compact_repair_fit_run(run) for run in ranked_runs]
    primary_ids = [fit.get('direction_id') for fit in primary_fits]
    primary_id_set = set(str(item) for item in primary_ids)
    lines = [
        '# C2 All-Primary Repair-Fit Context',
        '',
        'C2 treats every reproduced direction as a primary repair gate. Do not repair only the cleanest or selected direction; the final patch must satisfy every primary direction after repair.',
        '',
        '## Primary Directions Required For Repair',
        json.dumps(primary_fits, ensure_ascii=False, indent=2),
        '',
        '## Legacy Summarizer Selection (not exclusive)',
        f'- summarizer_selected_direction_id: {selected_direction_id or "(none)"}',
        f'- legacy_repair_selected_direction_id: {selected_run.get("direction_id", "")}',
        f'- primary_direction_ids: {json.dumps(primary_ids, ensure_ascii=False)}',
        f'- legacy_selected_score: {direction_score(selected_run):.2f}',
        '',
        '## Root-Cause Invariant Snapshot',
        json.dumps({
            'repair_ready': invariant.get('repair_ready'),
            'evidence_level': invariant.get('evidence_level'),
            'root_cause': invariant.get('root_cause'),
            'must_reject_or_constrain': invariant.get('must_reject_or_constrain'),
            'must_preserve': invariant.get('must_preserve'),
            'source_to_sink_cut_point': invariant.get('source_to_sink_cut_point'),
            'forbidden_patch_behaviors': invariant.get('forbidden_patch_behaviors'),
            'primary_vulnerable_signal': invariant.get('primary_vulnerable_signal'),
            'patched_expected_behavior': invariant.get('patched_expected_behavior'),
        }, ensure_ascii=False, indent=2),
        '',
        '## Static Trace Public Boundary Hints',
        json.dumps({
            'source': static_trace.get('source'),
            'sink': static_trace.get('sink'),
            'entrypoints': static_trace.get('entrypoints', [])[:8],
            'candidate_call_chains': static_trace.get('candidate_call_chains', [])[:3],
            'official_eval_hypothesis': static_trace.get('official_eval_hypothesis'),
        }, ensure_ascii=False, indent=2),
        '',
        '## All Direction Repair-Fit Scores',
        json.dumps([{**fit, 'score': direction_score(run), 'primary_required': str(run.get('direction_id')) in primary_id_set} for fit, run in zip(all_fits, ranked_runs)], ensure_ascii=False, indent=2),
        '',
        '## C2 Repair Rules',
        '- Every reproduced direction is primary. Supporting/noisy is only for non-reproduced directions.',
        '- Patch the shared source-to-sink security boundary so every primary direction flips from vulnerable to not reproduced.',
        '- If primary directions cover different entrypoints or bypass mechanisms, carry all of them into the patch design rather than choosing one.',
        '- Use compatibility controls and existing source behavior to avoid overbroad blocking.',
    ]
    for run, fit in zip(primary_runs, primary_fits):
        if fit.get('is_direct_sink_only') is True:
            lines.append(f"- WARNING: primary {run.get('direction_id')} is direct-sink-only; lift the fix to the nearest shared production boundary before patching.")
        if fit.get('public_entrypoint_ok') is not True:
            lines.append(f"- WARNING: primary {run.get('direction_id')} lacks public-entrypoint coverage; satisfy it plus the other public primary directions.")
        if fit.get('compatibility_controls_ok') is False:
            lines.append(f"- WARNING: primary {run.get('direction_id')} compatibility controls are not passing; inspect before broadening the patch.")
    if not primary_runs:
        lines.append('- WARNING: no primary direction was selected; repair should not proceed without reproduced evidence.')
    return chr(10).join(lines).strip() + chr(10)




def _string_list(value: Any, limit: int = 20) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        items = [value]
    out: List[str] = []
    seen = set()
    for item in items:
        rendered = json.dumps(item, ensure_ascii=False, sort_keys=True) if isinstance(item, dict) else str(item)
        rendered = tail_chars(rendered.strip(), 500)
        if rendered and rendered not in seen:
            out.append(rendered)
            seen.add(rendered)
        if len(out) >= limit:
            break
    return out


def compact_static_trace_public_boundary(static_trace: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(static_trace, dict):
        return {'source': '', 'sink': '', 'entrypoints': [], 'candidate_call_chains': [], 'key_files': []}
    entrypoints = []
    for item in (static_trace.get('entrypoints') or static_trace.get('key_functions') or [])[:10]:
        if isinstance(item, dict):
            symbol = item.get('symbol') or item.get('name') or item.get('function') or ''
            file_path = item.get('file') or item.get('path') or ''
            line = item.get('line') or item.get('start_line') or ''
            if file_path and symbol:
                entrypoints.append(f'{file_path}:{line}::{symbol}' if line else f'{file_path}::{symbol}')
            elif symbol:
                entrypoints.append(str(symbol))
        else:
            entrypoints.append(str(item))
    chains = []
    for chain in (static_trace.get('candidate_call_chains') or [])[:3]:
        if isinstance(chain, dict):
            chains.append({
                'chain_id': chain.get('chain_id'),
                'entry_api': chain.get('entry_api'),
                'source': chain.get('source'),
                'sink': chain.get('sink'),
                'files': _string_list(chain.get('files'), 8),
                'functions': _string_list(chain.get('functions'), 8),
                'confidence': chain.get('confidence'),
                'summary': chain.get('summary'),
            })
        else:
            chains.append({'summary': str(chain)})
    return {
        'source': static_trace.get('source') or '',
        'sink': static_trace.get('sink') or '',
        'entrypoints': _string_list(entrypoints, 10),
        'candidate_call_chains': chains,
        'key_files': _string_list(static_trace.get('key_files'), 12),
        'confidence': static_trace.get('confidence'),
        'official_eval_hypothesis': static_trace.get('official_eval_hypothesis') or '',
    }


def summarize_reproducer_output(output: str) -> Dict[str, Any]:
    text = output or ''
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    signal = ''
    if 'REGRESSION_CONTROL_FAILED' in text:
        signal = 'REGRESSION_CONTROL_FAILED'
    elif 'VULNERABILITY_REPRODUCED' in text:
        signal = 'VULNERABILITY_REPRODUCED'
    elif lines:
        signal = tail_chars(lines[-1], 300)
    return {'signal': signal, 'line_count': len(lines), 'output_tail': tail_chars(text, 1200)}


def compact_selected_poc_spec(run: Dict[str, Any], invariant: Dict[str, Any]) -> Dict[str, Any]:
    spec = _parse_run_poc_spec(run)
    direction = run.get('direction') if isinstance(run.get('direction'), dict) else {}
    return {
        'vulnerability_type': spec.get('vulnerability_type') or direction.get('vulnerability_type') or '',
        'root_cause_invariant': spec.get('root_cause_invariant') or invariant.get('root_cause') or '',
        'source_api': spec.get('source_api') or direction.get('source_api') or '',
        'sink_api': spec.get('sink_api') or direction.get('sink_api') or '',
        'call_chain': _string_list(spec.get('call_chain') or direction.get('call_chain'), 12),
        'input_class': spec.get('input_class') or direction.get('input_class') or '',
        'is_end_to_end': _as_bool(spec.get('is_end_to_end')),
        'is_direct_sink_only': run_bool(run, 'is_direct_sink_only', 'direct_sink_only'),
        'vulnerable_signal': spec.get('vulnerable_signal') or direction.get('vulnerable_signal') or invariant.get('primary_vulnerable_signal') or '',
        'patched_expected_signal': spec.get('patched_expected_signal') or direction.get('patched_expected_signal') or invariant.get('patched_expected_behavior') or '',
        'compatibility_controls': _string_list(spec.get('compatibility_controls') or direction.get('compatibility_controls'), 20),
        'forbidden_patch_behaviors': _string_list(spec.get('forbidden_patch_behaviors') or invariant.get('forbidden_patch_behaviors'), 20),
        'weakness_or_uncertainty': spec.get('weakness_or_uncertainty') or run_field(run, 'weak_reason') or '',
    }


def build_primary_direction_contract(
    run: Dict[str, Any],
    invariant: Dict[str, Any],
    artifacts: Dict[str, Any],
) -> Dict[str, Any]:
    fit = compact_repair_fit_run(run)
    spec = compact_selected_poc_spec(run, invariant)
    return {
        'direction_id': run.get('direction_id', ''),
        'status': run.get('status') or '',
        'score': round(direction_score(run), 2),
        'repair_fit': fit,
        'poc_spec': spec,
        'regression_contract': {
            'vulnerable_signal': spec.get('vulnerable_signal') or 'VULNERABILITY_REPRODUCED on vulnerable checkout',
            'patched_expected_signal': spec.get('patched_expected_signal') or 'No VULNERABILITY_REPRODUCED; compatibility controls still pass',
            'compatibility_requirements': spec.get('compatibility_controls') or [],
            'reproducer_path': artifacts.get('reproducer_path', ''),
            'control_tests_path': artifacts.get('control_tests_path', ''),
        },
        'validation': {
            'reproduced_iteration': int(run.get('iteration') or 0),
            'oracle_quality': fit.get('oracle_quality') or '',
            'public_entrypoint_ok': fit.get('public_entrypoint_ok'),
            'direct_sink_only': fit.get('is_direct_sink_only'),
            'compatibility_controls_ok': fit.get('compatibility_controls_ok'),
            'before_fix_observation': summarize_reproducer_output(run.get('reproducer_output', '')),
        },
        'artifacts': artifacts,
    }


def build_c1_repair_context_contract(
    *,
    record: Any,
    static_trace: Dict[str, Any],
    invariant: Dict[str, Any],
    repair_brief: str,
    selected_direction_id: str,
    selected_run: Dict[str, Any],
    direction_runs: List[Dict[str, Any]],
    primary_runs: List[Dict[str, Any]],
    primary_direction_artifacts: Dict[str, Dict[str, Any]],
    selected_reproducer_path: str,
    control_tests_path: str,
    repair_context_dir: str,
    artifact_dir: str,
    repair_fit_context_path: str,
    final_reproducer_output: str,
    reproduced_iteration: int,
) -> Dict[str, Any]:
    selected_fit = compact_repair_fit_run(selected_run)
    primary_ids = primary_direction_id_set(primary_runs)
    primary_contracts = [
        build_primary_direction_contract(run, invariant, primary_direction_artifacts.get(str(run.get('direction_id', '')), {}))
        for run in primary_runs
    ]
    ranked_runs = sorted(direction_runs, key=direction_score, reverse=True)
    directions_summary = []
    for run in ranked_runs[:8]:
        fit = compact_repair_fit_run(run)
        direction_id = str(fit.get('direction_id') or '')
        directions_summary.append({
            'direction_id': fit.get('direction_id'),
            'status': fit.get('status'),
            'score': round(direction_score(run), 2),
            'primary_required': direction_id in primary_ids,
            'public_entrypoint_ok': fit.get('public_entrypoint_ok'),
            'is_direct_sink_only': fit.get('is_direct_sink_only'),
            'oracle_quality': fit.get('oracle_quality'),
            'weak_reason': fit.get('weak_reason'),
        })
    coverage_matrix = []
    for item in primary_contracts:
        fit = item.get('repair_fit', {})
        coverage_matrix.append({
            'direction_id': item.get('direction_id'),
            'public_entrypoint_ok': fit.get('public_entrypoint_ok'),
            'direct_sink_only': fit.get('is_direct_sink_only'),
            'tested_entrypoints': _string_list(fit.get('tested_entrypoints'), 20),
            'untested_public_entrypoints': _string_list(fit.get('untested_public_entrypoints'), 20),
            'source_api': fit.get('source_api', ''),
            'sink_api': fit.get('sink_api', ''),
        })
    return {
        'cve_id': record.cve_id,
        'schema_version': 'c2.repair_context_contract.v1',
        'contract_policy': 'all_reproduced_directions_are_primary_and_must_pass_after_repair',
        'vulnerability_summary': {
            'root_cause': invariant.get('root_cause') or '',
            'evidence_level': invariant.get('evidence_level') or '',
            'repair_ready': bool(invariant.get('repair_ready')) or bool(primary_contracts),
            'repair_brief_summary': tail_chars(repair_brief.strip(), 1800),
        },
        'repair_target': {
            'must_reject_or_constrain': _string_list(invariant.get('must_reject_or_constrain'), 20),
            'must_preserve': _string_list(invariant.get('must_preserve'), 20),
            'source_to_sink_cut_point': invariant.get('source_to_sink_cut_point') or '',
            'forbidden_patch_behaviors': _string_list(invariant.get('forbidden_patch_behaviors'), 20),
            'static_trace_public_boundary': compact_static_trace_public_boundary(static_trace),
        },
        'primary_directions': primary_contracts,
        'legacy_selected_direction': {
            'summarizer_selected_direction_id': selected_direction_id,
            'legacy_repair_selected_direction_id': selected_run.get('direction_id', ''),
            'repair_fit': selected_fit,
            'note': 'C2 keeps this only for backward-compatible logs. It is not exclusive; all primary_directions are required.',
        },
        'direction_triage': directions_summary,
        'entrypoint_coverage': {
            'policy': 'coverage is evaluated across all primary_directions, not only a selected direction',
            'primary_direction_ids': [item.get('direction_id') for item in primary_contracts],
            'coverage_matrix': coverage_matrix,
        },
        'regression_contract': {
            'all_primary_required': True,
            'directions': [item.get('regression_contract', {}) for item in primary_contracts],
            'legacy_selected_reproducer_path': selected_reproducer_path,
            'legacy_control_tests_path': control_tests_path,
        },
        'validation': {
            'primary_direction_count': len(primary_contracts),
            'primary_direction_ids': [item.get('direction_id') for item in primary_contracts],
            'before_fix_observations': {item.get('direction_id'): item.get('validation', {}).get('before_fix_observation', {}) for item in primary_contracts},
            'legacy_reproduction_status': selected_run.get('status') or '',
            'legacy_reproduced_iteration': reproduced_iteration,
            'legacy_before_fix_observation': summarize_reproducer_output(final_reproducer_output),
            'post_repair_policy': 'fail run if any primary reproducer still reports VULNERABILITY_REPRODUCED or any primary compatibility control fails',
        },
        'artifacts': {
            'repair_context_json': f'{repair_context_dir}/repair_context.json',
            'repair_context_contract_json': f'{repair_context_dir}/repair_context_contract.json',
            'repair_context_summary_md': f'{repair_context_dir}/repair_context_summary.md',
            'repair_fit_context_md': repair_fit_context_path,
            'primary_direction_artifacts': [item.get('artifacts', {}) for item in primary_contracts],
            'legacy_selected_reproducer_sh': selected_reproducer_path,
            'legacy_control_tests_sh': control_tests_path,
            'direction_results_for_summarizer_md': f'{artifact_dir}/direction_results_for_summarizer.md',
        },
    }



def c1_repair_context_contract_markdown(contract: Dict[str, Any]) -> str:
    vuln = contract.get('vulnerability_summary', {})
    target = contract.get('repair_target', {})
    primary = contract.get('primary_directions', []) or []
    entry = contract.get('entrypoint_coverage', {})
    validation = contract.get('validation', {})
    artifacts = contract.get('artifacts', {})
    lines = [
        f"# C2 Repair Context Contract for {contract.get('cve_id', '')}",
        '',
        'This compact contract is the only repair-facing upstream summary. C2 treats every reproduced direction as a primary gate; raw scripts and full outputs remain in artifacts and are not inlined.',
        '',
        '## Root Cause',
        str(vuln.get('root_cause') or '(unspecified)'),
        '',
        '## Repair Target',
        f"- Must reject/constrain: {json.dumps(target.get('must_reject_or_constrain', []), ensure_ascii=False)}",
        f"- Must preserve: {json.dumps(target.get('must_preserve', []), ensure_ascii=False)}",
        f"- Cut point: {target.get('source_to_sink_cut_point', '')}",
        f"- Forbidden patch behaviors: {json.dumps(target.get('forbidden_patch_behaviors', []), ensure_ascii=False)}",
        '',
        '## Primary Directions (All Required)',
    ]
    for item in primary:
        fit = item.get('repair_fit', {})
        regression = item.get('regression_contract', {})
        lines.extend([
            f"### {item.get('direction_id', '')}",
            f"- status: {item.get('status', '')}",
            f"- score: {item.get('score', '')}",
            f"- source_api: {fit.get('source_api', '')}",
            f"- sink_api: {fit.get('sink_api', '')}",
            f"- public_entrypoint_ok: {fit.get('public_entrypoint_ok')}",
            f"- direct_sink_only: {fit.get('is_direct_sink_only')}",
            f"- vulnerable signal: {regression.get('vulnerable_signal', '')}",
            f"- patched expected signal: {regression.get('patched_expected_signal', '')}",
            f"- reproducer: {regression.get('reproducer_path', '')}",
            f"- controls: {regression.get('control_tests_path', '')}",
        ])
    lines.extend([
        '',
        '## Entrypoint Coverage Matrix',
        json.dumps(entry.get('coverage_matrix', []), ensure_ascii=False, indent=2),
        '',
        '## Validation Policy',
        f"- Primary direction count: {validation.get('primary_direction_count', 0)}",
        f"- Primary direction ids: {json.dumps(validation.get('primary_direction_ids', []), ensure_ascii=False)}",
        f"- Post-repair policy: {validation.get('post_repair_policy', '')}",
        '',
        '## Artifact Paths',
        f"- repair_context.json: {artifacts.get('repair_context_json', '')}",
        f"- repair_fit_context.md: {artifacts.get('repair_fit_context_md', '')}",
        f"- primary_direction_artifacts: {json.dumps(artifacts.get('primary_direction_artifacts', []), ensure_ascii=False)}",
        f"- full direction results: {artifacts.get('direction_results_for_summarizer_md', '')}",
    ])
    return chr(10).join(lines).strip() + chr(10)



def build_c1_compact_constructed_poc_field(contract: Dict[str, Any], record: Any) -> str:
    primary = contract.get('primary_directions', []) or []
    validation = contract.get('validation', {})
    lines = [
        f'# Compact Multi-Primary Regression Evidence for {record.cve_id}',
        '',
        'Use this as evidence only. C2 keeps every reproduced direction as a primary repair gate. Raw scripts and full outputs are intentionally not inlined; use artifact paths only if needed.',
        '',
        f"- repair_context.json: {contract.get('artifacts', {}).get('repair_context_json', '')}",
        f"- primary direction ids: {json.dumps(validation.get('primary_direction_ids', []), ensure_ascii=False)}",
        f"- post-repair policy: {validation.get('post_repair_policy', '')}",
        '',
        '## Primary Direction Contracts',
    ]
    for item in primary:
        regression = item.get('regression_contract', {})
        observation = item.get('validation', {}).get('before_fix_observation', {})
        lines.extend([
            f"### {item.get('direction_id', '')}",
            f"- reproducer_path: {regression.get('reproducer_path', '')}",
            f"- control_tests_path: {regression.get('control_tests_path', '')}",
            f"- vulnerable signal: {regression.get('vulnerable_signal', '')}",
            f"- patched expected signal: {regression.get('patched_expected_signal', '')}",
            f"- before-fix signal: {observation.get('signal', '')}",
            f"- before-fix output tail: {tail_chars(observation.get('output_tail', ''), 700)}",
            '',
        ])
    return chr(10).join(lines).strip() + chr(10)



def build_c1_repair_knowledge_digest(contract: Dict[str, Any]) -> str:
    target = contract.get('repair_target', {})
    boundary = target.get('static_trace_public_boundary', {})
    lines = [
        '# Compact Repository/Security Context',
        '',
        'Raw static trace and testcase knowledge are retained in artifacts. This digest only carries repair-relevant location and boundary hints.',
        '',
        f"- source: {boundary.get('source', '')}",
        f"- sink: {boundary.get('sink', '')}",
        f"- key files: {json.dumps(boundary.get('key_files', []), ensure_ascii=False)}",
        f"- candidate entrypoints: {json.dumps(boundary.get('entrypoints', []), ensure_ascii=False)}",
        f"- candidate call chains: {json.dumps(boundary.get('candidate_call_chains', []), ensure_ascii=False)}",
        f"- official eval hypothesis: {boundary.get('official_eval_hypothesis', '')}",
    ]
    return chr(10).join(lines).strip() + chr(10)


def c1_control_context(contract: Dict[str, Any]) -> str:
    primary = contract.get('primary_directions', []) or []
    lines = ['# Compatibility Control Summary', 'Every primary direction with controls must pass after repair.']
    for item in primary:
        regression = item.get('regression_contract', {})
        lines.extend([
            f"- {item.get('direction_id', '')} control_tests.sh: {regression.get('control_tests_path', '')}",
            f"  requirements: {json.dumps(regression.get('compatibility_requirements', []), ensure_ascii=False)}",
        ])
    lines.append('- Script bodies are not inlined; run/read paths only if needed.')
    return chr(10).join(lines).strip() + chr(10)


def c1_oracle_context(contract: Dict[str, Any]) -> str:
    primary = contract.get('primary_directions', []) or []
    lines = ['# Oracle Summary', 'All primary direction oracles are required repair gates.']
    for item in primary:
        regression = item.get('regression_contract', {})
        validation = item.get('validation', {})
        lines.extend([
            f"## {item.get('direction_id', '')}",
            f"- vulnerable signal: {regression.get('vulnerable_signal', '')}",
            f"- patched expected signal: {regression.get('patched_expected_signal', '')}",
            f"- oracle quality: {validation.get('oracle_quality', '')}",
            f"- public_entrypoint_ok: {validation.get('public_entrypoint_ok')}",
            f"- direct_sink_only: {validation.get('direct_sink_only')}",
        ])
    return chr(10).join(lines).strip() + chr(10)


def c1_root_cause_context(contract: Dict[str, Any]) -> str:
    return json.dumps({
        'vulnerability_summary': contract.get('vulnerability_summary', {}),
        'repair_target': contract.get('repair_target', {}),
        'entrypoint_coverage': contract.get('entrypoint_coverage', {}),
        'primary_directions': contract.get('primary_directions', []),
    }, ensure_ascii=False, indent=2) + chr(10)


def direction_runs_for_prompt(direction_runs: List[Dict[str, Any]], max_chars: int) -> str:
    per_budget = max(3000, max_chars // max(1, len(direction_runs)))
    blocks: List[str] = []
    for run in direction_runs:
        feedback = run.get('feedback') if isinstance(run.get('feedback'), dict) else {}
        lines = [
            f"## Direction {run.get('direction_id', 'unknown')}",
            '',
            '### Planned Direction',
            '```json',
            json.dumps(run.get('direction', {}), ensure_ascii=False, indent=2),
            '```',
            '',
            '### Reproduction Judgment',
            f"- status: {run.get('status', 'unknown')}",
            f"- return_code: {run.get('return_code', 'unknown')}",
            f"- oracle_quality: {feedback.get('oracle_quality', 'unknown')}",
            f"- public_entrypoint_ok: {feedback.get('public_entrypoint_ok', 'unknown')}",
            f"- compatibility_controls_ok: {feedback.get('compatibility_controls_ok', 'unknown')}",
            f"- weak_reason: {feedback.get('weak_reason', '')}",
            f"- error: {run.get('error', '')}",
            '',
            '### PoC Spec',
            tail_chars(run.get('poc_spec', ''), per_budget // 4),
            '',
            '### Oracle Summary',
            tail_chars(run.get('oracle_summary', ''), per_budget // 4),
            '',
            '### Reproducer Output Tail',
            '```',
            tail_chars(run.get('reproducer_output', ''), per_budget // 4),
            '```',
            '',
            '### Reproduction Feedback',
            tail_chars(run.get('feedback_md') or run.get('feedback_json', ''), per_budget // 4),
        ]
        blocks.append('\n'.join(lines))
    return '\n\n'.join(blocks).strip() + '\n'


def build_multi_direction_constructed_poc_field(
    *,
    record: Any,
    selected_run: Dict[str, Any],
    direction_results_summary: str,
    root_cause_invariant_text: str,
    repair_brief: str,
    selected_reproducer_path: str,
    max_chars: int,
) -> str:
    lines = [
        f'# Multi-Direction PoC Evidence for {record.cve_id}',
        '',
        'The upstream agents explored multiple candidate directions. This field is evidence for repair, not ground truth.',
        '',
        '## Selected Direction',
        f"- direction_id: {selected_run.get('direction_id', 'unknown')}",
        f"- reproduction_status: {selected_run.get('status', 'unknown')}",
        f"- selected_reproducer_path: {selected_reproducer_path or '(none)'}",
        '',
        '## Clean Root-Cause Invariant',
        '<begin_of_root_cause_invariant>',
        tail_chars(root_cause_invariant_text, max(3000, max_chars // 4)),
        '<end_of_root_cause_invariant>',
        '',
        '## Repair Brief',
        '<begin_of_repair_brief>',
        tail_chars(repair_brief, max(3000, max_chars // 4)),
        '<end_of_repair_brief>',
        '',
        '## Selected Reproducer Script',
        '<begin_of_reproducer_sh>',
        tail_chars(selected_run.get('reproducer', ''), max(3000, max_chars // 4)),
        '<end_of_reproducer_sh>',
        '',
        '## Selected Reproducer Output',
        '<begin_of_reproducer_output>',
        tail_chars(selected_run.get('reproducer_output', ''), max(2000, max_chars // 6)),
        '<end_of_reproducer_output>',
        '',
        '## Direction Result Summary',
        tail_chars(direction_results_summary, max(4000, max_chars // 3)),
    ]
    return '\n'.join(lines).strip() + '\n'


def copy_container_artifacts(
    container_id: str,
    cve_id: str,
    outputs: Path,
    artifact_dir: str,
    extra_paths: Optional[List[str]] = None,
) -> str:
    persist_raw = str(os.getenv('PATCHEVAL_COPY_CONTAINER_ARTIFACTS', '1')).strip().lower()
    if persist_raw in {'0', 'false', 'no', 'off'}:
        return ''
    stamp = time.strftime('%Y%m%d_%H%M%S')
    dest_parent = outputs / 'container_artifact_snapshots' / cve_id / stamp
    dest_parent.mkdir(parents=True, exist_ok=True)
    extra_paths = [path for path in (extra_paths or []) if path]

    def note_snapshot_error(label: str, detail: str) -> None:
        if not detail:
            return
        with (dest_parent / 'snapshot_errors.log').open('a', encoding='utf-8') as handle:
            handle.write(f'{label}: {detail}\n')

    def salvage_extra_path(path: str) -> Optional[str]:
        safe = re.sub(r'[^A-Za-z0-9_.-]+', '_', path.strip('/')) or 'extra'
        if not is_sandbox_container(container_id):
            dest = dest_parent / 'salvaged' / safe
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                result = subprocess.run(['docker', 'cp', f'{container_id}:{path}', str(dest)], capture_output=True, text=True, timeout=120)
                if result.returncode != 0:
                    note_snapshot_error(f'salvage {path}', tail_chars((result.stdout + result.stderr).strip(), 2000))
                    return None
                return str(dest)
            except Exception as exc:
                with (dest_parent / 'salvage_errors.log').open('a', encoding='utf-8') as handle:
                    handle.write(f'{path}: {exc}\n')
                return None
        parent = shlex.quote(str(PurePosixPath(path).parent))
        base = shlex.quote(PurePosixPath(path).name)
        inner = f"set -euo pipefail; test -e {shlex.quote(path)}; tar -C {parent} -czf - {base} | base64 | tr -d '\n'"
        cmd = 'bash -lc ' + shlex.quote(inner)
        try:
            rc, stdout, stderr = sandbox_api_client.exec_shell(container_id, cmd, timeout=120)
            if rc != 0 or not stdout:
                note_snapshot_error(f'salvage {path}', tail_chars((stdout + stderr).strip(), 2000))
                return None
            salvage_dir = dest_parent / 'salvaged' / safe
            salvage_dir.mkdir(parents=True, exist_ok=True)
            archive_path = salvage_dir / (PurePosixPath(path).name + '.tar.gz')
            archive_path.write_bytes(base64.b64decode(stdout.encode('ascii')))
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(salvage_dir)
            return str(salvage_dir)
        except Exception as exc:
            with (dest_parent / 'salvage_errors.log').open('a', encoding='utf-8') as handle:
                handle.write(f'{path}: {exc}\n')
            return None

    def finalize_snapshot(return_path: str) -> str:
        try:
            export_report = export_opencode_session_store(dest_parent)
            if export_report.get('errors'):
                note_snapshot_error('opencode_session_export', json.dumps(export_report.get('errors'), ensure_ascii=False))
        except Exception as exc:
            note_snapshot_error('opencode_session_export', str(exc))
        return return_path

    def salvage_extra_paths() -> List[str]:
        salvaged: List[str] = []
        for path in extra_paths:
            saved = salvage_extra_path(path)
            if saved:
                salvaged.append(saved)
        return salvaged

    if is_sandbox_container(container_id):
        parent = shlex.quote(str(Path(artifact_dir).parent))
        base = shlex.quote(Path(artifact_dir).name)
        inner = f"set -euo pipefail; test -e {shlex.quote(artifact_dir)}; tar -C {parent} -czf - {base} | base64 | tr -d '\n'"
        cmd = 'bash -lc ' + shlex.quote(inner)
        rc, stdout, stderr = sandbox_api_client.exec_shell(container_id, cmd, timeout=240)
        if rc != 0:
            saved = salvage_extra_paths()
            if saved:
                note_snapshot_error('artifact_dir', tail_chars((stdout + stderr).strip(), 2000))
                return finalize_snapshot(str(dest_parent))
            return (stdout + stderr).strip()
        archive_path = dest_parent / (Path(artifact_dir).name + '.tar.gz')
        archive_path.write_bytes(base64.b64decode(stdout.encode('ascii')))
        with tarfile.open(archive_path, 'r:gz') as tar:
            tar.extractall(dest_parent)
        salvage_extra_paths()
        return finalize_snapshot(str(dest_parent / Path(artifact_dir).name))
    result = subprocess.run(['docker', 'cp', f'{container_id}:{artifact_dir}', str(dest_parent)], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        saved = salvage_extra_paths()
        if saved:
            note_snapshot_error('artifact_dir', tail_chars((result.stdout + result.stderr).strip(), 2000))
            return finalize_snapshot(str(dest_parent))
        return (result.stdout + result.stderr).strip()
    salvage_extra_paths()
    return finalize_snapshot(str(dest_parent / Path(artifact_dir).name))


def workflow_snapshot_extra_paths(work_dir: str) -> List[str]:
    return [
        '/workspace/fix.patch',
        '/workspace/candidate-cve-fix.patch',
        f'{work_dir}/.repair',
        f'{work_dir}/.repair-mas',
        f'{work_dir}/.opencode',
        '/workspace/.opencode',
        '/root/.config/opencode',
        '/root/.local/share/opencode',
        '/root/.local/state/opencode',
        '/path/to/local/resource
        '/path/to/local/resource
        '/path/to/local/resource
    ]


def opencode_session_store_paths(work_dir: str) -> List[str]:
    return [
        f'{work_dir}/.opencode',
        '/workspace/.opencode',
        '/root/.config/opencode',
        '/root/.local/share/opencode',
        '/root/.local/state/opencode',
        '/path/to/local/resource
        '/path/to/local/resource
        '/path/to/local/resource
    ]


def extract_candidate_patch(
    container_id: str,
    work_dir: str,
    patch_path: str = '/workspace/candidate-cve-fix.patch',
    allow_worktree_fallback: bool = True,
) -> str:
    read_errors: List[str] = []
    for candidate_path in [
        patch_path,
        f'{work_dir}/.repair/candidate.patch',
        f'{work_dir}/.repair-mas/candidate.patch',
    ]:
        try:
            candidate = docker_read_text(container_id, candidate_path, missing_ok=True, timeout=60)
        except Exception as exc:
            read_errors.append(f'{candidate_path}: {exc}')
            continue
        if candidate.strip():
            return _normalize_extracted_patch(container_id, work_dir, candidate)
    if not allow_worktree_fallback:
        detail = '; '.join(read_errors)
        raise RuntimeError(f'repair agent did not produce required patch file: {patch_path}' + (f' ({detail})' if detail else ''))
    diff_cmd = f'cd {shlex.quote(work_dir)} && git diff --binary HEAD'
    result = docker_exec(container_id, ['bash', '-lc', diff_cmd], timeout=120)
    if result.returncode != 0:
        raise RuntimeError('failed to extract candidate patch: ' + (result.stdout + result.stderr).strip())
    return _normalize_extracted_patch(container_id, work_dir, result.stdout)


SUBMISSION_PATCH_FORBIDDEN_PREFIXES = (
    '.vulnerability-analysis/',
    '.repair/',
    '.repair-mas/',
    '.opencode/',
)


def list_worktree_files(container_id: str, work_dir: str) -> List[str]:
    result = docker_exec(
        container_id,
        ['bash', '-lc', f'cd {shlex.quote(work_dir)} && git ls-files'],
        timeout=60,
    )
    if result.returncode != 0:
        return []
    return [line.strip().replace('\\', '/') for line in result.stdout.splitlines() if line.strip()]


def _normalize_extracted_patch(container_id: str, work_dir: str, patch_text: str) -> str:
    files = list_worktree_files(container_id, work_dir)
    return normalize_candidate_patch_paths(patch_text, work_dir=work_dir, repo_files=files)


def _decode_git_patch_path(path_token: str) -> str:
    path = path_token.strip()
    if not path:
        return ''
    if path in {'/dev/null', 'dev/null'}:
        return ''
    if len(path) >= 2 and path[0] in {'"', "'"} and path[-1] == path[0]:
        try:
            parts = shlex.split(path)
            if parts:
                path = parts[0]
        except ValueError:
            path = path[1:-1]
    if path.startswith('a/') or path.startswith('b/'):
        path = path[2:]
    path = path.replace('\\', '/')
    while path.startswith('./'):
        path = path[2:]
    return path


def patch_file_paths(patch_text: str) -> List[str]:
    paths: List[str] = []
    seen: set[str] = set()
    for line in patch_text.splitlines():
        tokens: List[str] = []
        if line.startswith('diff --git '):
            try:
                tokens = shlex.split(line[len('diff --git '):])
            except ValueError:
                tokens = line[len('diff --git '):].split()
        elif line.startswith('--- ') or line.startswith('+++ '):
            tokens = [line[4:].split('\t', 1)[0].strip()]
        elif line.startswith('rename from ') or line.startswith('rename to '):
            tokens = [line.split(' ', 2)[2].strip()]
        else:
            continue
        for token in tokens:
            path = _decode_git_patch_path(token)
            if not path or path in seen:
                continue
            seen.add(path)
            paths.append(path)
    return paths


def validate_submission_patch_paths(patch_text: str) -> Dict[str, Any]:
    paths = patch_file_paths(patch_text)
    unsafe_paths: List[Dict[str, str]] = []
    forbidden_paths: List[Dict[str, str]] = []
    for path in paths:
        parts = PurePosixPath(path).parts
        if path.startswith('/') or '\\' in path or '..' in parts:
            unsafe_paths.append({'path': path, 'reason': 'absolute, backslash, or parent-directory path'})
            continue
        normalized = path.rstrip('/') + '/'
        for prefix in SUBMISSION_PATCH_FORBIDDEN_PREFIXES:
            if normalized.startswith(prefix):
                forbidden_paths.append({'path': path, 'reason': f'analysis artifact prefix {prefix}'})
                break
    ok = not unsafe_paths and not forbidden_paths
    return {
        'ok': ok,
        'paths': paths,
        'unsafe_paths': unsafe_paths,
        'forbidden_paths': forbidden_paths,
        'forbidden_prefixes': list(SUBMISSION_PATCH_FORBIDDEN_PREFIXES),
    }


def assert_submission_patch_paths(patch_text: str) -> Dict[str, Any]:
    validation = validate_submission_patch_paths(patch_text)
    if validation['ok']:
        return validation
    failures = validation['unsafe_paths'] + validation['forbidden_paths']
    details = '; '.join(f"{item['path']} ({item['reason']})" for item in failures[:12])
    if len(failures) > 12:
        details += f'; ... {len(failures) - 12} more'
    raise RuntimeError(
        'candidate patch contains paths that cannot be submitted as the final patch: ' + details
    )


def export_candidate_patch(
    *,
    outputs: Path,
    cve_id: str,
    candidate_patch: str,
    result: Dict[str, Any],
    source: str,
) -> None:
    candidate_host_path = outputs / 'candidate_patches' / f'{cve_id}.patch'
    candidate_host_path.parent.mkdir(parents=True, exist_ok=True)
    candidate_host_path.write_text(candidate_patch, encoding='utf-8')
    result['patch_path_validation'] = assert_submission_patch_paths(candidate_patch)
    exported_patch_path = outputs / 'patches' / f'{cve_id}.patch'
    exported_patch_path.parent.mkdir(parents=True, exist_ok=True)
    exported_patch_path.write_text(candidate_patch, encoding='utf-8')
    result['candidate_patch_path'] = str(candidate_host_path)
    result['candidate_patch_stats'] = simple_patch_stats(candidate_patch)
    result['patch_path'] = str(exported_patch_path)
    result['patch_stats'] = simple_patch_stats(candidate_patch)
    result['patch_export_source'] = source


def check_candidate_patch_in_clean_worktree(container_id: str, work_dir: str, patch_path: str, timeout: int = 180) -> Dict[str, Any]:
    cmd = f'''
set -euo pipefail
cd {shlex.quote(work_dir)}
test -s {shlex.quote(patch_path)}
tmp="$(mktemp -d /tmp/patcheval-clean-apply.XXXXXX)"
cleanup() {{
    cd {shlex.quote(work_dir)} >/dev/null 2>&1 || true
    git worktree remove --force "$tmp" >/dev/null 2>&1 || rm -rf "$tmp"
    git worktree prune >/dev/null 2>&1 || true
}}
trap cleanup EXIT
git worktree add --detach --quiet "$tmp" HEAD
cd "$tmp"
git apply --check --whitespace=nowarn {shlex.quote(patch_path)}
'''
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=timeout)
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        raise RuntimeError('candidate patch does not apply to a clean baseline worktree: ' + output)
    return {
        'return_code': result.returncode,
        'output_tail': tail_chars(output, 2000),
        'mode': 'temporary_git_worktree_git_apply_check',
    }


def apply_candidate_patch_for_validation(container_id: str, work_dir: str, patch_path: str = '/workspace/candidate-cve-fix.patch') -> Dict[str, Any]:
    # Apply the candidate patch to a clean checkout before generated-gate validation.
    reset_ok, reset_output = reset_worktree(container_id, work_dir)
    if not reset_ok:
        raise RuntimeError('failed to reset worktree before applying candidate patch: ' + reset_output)
    clean_worktree_check = check_candidate_patch_in_clean_worktree(container_id, work_dir, patch_path)
    cmd = (
        f'cd {shlex.quote(work_dir)} && '
        f'test -s {shlex.quote(patch_path)} && '
        f'git apply --whitespace=nowarn {shlex.quote(patch_path)}'
    )
    result = docker_exec(container_id, ['bash', '-lc', cmd], timeout=120)
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        raise RuntimeError('failed to apply candidate patch before post-validation: ' + output)
    return {
        'patch_path': patch_path,
        'work_dir': work_dir,
        'return_code': result.returncode,
        'output_tail': tail_chars(output, 2000),
        'clean_worktree_check': clean_worktree_check,
    }


def simple_patch_stats(patch_text: str) -> Dict[str, Any]:
    return {
        'bytes': len(patch_text.encode('utf-8')),
        'diff_files': patch_text.count('diff --git '),
        'added_lines': sum(1 for line in patch_text.splitlines() if line.startswith('+') and not line.startswith('+++')),
        'removed_lines': sum(1 for line in patch_text.splitlines() if line.startswith('-') and not line.startswith('---')),
    }


def profile_value(record: Any, name: str, default: str = '') -> str:
    value = str(getattr(record, name.lower(), default) or default)
    return (
        value
        .replace('{WORK_DIR}', str(getattr(record, 'work_dir', '')))
        .replace('{TASK_ID}', str(getattr(record, 'task_id', getattr(record, 'cve_id', ''))))
    )


def stage_values(record: Any, artifact_dir: str, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    cve_description = str(getattr(record, 'cve_description', '') or '').strip()
    if not cve_description:
        raise ValueError(f'dataset record {record.cve_id} missing cve_description; cannot render CVE_DESCRIPTION')
    task_id = str(getattr(record, 'task_id', getattr(record, 'cve_id', '')) or '')
    values = {
        'CVE_ID': record.cve_id,
        'TASK_ID': task_id,
        'BENCHMARK_NAME': profile_value(record, 'BENCHMARK_NAME', 'PatchEval'),
        'TASK_KIND': profile_value(record, 'TASK_KIND', 'CVE'),
        'WORK_DIR': record.work_dir,
        'REPO_NAME': Path(record.work_dir).name,
        'CVE_DESCRIPTION': cve_description,
        'PROBLEM_STATEMENT': record.problem_statement,
        'PATH_POLICY': profile_value(record, 'PATH_POLICY'),
        'REPAIR_SOURCE_RESTRICTIONS': profile_value(record, 'REPAIR_SOURCE_RESTRICTIONS'),
        'VALIDATION_INSTRUCTIONS': profile_value(record, 'VALIDATION_INSTRUCTIONS'),
        'FINAL_PATCH_INSTRUCTIONS': profile_value(record, 'FINAL_PATCH_INSTRUCTIONS'),
        'ANALYSIS_DELEGATION_INSTRUCTIONS': profile_value(record, 'ANALYSIS_DELEGATION_INSTRUCTIONS'),
        'FINAL_PATCH_PATH': profile_value(record, 'FINAL_PATCH_PATH', '/workspace/fix.patch'),
        'ARTIFACT_DIR': artifact_dir,
    }
    if extra:
        values.update(extra)
    return values


SENSITIVE_FIELD_RE = re.compile(r'(token|secret|password|credential|api[_-]?key|authorization)', re.IGNORECASE)
SENSITIVE_VALUE_RE = re.compile(r'\b(sk-[A-Za-z0-9_-]{12,}|Bearer\s+[A-Za-z0-9._-]{12,})\b')
OPENCODE_TRACE_TABLES = {'session', 'message', 'part', 'session_message', 'session_input', 'todo', 'event'}
OPENCODE_STREAM_TABLES = {'session', 'message', 'part', 'session_input', 'todo'}


def redact_trace_value(value: Any, key: str = '') -> Any:
    if SENSITIVE_FIELD_RE.search(key):
        return '[redacted]'
    if isinstance(value, dict):
        return {str(k): redact_trace_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_trace_value(item, key) for item in value]
    if isinstance(value, str):
        redacted = SENSITIVE_VALUE_RE.sub('[redacted]', value)
        if len(redacted) > 20000:
            return tail_chars(redacted, 20000)
        return redacted
    return value


def compact_stream_text(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    head_len = max(1, limit // 2)
    tail_len = max(1, limit - head_len)
    omitted = len(text) - head_len - tail_len
    return text[:head_len] + f'\n[truncated {omitted} chars]\n' + text[-tail_len:]


def compact_stream_value(value: Any, *, key: str = '', string_limit: Optional[int] = None) -> Any:
    limit = string_limit
    if limit is None:
        limit = max(1000, int(os.getenv('PATCHEVAL_OPENCODE_STREAM_STRING_LIMIT', '8000')))
    value = redact_trace_value(value, key)
    if isinstance(value, dict):
        return {str(k): compact_stream_value(v, key=str(k), string_limit=limit) for k, v in value.items()}
    if isinstance(value, list):
        max_items = max(20, int(os.getenv('PATCHEVAL_OPENCODE_STREAM_LIST_LIMIT', '200')))
        compacted = [compact_stream_value(item, key=key, string_limit=limit) for item in value[:max_items]]
        if len(value) > max_items:
            compacted.append({'truncated_items': len(value) - max_items})
        return compacted
    if isinstance(value, str):
        return compact_stream_text(value, limit)
    return value


def sqlite_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def sqlite_rows_as_dicts(
    conn: sqlite3.Connection,
    table: str,
    columns: List[str],
    *,
    limit: int,
) -> List[Dict[str, Any]]:
    table_sql = sqlite_identifier(table)
    if 'time_created' in columns:
        order_sql = ' order by time_created asc'
    elif 'seq' in columns:
        order_sql = ' order by seq asc'
    else:
        order_sql = ' order by rowid asc'
    rows: List[Dict[str, Any]] = []
    for row in conn.execute(f'select * from {table_sql}{order_sql} limit ?', (limit,)):
        item: Dict[str, Any] = {}
        for idx, column in enumerate(columns):
            value: Any = row[idx]
            if column == 'data' and isinstance(value, str):
                parsed = parse_json_lenient(value)
                value = parsed if parsed else value
            item[column] = redact_trace_value(value, column)
        rows.append(item)
    return rows


def export_opencode_sqlite_db(db_path: Path, output_path: Path, *, max_rows: int) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        'db_path': str(db_path),
        'db_size_bytes': db_path.stat().st_size if db_path.exists() else 0,
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'tables': {},
    }
    # The DB files exported for trace inspection are static copies. Opening
    # them as immutable avoids shared-filesystem WAL/SHM writes that can fail
    # with "disk I/O error" even when the copied database itself is valid.
    conn = sqlite3.connect(f'file:{db_path}?mode=ro&immutable=1', uri=True)
    try:
        table_names = [
            str(row[0])
            for row in conn.execute("select name from sqlite_master where type='table' order by name")
        ]
        for table in table_names:
            columns = [str(row[1]) for row in conn.execute(f'pragma table_info({sqlite_identifier(table)})')]
            count = int(conn.execute(f'select count(*) from {sqlite_identifier(table)}').fetchone()[0])
            entry: Dict[str, Any] = {
                'row_count': count,
                'columns': columns,
                'exported': table in OPENCODE_TRACE_TABLES,
            }
            if table in OPENCODE_TRACE_TABLES:
                entry['rows'] = sqlite_rows_as_dicts(conn, table, columns, limit=max_rows)
                if count > max_rows:
                    entry['truncated_after_rows'] = max_rows
            report['tables'][table] = entry
    finally:
        conn.close()
    write_json(output_path, redact_trace_value(report))
    return report


def export_opencode_session_store(snapshot_root: Path) -> Dict[str, Any]:
    export_root = snapshot_root / 'opencode_session_export'
    max_rows = max(100, int(os.getenv('PATCHEVAL_OPENCODE_DB_EXPORT_MAX_ROWS', '5000')))
    reports: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    seen: set[str] = set()
    for db_path in sorted(snapshot_root.rglob('*.db')):
        if db_path.name.endswith(('-wal', '-shm')):
            continue
        resolved = str(db_path.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        safe_name = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(db_path.relative_to(snapshot_root)))
        output_path = export_root / f'{safe_name}.json'
        try:
            report = export_opencode_sqlite_db(db_path, output_path, max_rows=max_rows)
            reports.append({'db_path': str(db_path), 'export_path': str(output_path), 'tables': list(report.get('tables', {}).keys())})
        except Exception as exc:
            errors.append({'db_path': str(db_path), 'error': str(exc)})
    manifest = {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'snapshot_root': str(snapshot_root),
        'exports': reports,
        'errors': errors,
        'note': 'Only trace-relevant OpenCode tables are exported; credential/account tables are summarized by schema/count only.',
    }
    if reports or errors:
        write_json(export_root / 'manifest.json', manifest)
    return manifest


def copy_container_path_to_host(container_id: str, source_path: str, dest_parent: Path) -> Dict[str, Any]:
    safe = re.sub(r'[^A-Za-z0-9_.-]+', '_', source_path.strip('/')) or 'root'
    dest_dir = dest_parent / 'salvaged' / safe
    result: Dict[str, Any] = {
        'source_path': source_path,
        'dest_dir': str(dest_dir),
        'copied': False,
        'error': '',
    }
    if is_sandbox_container(container_id):
        parent = shlex.quote(str(PurePosixPath(source_path).parent))
        base = shlex.quote(PurePosixPath(source_path).name)
        inner = f"set -euo pipefail; test -e {shlex.quote(source_path)}; tar -C {parent} -czf - {base} | base64 | tr -d '\n'"
        cmd = 'bash -lc ' + shlex.quote(inner)
        try:
            rc, stdout, stderr = sandbox_api_client.exec_shell(container_id, cmd, timeout=180)
            if rc != 0 or not stdout:
                result['error'] = tail_chars((stdout + stderr).strip(), 2000)
                return result
            dest_dir.mkdir(parents=True, exist_ok=True)
            archive_path = dest_dir / (PurePosixPath(source_path).name + '.tar.gz')
            archive_path.write_bytes(base64.b64decode(stdout.encode('ascii')))
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(dest_dir)
            result['copied'] = True
            return result
        except Exception as exc:
            result['error'] = str(exc)
            return result
    try:
        dest_dir.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(['docker', 'cp', f'{container_id}:{source_path}', str(dest_dir)], capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            result['error'] = tail_chars((proc.stdout + proc.stderr).strip(), 2000)
            return result
        result['copied'] = True
        return result
    except Exception as exc:
        result['error'] = str(exc)
        return result


def copy_opencode_session_db_files_to_host(container_id: str, source_paths: List[str], dest_parent: Path) -> Dict[str, Any]:
    dest_dir = dest_parent / 'salvaged_db_files'
    result: Dict[str, Any] = {
        'source_paths': source_paths,
        'dest_dir': str(dest_dir),
        'copied': False,
        'method': 'sqlite3_backup',
        'error': '',
    }
    quoted_paths = ' '.join(shlex.quote(path) for path in source_paths)
    inner = f"""
set -euo pipefail
if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "sqlite3 command not available for consistent OpenCode DB backup" >&2
    exit 3
fi
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
db_list="$tmpdir/dbs.txt"
backup_root="$tmpdir/export"
mkdir -p "$backup_root"
for root in {quoted_paths}; do
    if [ -e "$root" ]; then
        find "$root" -type f -name '*.db' -print >> "$db_list"
    fi
done
if [ ! -s "$db_list" ]; then
    exit 2
fi
sort -u "$db_list" | while IFS= read -r db; do
    rel="${{db#/}}"
    dest="$backup_root/$rel"
    mkdir -p "$(dirname "$dest")"
    sqlite3 "$db" ".backup '$dest'"
done
tar -C "$backup_root" -czf - . | base64 | tr -d '\\n'
"""
    try:
        if is_sandbox_container(container_id):
            rc, stdout, stderr = sandbox_api_client.exec_shell(container_id, 'bash -lc ' + shlex.quote(inner), timeout=120)
        else:
            proc = docker_exec(container_id, ['bash', '-lc', inner], timeout=120)
            rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        if rc == 2:
            result['error'] = 'no OpenCode DB files found'
            return result
        if rc == 3:
            result['error'] = tail_chars((stdout + stderr).strip(), 2000) or 'sqlite3 command not available'
            return result
        if rc != 0 or not stdout:
            result['error'] = tail_chars((stdout + stderr).strip(), 2000)
            return result
        dest_dir.mkdir(parents=True, exist_ok=True)
        archive_path = dest_dir / 'opencode_session_dbs.tar.gz'
        archive_path.write_bytes(base64.b64decode(stdout.encode('ascii')))
        with tarfile.open(archive_path, 'r:gz') as tar:
            tar.extractall(dest_dir)
        result['copied'] = True
        return result
    except Exception as exc:
        result['error'] = str(exc)
        return result


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        parsed = parse_json_lenient(value)
        if parsed:
            return parsed
    return value


def _walk_values(value: Any) -> List[Any]:
    values = [value]
    if isinstance(value, dict):
        for nested in value.values():
            values.extend(_walk_values(nested))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_walk_values(nested))
    return values


def _walk_key_values(value: Any, wanted_keys: set[str]) -> List[Any]:
    found: List[Any] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key) in wanted_keys:
                found.append(nested)
            found.extend(_walk_key_values(nested, wanted_keys))
    elif isinstance(value, list):
        for nested in value:
            found.extend(_walk_key_values(nested, wanted_keys))
    return found


def _coerce_id_values(values: List[Any], prefixes: Tuple[str, ...]) -> List[str]:
    out: List[str] = []
    for value in values:
        for candidate in _walk_values(_json_value(value)):
            if not isinstance(candidate, str):
                continue
            if prefixes and not candidate.startswith(prefixes):
                continue
            if candidate not in out:
                out.append(candidate)
    return out


def row_session_ids(row: Dict[str, Any]) -> List[str]:
    keys = {'sessionID', 'sessionId', 'session_id', 'session', 'parentSessionID', 'parentSessionId', 'parent_session_id', 'id'}
    return _coerce_id_values(_walk_key_values(row, keys), ('ses_',))


def row_message_ids(row: Dict[str, Any]) -> List[str]:
    keys = {'messageID', 'messageId', 'message_id', 'message', 'id'}
    return _coerce_id_values(_walk_key_values(row, keys), ('msg_',))


def row_timestamp_value(row: Dict[str, Any]) -> float:
    for key in ['time_created', 'timeCreated', 'created_at', 'createdAt', 'timestamp', 'time', 'updated_at', 'updatedAt']:
        value = row.get(key)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                pass
    data = _json_value(row.get('data'))
    if isinstance(data, dict):
        for key in ['time_created', 'timeCreated', 'created_at', 'createdAt', 'timestamp', 'time']:
            value = data.get(key)
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value)
                except ValueError:
                    pass
    return 0.0


def load_opencode_export_rows(export_root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for report_path in sorted(export_root.glob('*.json')):
        if report_path.name == 'manifest.json':
            continue
        try:
            report = json.loads(report_path.read_text(encoding='utf-8'))
        except Exception:
            continue
        tables = report.get('tables') if isinstance(report.get('tables'), dict) else {}
        for table_name, table_info in tables.items():
            if not isinstance(table_info, dict):
                continue
            for idx, row in enumerate(table_info.get('rows') or []):
                if isinstance(row, dict):
                    rows.append({
                        'export_path': str(report_path),
                        'source_db_path': report.get('db_path', ''),
                        'table': table_name,
                        'row_index': idx,
                        'row': row,
                    })
    return rows


def subagent_session_ids_from_index(subagent_trace_index_path: Optional[Path]) -> List[str]:
    if not subagent_trace_index_path or not subagent_trace_index_path.exists():
        return []
    try:
        index = json.loads(subagent_trace_index_path.read_text(encoding='utf-8'))
    except Exception:
        return []
    session_ids: List[str] = []
    for call in index.get('task_calls') or []:
        if not isinstance(call, dict):
            continue
        session_id = str(call.get('child_session_id') or '')
        if session_id.startswith('ses_') and session_id not in session_ids:
            session_ids.append(session_id)
    return session_ids


def child_session_ids_from_rows(all_rows: List[Dict[str, Any]]) -> List[str]:
    session_ids: List[str] = []
    for wrapped in all_rows:
        if str(wrapped.get('table') or '') != 'session':
            continue
        row = wrapped.get('row') if isinstance(wrapped.get('row'), dict) else {}
        session_id = str(row.get('id') or '')
        parent_id = str(row.get('parent_id') or row.get('parentSessionId') or row.get('parentSessionID') or '')
        if session_id.startswith('ses_') and parent_id.startswith('ses_') and session_id not in session_ids:
            session_ids.append(session_id)
    return session_ids


def materialize_opencode_session_logs(
    *,
    trace_root: Path,
    output_dir: Path,
    cve_id: str,
    stage_name: str,
    stage_log_path: Path,
    subagent_trace_index_path: Optional[Path],
) -> Dict[str, Any]:
    export_root = trace_root / 'opencode_session_export'
    all_rows = load_opencode_export_rows(export_root)
    session_message_ids: Dict[str, set[str]] = {}
    row_session_cache: List[Tuple[Dict[str, Any], List[str], List[str]]] = []
    for wrapped in all_rows:
        row = wrapped.get('row') if isinstance(wrapped.get('row'), dict) else {}
        session_ids = row_session_ids(row)
        message_ids = row_message_ids(row)
        row_session_cache.append((wrapped, session_ids, message_ids))
        for session_id in session_ids:
            session_message_ids.setdefault(session_id, set()).update(message_ids)
    changed = True
    while changed:
        changed = False
        for _, session_ids, message_ids in row_session_cache:
            inferred_sessions = [
                session_id
                for session_id, known_messages in session_message_ids.items()
                if known_messages.intersection(message_ids)
            ]
            for session_id in inferred_sessions:
                before = len(session_message_ids.setdefault(session_id, set()))
                session_message_ids[session_id].update(message_ids)
                if len(session_message_ids[session_id]) != before:
                    changed = True

    indexed_subagents = subagent_session_ids_from_index(subagent_trace_index_path)
    discovered_child_sessions = child_session_ids_from_rows(all_rows)
    discovered_sessions = sorted(session_message_ids)
    target_sessions = indexed_subagents or discovered_child_sessions or discovered_sessions
    output_dir.mkdir(parents=True, exist_ok=True)
    logs: List[Dict[str, Any]] = []
    for session_id in target_sessions:
        known_messages = session_message_ids.get(session_id, set())
        included: List[Dict[str, Any]] = []
        for wrapped, session_ids, message_ids in row_session_cache:
            row_text = json.dumps(wrapped.get('row', {}), ensure_ascii=False, sort_keys=True)
            if (
                session_id in session_ids
                or bool(known_messages.intersection(message_ids))
                or session_id in row_text
            ):
                included.append(wrapped)
        included.sort(key=lambda item: (row_timestamp_value(item.get('row', {})), str(item.get('table')), int(item.get('row_index') or 0)))
        log_path = output_dir / f'{session_id}.raw_rows.jsonl'
        with log_path.open('w', encoding='utf-8') as handle:
            for item in included:
                handle.write(json.dumps(redact_trace_value(item), ensure_ascii=False) + '\n')
        logs.append({
            'session_id': session_id,
            'is_indexed_subagent': session_id in indexed_subagents,
            'row_count': len(included),
            'message_id_count': len(known_messages),
            'path': str(log_path),
        })
    manifest = {
        'schema_version': '1.0',
        'cve_id': cve_id,
        'stage_name': stage_name,
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'trace_root': str(trace_root),
        'export_root': str(export_root),
        'stage_log_path': str(stage_log_path),
        'subagent_trace_index_path': str(subagent_trace_index_path or ''),
        'indexed_subagent_session_ids': indexed_subagents,
        'discovered_child_session_ids': discovered_child_sessions,
        'discovered_session_count': len(discovered_sessions),
        'materialized_session_count': len(logs),
        'logs': logs,
        'note': 'Each raw_rows JSONL entry is a trace-relevant OpenCode SQLite row, joined by session/message ids when possible.',
    }
    write_json(output_dir / 'manifest.json', manifest)
    return manifest


def stable_trace_source_path(path_value: Any, trace_root: Path) -> str:
    path_text = str(path_value or '')
    if not path_text:
        return ''
    try:
        return str(Path(path_text).resolve().relative_to(trace_root.resolve()))
    except Exception:
        return path_text


def normalized_opencode_stream_event(
    *,
    wrapped: Dict[str, Any],
    session_id: str,
    indexed_subagents: List[str],
    trace_root: Path,
    cve_id: str,
    stage_name: str,
    captured_at: str,
) -> Optional[Dict[str, Any]]:
    table = str(wrapped.get('table') or '')
    if table not in OPENCODE_STREAM_TABLES:
        return None
    row = wrapped.get('row') if isinstance(wrapped.get('row'), dict) else {}
    data = _json_value(row.get('data'))
    timestamp = row_timestamp_value(row)
    source = {
        'table': table,
        'row_index': wrapped.get('row_index'),
        'source_db_path': stable_trace_source_path(wrapped.get('source_db_path'), trace_root),
    }
    row_id = str(row.get('id') or '')
    if row_id:
        source['row_id'] = row_id
    base: Dict[str, Any] = {
        'schema_version': '1.0',
        'captured_at': captured_at,
        'cve_id': cve_id,
        'stage_name': stage_name,
        'sessionID': session_id,
        'session_id': session_id,
        'is_indexed_subagent': session_id in indexed_subagents,
        'timestamp': timestamp or None,
        'source': source,
    }
    if table == 'part':
        part = data if isinstance(data, dict) else {k: v for k, v in row.items() if k not in {'data'}}
        if 'id' not in part and row_id:
            part['id'] = row_id
        if 'sessionID' not in part:
            part['sessionID'] = session_id
        if 'messageID' not in part and row.get('messageID'):
            part['messageID'] = row.get('messageID')
        event_type = 'part'
        if part.get('type') == 'tool' or part.get('tool') or isinstance(part.get('state'), dict):
            event_type = 'tool_use'
        elif part.get('type') in {'text', 'reasoning'}:
            event_type = str(part.get('type'))
        base.update({'type': event_type, 'part': compact_stream_value(part)})
        return base
    if table == 'message':
        message = data if isinstance(data, dict) else {k: v for k, v in row.items() if k not in {'data'}}
        if 'id' not in message and row_id:
            message['id'] = row_id
        base.update({'type': 'message', 'message': compact_stream_value(message)})
        return base
    if table == 'event':
        event_data = data if isinstance(data, dict) else {k: v for k, v in row.items() if k not in {'data'}}
        event_type = str(event_data.get('type') or row.get('type') or 'event')
        base.update({'type': event_type, 'event': compact_stream_value(event_data)})
        return base
    if table == 'todo':
        todo = data if isinstance(data, dict) else {k: v for k, v in row.items() if k not in {'data'}}
        base.update({'type': 'todo', 'todo': compact_stream_value(todo)})
        return base
    if table == 'session_input':
        session_input = data if isinstance(data, dict) else {k: v for k, v in row.items() if k not in {'data'}}
        base.update({'type': 'session_input', 'input': compact_stream_value(session_input)})
        return base
    if table == 'session':
        session = data if isinstance(data, dict) else {k: v for k, v in row.items() if k not in {'data'}}
        base.update({'type': 'session', 'session': compact_stream_value(session)})
        return base
    return None


def append_incremental_opencode_session_events(
    *,
    trace_root: Path,
    stream_dir: Path,
    cve_id: str,
    stage_name: str,
    stage_log_path: Path,
    subagent_trace_index_path: Optional[Path],
    seen_event_keys: set[str],
) -> Dict[str, Any]:
    export_root = trace_root / 'opencode_session_export'
    all_rows = load_opencode_export_rows(export_root)
    session_message_ids: Dict[str, set[str]] = {}
    row_session_cache: List[Tuple[Dict[str, Any], List[str], List[str]]] = []
    for wrapped in all_rows:
        row = wrapped.get('row') if isinstance(wrapped.get('row'), dict) else {}
        session_ids = row_session_ids(row)
        message_ids = row_message_ids(row)
        row_session_cache.append((wrapped, session_ids, message_ids))
        for session_id in session_ids:
            session_message_ids.setdefault(session_id, set()).update(message_ids)
    changed = True
    while changed:
        changed = False
        for _, session_ids, message_ids in row_session_cache:
            inferred_sessions = [
                session_id
                for session_id, known_messages in session_message_ids.items()
                if known_messages.intersection(message_ids)
            ]
            for session_id in inferred_sessions:
                before = len(session_message_ids.setdefault(session_id, set()))
                session_message_ids[session_id].update(message_ids)
                if len(session_message_ids[session_id]) != before:
                    changed = True

    indexed_subagents = subagent_session_ids_from_index(subagent_trace_index_path)
    discovered_child_sessions = child_session_ids_from_rows(all_rows)
    target_sessions = indexed_subagents or discovered_child_sessions
    stream_dir.mkdir(parents=True, exist_ok=True)
    appended_by_session: Dict[str, int] = {}
    captured_at = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    for session_id in target_sessions:
        known_messages = session_message_ids.get(session_id, set())
        session_path = stream_dir / f'{session_id}.events.jsonl'
        for wrapped, session_ids, message_ids in row_session_cache:
            table = str(wrapped.get('table') or '')
            if table not in OPENCODE_STREAM_TABLES:
                continue
            row_text = json.dumps(wrapped.get('row', {}), ensure_ascii=False, sort_keys=True)
            if not (
                session_id in session_ids
                or bool(known_messages.intersection(message_ids))
                or session_id in row_text
            ):
                continue
            event_key_material = json.dumps(
                {
                    'session_id': session_id,
                    'table': wrapped.get('table', ''),
                    'row': wrapped.get('row', {}),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            event_key = hashlib.sha256(event_key_material.encode('utf-8')).hexdigest()
            if event_key in seen_event_keys:
                continue
            seen_event_keys.add(event_key)
            event = normalized_opencode_stream_event(
                wrapped=wrapped,
                session_id=session_id,
                indexed_subagents=indexed_subagents,
                trace_root=trace_root,
                cve_id=cve_id,
                stage_name=stage_name,
                captured_at=captured_at,
            )
            if event is None:
                continue
            event['event_key'] = event_key
            with session_path.open('a', encoding='utf-8') as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + '\n')
            with (stream_dir / 'all_events.jsonl').open('a', encoding='utf-8') as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + '\n')
            appended_by_session[session_id] = appended_by_session.get(session_id, 0) + 1

    manifest = {
        'schema_version': '1.0',
        'cve_id': cve_id,
        'stage_name': stage_name,
        'updated_at': captured_at,
        'stream_dir': str(stream_dir),
        'stage_log_path': str(stage_log_path),
        'subagent_trace_index_path': str(subagent_trace_index_path or ''),
        'indexed_subagent_session_ids': indexed_subagents,
        'discovered_child_session_ids': discovered_child_sessions,
        'target_session_ids': target_sessions,
        'known_event_key_count': len(seen_event_keys),
        'appended_event_count': sum(appended_by_session.values()),
        'appended_by_session': appended_by_session,
        'all_events_path': str(stream_dir / 'all_events.jsonl'),
        'session_event_paths': {session_id: str(stream_dir / f'{session_id}.events.jsonl') for session_id in target_sessions},
        'note': 'This file is updated while the stage is running. Each JSONL line is one compact, readable OpenCode event; raw SQLite rows are kept only in completion/timeout snapshots.',
    }
    write_json(stream_dir / 'stream_manifest.json', manifest)
    write_json(stream_dir.parent / 'latest_manifest.json', manifest)
    return manifest


def capture_opencode_session_trace(
    *,
    container_id: str,
    cve_id: str,
    stage_name: str,
    outputs_root: Path,
    work_dir: str,
    stage_log_path: Path,
    subagent_trace_index_path: Optional[Path],
    reason: str,
    stream_seen_event_keys: Optional[set[str]] = None,
    persist_snapshot: bool = True,
) -> Dict[str, Any]:
    stamp = time.strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8]
    if persist_snapshot:
        trace_root = outputs_root / 'opencode_session_traces' / cve_id / stage_name / stamp
    else:
        trace_root = outputs_root / 'opencode_session_traces' / '.stream_tmp' / cve_id / stage_name / stamp
    trace_root.mkdir(parents=True, exist_ok=True)
    subagent_output_dir = outputs_root / 'subagent_logs' / cve_id / stage_name / stamp
    try:
        store_paths = opencode_session_store_paths(work_dir)
        if persist_snapshot:
            copied = [copy_container_path_to_host(container_id, path, trace_root) for path in store_paths]
            copied.append(copy_opencode_session_db_files_to_host(container_id, store_paths, trace_root))
        else:
            copied = [copy_opencode_session_db_files_to_host(container_id, store_paths, trace_root)]
        export_report = export_opencode_session_store(trace_root)
        materialized: Dict[str, Any] = {}
        if persist_snapshot:
            materialized = materialize_opencode_session_logs(
                trace_root=trace_root,
                output_dir=subagent_output_dir,
                cve_id=cve_id,
                stage_name=stage_name,
                stage_log_path=stage_log_path,
                subagent_trace_index_path=subagent_trace_index_path,
            )
        stream_manifest: Dict[str, Any] = {}
        if stream_seen_event_keys is not None:
            stream_manifest = append_incremental_opencode_session_events(
                trace_root=trace_root,
                stream_dir=outputs_root / 'subagent_logs' / cve_id / stage_name / 'stream',
                cve_id=cve_id,
                stage_name=stage_name,
                stage_log_path=stage_log_path,
                subagent_trace_index_path=subagent_trace_index_path,
                seen_event_keys=stream_seen_event_keys,
            )
        manifest = {
            'schema_version': '1.0',
            'cve_id': cve_id,
            'stage_name': stage_name,
            'reason': reason,
            'created_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            'persist_snapshot': persist_snapshot,
            'trace_root': str(trace_root) if persist_snapshot else '',
            'subagent_log_manifest_path': str(subagent_output_dir / 'manifest.json') if persist_snapshot else '',
            'copied_paths': copied,
            'opencode_export_manifest': str(trace_root / 'opencode_session_export' / 'manifest.json') if persist_snapshot else '',
            'opencode_export_report': export_report if persist_snapshot else {
                'exports': len(export_report.get('exports') or []),
                'errors': export_report.get('errors') or [],
            },
            'materialized_session_log_summary': {
                'discovered_session_count': materialized.get('discovered_session_count'),
                'materialized_session_count': materialized.get('materialized_session_count'),
                'indexed_subagent_session_ids': materialized.get('indexed_subagent_session_ids'),
            },
            'stream_manifest_path': str(outputs_root / 'subagent_logs' / cve_id / stage_name / 'stream' / 'stream_manifest.json') if stream_manifest else '',
            'stream_appended_event_count': stream_manifest.get('appended_event_count', 0) if stream_manifest else 0,
        }
        if persist_snapshot:
            write_json(trace_root / 'trace_manifest.json', manifest)
            write_json(outputs_root / 'subagent_logs' / cve_id / stage_name / 'latest_snapshot_manifest.json', manifest)
        return manifest
    finally:
        if not persist_snapshot:
            shutil.rmtree(trace_root, ignore_errors=True)


def extract_vulnerability_locations(problem_statement: str) -> List[str]:
    locations: List[str] = []
    for match in re.finditer(r'"file_path"\s*:\s*"([^"]+)"', problem_statement or ''):
        value = match.group(1).strip()
        if value and value not in locations:
            locations.append(value)
    return locations




def unique_keep_order(items: List[str], limit: int = 50) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        value = str(item).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
            if len(out) >= limit:
                break
    return out


def extract_path_mentions(problem_statement: str) -> List[str]:
    pattern = r'(?<![A-Za-z0-9_./-])([A-Za-z0-9_./-]+\.(?:py|js|jsx|ts|tsx|go|java|rb|php|c|cc|cpp|h|hpp|rs|cs|mjs|cjs))(?![A-Za-z0-9_./-])'
    return unique_keep_order([m.group(1).strip().lstrip('./') for m in re.finditer(pattern, problem_statement or '')], 40)


def container_shell_text(container_id: str, command: str, *, timeout: int = 45, limit: int = 20000) -> str:
    try:
        result = docker_exec(container_id, ['bash', '-lc', command], timeout=timeout)
        return tail_chars((result.stdout + result.stderr).strip(), limit)
    except Exception as exc:
        return f'[static-trace-command-error] {exc}'


def extract_problem_terms(problem_statement: str, limit: int = 30) -> List[str]:
    terms: List[str] = []
    for quoted in re.findall(r'`([^`]{2,80})`', problem_statement or ''):
        terms.append(quoted.strip())
    for quoted in re.findall(r'"([A-Za-z_][A-Za-z0-9_./:-]{2,80})"', problem_statement or ''):
        terms.append(quoted.strip())
    stop = {'the','and','for','with','that','this','from','into','when','then','than','cve','vulnerability','vulnerable','patch','fixed','before','after','github','true','false','null','none','path','file','line','code','test','error'}
    for word in re.findall(r'\b[A-Za-z_][A-Za-z0-9_./:-]{3,80}\b', problem_statement or ''):
        low = word.lower().strip('_-')
        if low in stop or low.startswith('cve-'):
            continue
        if any(ch in word for ch in './:_-') or re.search(r'[A-Z][a-z]+[A-Z]|[a-z]+[A-Z]', word):
            terms.append(word.strip())
    return unique_keep_order(terms, limit)


def infer_language_from_files(record: Any, files: List[str]) -> str:
    explicit = str(getattr(record, 'language', '') or getattr(record, 'repo_language', '') or '').strip()
    if explicit:
        return explicit
    ext_counts: Dict[str, int] = {}
    for path in files:
        suffix = Path(path).suffix.lower()
        ext_counts[suffix] = ext_counts.get(suffix, 0) + 1
    if not ext_counts:
        return 'unknown'
    suffix = max(ext_counts.items(), key=lambda item: item[1])[0]
    return {'.py':'Python','.js':'JavaScript','.jsx':'JavaScript','.mjs':'JavaScript','.cjs':'JavaScript','.ts':'TypeScript','.tsx':'TypeScript','.go':'Go','.java':'Java','.rb':'Ruby','.php':'PHP','.c':'C/C++','.cc':'C/C++','.cpp':'C/C++','.h':'C/C++','.hpp':'C/C++','.rs':'Rust'}.get(suffix, suffix.lstrip('.').upper())


def infer_sink_hints(problem_statement: str, language: str) -> List[str]:
    text = (problem_statement or '').lower()
    rules = [
        (['path traversal','directory traversal','../','arbitrary file','zip slip','tar slip'], 'filesystem path resolution / file read-write sink'),
        (['command injection','shell injection','os command','exec(','spawn'], 'command execution sink'),
        (['sql injection','sqli','query'], 'database query construction sink'),
        (['ssrf','server-side request forgery','url fetch','redirect'], 'server-side URL fetch / HTTP client sink'),
        (['xss','cross-site scripting','html','sanitize','escape'], 'HTML/template rendering sink'),
        (['deserialization','deserialize','pickle','yaml.load','unmarshal'], 'unsafe deserialization sink'),
        (['authorization','authentication','access control','permission','bypass'], 'authorization or authentication boundary'),
        (['prototype pollution','__proto__','constructor.prototype'], 'object property merge / prototype mutation sink'),
        (['redos','regular expression denial','catastrophic backtracking'], 'regular expression evaluation sink'),
        (['xxe','external entity','xml entity'], 'XML parser external entity sink'),
    ]
    sinks = [sink for keys, sink in rules if any(key in text for key in keys)]
    return unique_keep_order(sinks or [f'{language} security-sensitive sink inferred from CVE description'], 8)


def default_env_requirements(language: str, manifests: List[str], tool_probe: Dict[str, str]) -> List[str]:
    reqs = ['repository checkout exists at work_dir', 'benchmark oracle files remain hidden from agents']
    lang = language.lower()
    if 'python' in lang or any(item.endswith(('pyproject.toml','requirements.txt','setup.py')) for item in manifests):
        reqs.extend(['python/python3 interpreter available', 'package import path or venv usable without network install'])
    if 'javascript' in lang or 'typescript' in lang or any(item.endswith('package.json') for item in manifests):
        reqs.extend(['node runtime available', 'npm/yarn/pnpm dependencies already present or local package import usable'])
    if lang == 'go' or any(item.endswith('go.mod') for item in manifests):
        reqs.extend(['go toolchain available', 'module cache or vendored dependencies available'])
    if 'java' in lang or any(item.endswith(('pom.xml','build.gradle','build.gradle.kts')) for item in manifests):
        reqs.extend(['java build toolchain available', 'maven/gradle dependencies already cached if needed'])
    for tool, path in sorted(tool_probe.items()):
        reqs.append(f'{tool}={path}')
    return unique_keep_order(reqs, 20)


def static_trace_summary_markdown(trace: Dict[str, Any]) -> str:
    lines = [
        f"# Static Trace Prepass for {trace.get('cve_id', 'unknown')}", '',
        f"- Language: {trace.get('language', 'unknown')}",
        f"- Confidence: {trace.get('confidence', 0)}",
        f"- Source: {trace.get('source', 'unknown')}",
        f"- Sink: {trace.get('sink', 'unknown')}",
        f"- Key files: {json.dumps(trace.get('key_files', []), ensure_ascii=False)}",
        f"- Key functions: {json.dumps(trace.get('key_functions', [])[:10], ensure_ascii=False)}",
        f"- Environment requirements: {json.dumps(trace.get('environment_requirements', []), ensure_ascii=False)}",
        '', '## Candidate Call Chains',
    ]
    chains = trace.get('candidate_call_chains') or []
    if not chains:
        lines.append('- none')
    for chain in chains:
        lines.extend([
            f"- {chain.get('chain_id')}: confidence={chain.get('confidence')}",
            f"  - entry_api: {chain.get('entry_api')}",
            f"  - source: {chain.get('source')}",
            f"  - sink: {chain.get('sink')}",
            f"  - files: {json.dumps(chain.get('files', []), ensure_ascii=False)}",
            f"  - functions: {json.dumps(chain.get('functions', []), ensure_ascii=False)}",
            f"  - evidence: {json.dumps(chain.get('evidence', []), ensure_ascii=False)}",
        ])
    lines.extend(['', '## Repair Targets', json.dumps(trace.get('repair_targets', {}), ensure_ascii=False, indent=2), '', '## Official Eval Hypothesis', str(trace.get('official_eval_hypothesis', 'unknown')), '', '## Constraints'])
    lines.extend(f'- {item}' for item in trace.get('constraints', []))
    return '\n'.join(lines).strip() + '\n'


def static_trace_to_knowledge_findings(trace: Dict[str, Any]) -> str:
    findings = {
        'cve_id': trace.get('cve_id'),
        'candidate_files': trace.get('key_files', []),
        'candidate_functions': [item.get('symbol') for item in trace.get('key_functions', []) if isinstance(item, dict) and item.get('symbol')],
        'security_boundary': f"{trace.get('source', 'unknown')} -> {trace.get('sink', 'unknown')}",
        'suspected_root_cause': trace.get('vulnerability_hypothesis') or 'Static trace prepass identified likely source-to-sink chain; validate against testcase knowledge before patching.',
        'reproduction_hypotheses': [chain.get('summary') for chain in trace.get('candidate_call_chains', []) if chain.get('summary')],
        'test_commands': [],
        'repair_constraints': trace.get('constraints', []),
    }
    return json.dumps(findings, ensure_ascii=False, indent=2) + '\n'


def run_static_trace_prepass(container_id: str, record: Any, artifact_dir: str, host_artifact_dir: Path) -> Tuple[Dict[str, Any], str, str]:
    problem = record.problem_statement or ''
    candidate_files = unique_keep_order(extract_vulnerability_locations(problem) + extract_path_mentions(problem), 40)
    work_q = shlex.quote(record.work_dir)
    manifests_text = container_shell_text(container_id, f"cd {work_q} && find . -maxdepth 4 -type f \\( -name package.json -o -name go.mod -o -name pyproject.toml -o -name requirements.txt -o -name setup.py -o -name pom.xml -o -name build.gradle -o -name build.gradle.kts -o -name Cargo.toml \\) | sed 's#^./##' | sort | head -50", timeout=30, limit=8000)
    manifests = [line.strip() for line in manifests_text.splitlines() if line.strip() and not line.startswith('[static-trace')]
    existing_files: List[str] = []
    if candidate_files:
        probe_parts = []
        for item in candidate_files[:40]:
            q = shlex.quote(item)
            probe_parts.append(f"if [ -f {q} ]; then printf '%s\\n' {q}; elif [ -f ./{q} ]; then printf '%s\\n' {q}; fi")
        existing_text = container_shell_text(container_id, f"cd {work_q} && {' ; '.join(probe_parts)}", timeout=30, limit=12000)
        existing_files.extend(line.strip().lstrip('./') for line in existing_text.splitlines() if line.strip() and not line.startswith('['))
    if not existing_files:
        grep_hits: List[str] = []
        for term in extract_problem_terms(problem, 8)[:5]:
            if len(term) < 4 or '/' in term:
                continue
            cmd = f"cd {work_q} && grep -RIl --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.venv -- {shlex.quote(term)} . 2>/dev/null | sed 's#^./##' | head -20"
            grep_hits.extend(line.strip() for line in container_shell_text(container_id, cmd, timeout=20, limit=4000).splitlines() if line.strip() and not line.startswith('['))
        existing_files.extend(grep_hits)
    if not existing_files:
        fallback_text = container_shell_text(container_id, f"cd {work_q} && find . -maxdepth 4 -type f \\( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.go' -o -name '*.java' -o -name '*.rb' -o -name '*.php' -o -name '*.rs' \\) | sed 's#^./##' | sort | head -40", timeout=30, limit=8000)
        existing_files.extend(line.strip() for line in fallback_text.splitlines() if line.strip() and not line.startswith('['))
    key_files = unique_keep_order(existing_files, 12)
    language = infer_language_from_files(record, key_files or candidate_files)
    lang_lower = language.lower()
    symbol_pattern = r'^[[:space:]]*(def|class)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*'
    if lang_lower == 'go':
        symbol_pattern = r'^[[:space:]]*func[[:space:]]+(\([^)]+\)[[:space:]]*)?[A-Za-z_][A-Za-z0-9_]*'
    elif 'javascript' in lang_lower or 'typescript' in lang_lower:
        symbol_pattern = r'(function[[:space:]]+[A-Za-z_$]|(const|let|var)[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=|exports\.|module\.exports|router\.|app\.)'
    elif 'java' in lang_lower:
        symbol_pattern = r'^[[:space:]]*(public|private|protected|class|interface|enum)[[:space:]]+'
    key_functions: List[Dict[str, Any]] = []
    for path in key_files[:8]:
        cmd = f"cd {work_q} && grep -nE {shlex.quote(symbol_pattern)} -- {shlex.quote(path)} 2>/dev/null | head -40"
        for line in container_shell_text(container_id, cmd, timeout=20, limit=12000).splitlines():
            if not line.strip() or ':' not in line or line.startswith('['):
                continue
            number, rest = line.split(':', 1)
            try:
                line_no = int(number)
            except ValueError:
                line_no = None
            key_functions.append({'file': path, 'line': line_no, 'symbol': rest.strip()[:180]})
            if len(key_functions) >= 30:
                break
        if len(key_functions) >= 30:
            break
    tool_probe_text = container_shell_text(container_id, "for t in python3 python node npm yarn pnpm go javac java mvn gradle ruby php cargo; do if command -v $t >/dev/null 2>&1; then printf '%s=%s\\n' $t $(command -v $t); fi; done", timeout=20, limit=8000)
    tool_probe = dict(line.split('=', 1) for line in tool_probe_text.splitlines() if '=' in line)
    sources = unique_keep_order([term for term in extract_problem_terms(problem, 20) if term not in key_files], 10) or ['external or user-controlled input described by CVE']
    sinks = infer_sink_hints(problem, language)
    env_reqs = default_env_requirements(language, manifests, tool_probe)
    confidence = round(min(0.45 + (0.12 if candidate_files else 0) + (0.12 if key_files else 0) + (0.08 if key_functions else 0) + (0.05 if sinks else 0), 0.82), 2)
    grouped_symbols: Dict[str, List[str]] = {}
    for item in key_functions:
        grouped_symbols.setdefault(str(item.get('file')), []).append(str(item.get('symbol')))
    chains: List[Dict[str, Any]] = []
    for idx, path in enumerate((key_files or ['unknown'])[:3], start=1):
        funcs = grouped_symbols.get(path, [])[:6]
        entry = funcs[0] if funcs else (Path(path).stem if path != 'unknown' else sources[0])
        chains.append({'chain_id': f'chain_{idx}', 'confidence': round(max(0.2, confidence - (idx - 1) * 0.08), 2), 'entry_api': entry, 'source': sources[0], 'sink': sinks[0], 'files': [] if path == 'unknown' else [path], 'functions': funcs, 'environment_requirements': env_reqs, 'evidence': unique_keep_order(['problem-statement file_path/path mention' if candidate_files else 'source tree fallback selection', f'language={language}', f'manifests={", ".join(manifests[:5])}' if manifests else 'no package manifest found in shallow scan'], 8), 'summary': f"{sources[0]} reaches {sinks[0]} through {path}"})
    trace: Dict[str, Any] = {'schema_version': 'static_trace_prepass.v1', 'cve_id': record.cve_id, 'problem_id': record.problem_id, 'work_dir': record.work_dir, 'language': language, 'generation_method': 'lightweight static prepass: problem-statement parsing, shallow source/manifests scan, grep-based symbol extraction, tool availability probe', 'source': sources[0], 'sink': sinks[0], 'sources': sources, 'sinks': sinks, 'entrypoints': key_functions[:10], 'candidate_call_chains': chains, 'key_files': key_files, 'key_functions': key_functions, 'environment_requirements': env_reqs, 'repair_targets': {'files': key_files[:6], 'functions': key_functions[:12]}, 'constraints': ['Do not read or rely on benchmark oracle files.', 'Do not modify tests, PoC scripts, package lockfiles, generated artifacts, or benchmark harness files in the final patch unless unavoidable.', 'Do not mutate production source only to make a PoC reproduce; reproduction must exercise the actual checked-out code path.', 'Prefer a minimal source-code fix at the validated source-to-sink boundary.', 'Preserve existing public API behavior except for blocking the vulnerable input or state.'], 'official_eval_hypothesis': 'Official eval is likely to exercise one of the public entrypoints above and assert that the sink is protected without breaking compatibility.', 'vulnerability_hypothesis': f"Likely vulnerable boundary: {sources[0]} -> {sinks[0]}; prioritize files {key_files[:3] or candidate_files[:3]}.", 'confidence': confidence, 'raw_evidence': {'problem_candidate_files': candidate_files, 'manifests': manifests, 'tool_probe': tool_probe}}
    json_text = json.dumps(trace, ensure_ascii=False, indent=2) + '\n'
    report = static_trace_summary_markdown(trace)
    docker_write_text(container_id, json_text, f'{artifact_dir}/static_trace.json')
    docker_write_text(container_id, report, f'{artifact_dir}/static_trace_summary.md')
    host_artifact_dir.mkdir(parents=True, exist_ok=True)
    (host_artifact_dir / 'static_trace.json').write_text(json_text, encoding='utf-8')
    (host_artifact_dir / 'static_trace_summary.md').write_text(report, encoding='utf-8')
    return trace, json_text, report


D_ANALYSIS_WORKERS = {
    'source_reachability_worker': 'source_reachability_worker.system.md',
    'reproducer_worker': 'reproducer_worker.system.md',
    'boundary_control_worker': 'boundary_control_worker.system.md',
    'evidence_review_worker': 'evidence_review_worker.system.md',
}

D_REPAIR_MAS_AGENTS = {
    'patch_generator': 'patch_generator.system.md',
    'patch_reviewer': 'patch_review.system.md',
}


def strip_markdown_front_matter(text: str) -> Tuple[Dict[str, str], str]:
    if not text.startswith('---'):
        return {}, text
    parts = text.split('---', 2)
    if len(parts) < 3:
        return {}, text
    meta: Dict[str, str] = {}
    for raw in parts[1].splitlines():
        if ':' not in raw:
            continue
        key, value = raw.split(':', 1)
        meta[key.strip()] = value.strip()
    return meta, parts[2].lstrip()


def read_prompt_body(path: Path) -> str:
    return strip_markdown_front_matter(read_text(path))[1].strip() + '\n'


def d_prompt_front_matter(description: str, tools: str = '') -> str:
    lines = ['---']
    if tools.strip():
        lines.append(f'allowed-tools: {tools}')
    lines.append(f'description: {description}')
    lines.append('---')
    return '\n'.join(lines) + '\n\n'


def d_analysis_config_dir(artifact_dir: str) -> str:
    return f'{artifact_dir}/analysis_mas_config'


def write_d_analysis_mas_config_files(container_id: str, args: argparse.Namespace, artifact_dir: str) -> Dict[str, str]:
    config_dir = d_analysis_config_dir(artifact_dir)
    paths: Dict[str, str] = {'config_dir': config_dir}
    files: Dict[str, str] = {}
    for worker_name, filename in D_ANALYSIS_WORKERS.items():
        source = Path(args.analysis_workers_dir) / filename
        dest = f'{config_dir}/workers/{filename}'
        files[dest] = read_text(source)
        paths[f'{worker_name}_system_prompt'] = dest
    for path in sorted(Path(args.analysis_tasks_dir).glob('*.task.md')):
        if path.name.startswith('._'):
            continue
        dest = f'{config_dir}/tasks/{path.name}'
        files[dest] = read_text(path)
        paths[path.stem] = dest
    docker_write_text_files(container_id, files)
    return paths


def install_d_opencode_subagents(opencode: OpenCodeRunner, args: argparse.Namespace, record: Any) -> Dict[str, Any]:
    work_dir = record.work_dir
    config_path = f'{work_dir}/opencode.json'
    raw_config = docker_read_text(opencode.container_id, config_path, missing_ok=True, timeout=60)
    config = parse_json_lenient(raw_config) if raw_config.strip() else {}
    if not config:
        config = {'$schema': 'https://opencode.ai/config.json'}
    permission = config.setdefault('permission', {})
    for key in ['read', 'bash', 'grep', 'glob', 'list', 'edit', 'write', 'task', 'todowrite', 'external_directory']:
        permission[key] = 'allow'
    agents = config.setdefault('agent', {})
    installed: Dict[str, str] = {}
    global_agent_dir = '/path/to/local/resource
    project_agent_dir = f'{work_dir}/.opencode/agents'
    files: Dict[str, str] = {}
    for worker_name, filename in D_ANALYSIS_WORKERS.items():
        path = Path(args.analysis_workers_dir) / filename
        meta, body = strip_markdown_front_matter(read_text(path))
        description = meta.get('description') or worker_name.replace('_', ' ')
        worker_prompt = body.strip() + '\n'
        agents[worker_name] = {
            'description': description,
            'mode': 'subagent',
            'prompt': worker_prompt,
            'permission': {
                'read': 'allow',
                'bash': 'allow',
                'grep': 'allow',
                'glob': 'allow',
                'list': 'allow',
                'edit': 'allow',
                'write': 'allow',
                'task': 'deny',
                'external_directory': 'allow',
            },
        }
        agent_md = (
            '---\n'
            f'description: {description}\n'
            'mode: subagent\n'
            'permission:\n'
            '  read: allow\n'
            '  bash: allow\n'
            '  grep: allow\n'
            '  glob: allow\n'
            '  list: allow\n'
            '  edit: allow\n'
            '  task: deny\n'
            '  external_directory: allow\n'
            '---\n\n'
            + worker_prompt
        )
        global_path = f'{global_agent_dir}/{worker_name}.md'
        project_path = f'{project_agent_dir}/{worker_name}.md'
        files[global_path] = agent_md
        files[project_path] = agent_md
        installed[worker_name] = global_path
    command_budget_plugin_path = install_command_budget_plugin(config, files, work_dir)
    files[config_path] = json.dumps(config, ensure_ascii=False, indent=2) + '\n'
    write_result = docker_write_text_files(opencode.container_id, files)
    post_install_cmd = (
        f'cd {shlex.quote(work_dir)} && '
        "mkdir -p .git/info && "
        "printf '\\n.opencode/\\n.vulnerability-analysis/\\n.repair/\\n' >> .git/info/exclude && "
        f'chown -R opencode_user:opencode_user {shlex.quote(global_agent_dir)} '
        f'{shlex.quote(project_agent_dir)} {shlex.quote(command_budget_plugin_path)} {shlex.quote(config_path)}'
    )
    docker_exec(opencode.container_id, ['bash', '-lc', post_install_cmd], timeout=60)
    opencode._log_process_step('d_subagents_installed', {'workers': installed, 'config_path': config_path})
    return {
        'config_path': config_path,
        'workers': installed,
        'write_transfer': write_result.get('transfer'),
        'subagent_depth_requested': int(getattr(args, 'analysis_subagent_depth', 1) or 1),
        'subagent_task_permission': 'deny',
        'command_budget_plugin_path': command_budget_plugin_path,
    }


def install_d_repair_mas_subagents(opencode: OpenCodeRunner, args: argparse.Namespace, record: Any) -> Dict[str, Any]:
    work_dir = record.work_dir
    config_path = f'{work_dir}/opencode.json'
    raw_config = docker_read_text(opencode.container_id, config_path, missing_ok=True, timeout=60)
    config = parse_json_lenient(raw_config) if raw_config.strip() else {}
    if not isinstance(config, dict) or not config:
        config = {'$schema': 'https://opencode.ai/config.json'}
    permission = config.setdefault('permission', {})
    for key in ['read', 'bash', 'grep', 'glob', 'list', 'edit', 'write', 'task', 'todowrite', 'external_directory']:
        permission[key] = 'allow'
    removed_agents: List[str] = []
    agents = config.setdefault('agent', {})
    if isinstance(agents, dict):
        for agent_name in D_ANALYSIS_WORKERS:
            if agent_name in agents:
                removed_agents.append(agent_name)
                agents.pop(agent_name, None)
    else:
        agents = {}
        config['agent'] = agents

    global_agent_dir = '/path/to/local/resource
    project_agent_dir = f'{work_dir}/.opencode/agents'
    files: Dict[str, str] = {}
    installed: Dict[str, str] = {}
    for agent_name, filename in D_REPAIR_MAS_AGENTS.items():
        path = Path(args.repair_mas_agents_dir) / filename
        meta, body = strip_markdown_front_matter(read_text(path))
        description = meta.get('description') or agent_name.replace('_', ' ')
        prompt = body.strip() + '\n'
        agents[agent_name] = {
            'description': description,
            'mode': 'subagent',
            'prompt': prompt,
            'permission': {
                'read': 'allow',
                'bash': 'allow',
                'grep': 'allow',
                'glob': 'allow',
                'list': 'allow',
                'edit': 'allow',
                'write': 'allow',
                'task': 'deny',
                'external_directory': 'allow',
            },
        }
        agent_md = (
            '---\n'
            f'description: {description}\n'
            'mode: subagent\n'
            'permission:\n'
            '  read: allow\n'
            '  bash: allow\n'
            '  grep: allow\n'
            '  glob: allow\n'
            '  list: allow\n'
            '  edit: allow\n'
            '  write: allow\n'
            '  task: deny\n'
            '  external_directory: allow\n'
            '---\n\n'
            + prompt
        )
        global_path = f'{global_agent_dir}/{agent_name}.md'
        project_path = f'{project_agent_dir}/{agent_name}.md'
        files[global_path] = agent_md
        files[project_path] = agent_md
        installed[agent_name] = global_path

    command_budget_plugin_path = install_command_budget_plugin(config, files, work_dir)
    files[config_path] = json.dumps(config, ensure_ascii=False, indent=2) + '\n'
    write_result = docker_write_text_files(opencode.container_id, files)
    post_install_cmd = (
        f'cd {shlex.quote(work_dir)} && '
        "mkdir -p .git/info && "
        "printf '\\n.opencode/\\n.vulnerability-analysis/\\n.repair/\\n.repair-mas/\\n' >> .git/info/exclude && "
        f'chown -R opencode_user:opencode_user {shlex.quote(global_agent_dir)} '
        f'{shlex.quote(project_agent_dir)} {shlex.quote(command_budget_plugin_path)} {shlex.quote(config_path)}'
    )
    docker_exec(opencode.container_id, ['bash', '-lc', post_install_cmd], timeout=60)
    marker = {
        'config_path': config_path,
        'task_permission': 'allow',
        'removed_analysis_agents': removed_agents,
        'repair_mas_agents': installed,
        'write_transfer': write_result.get('transfer'),
        'command_budget_plugin_path': command_budget_plugin_path,
        'note': 'Repair leader can delegate to patch_generator and patch_reviewer; prompt handoff remains vulnerability_model.json.',
    }
    opencode._log_process_step('d_repair_mas_subagents_installed', marker)
    return marker


def resolve_model_artifact_path(work_dir: str, path: str) -> str:
    text = str(path or '').strip()
    if not text:
        return ''
    if text.startswith('/'):
        return text
    if text.startswith('./'):
        text = text[2:]
    return f'{work_dir}/{text}'


def validate_vulnerability_model(container_id: str, work_dir: str, model: Dict[str, Any]) -> Dict[str, Any]:
    required_top = [
        'schema_version', 'task', 'status', 'security_boundary', 'root_cause',
        'execution_path', 'reproducer', 'boundary', 'coverage', 'evidence',
        'uncertainty', 'artifacts',
    ]
    missing_top = [key for key in required_top if key not in model]
    artifact_paths: List[str] = []
    artifacts = model.get('artifacts') if isinstance(model.get('artifacts'), dict) else {}
    for value in artifacts.values():
        if isinstance(value, str) and value.strip():
            artifact_paths.append(resolve_model_artifact_path(work_dir, value.strip()))
    model_path = f'{work_dir}/.vulnerability-analysis/vulnerability_model.json'
    artifact_paths.append(model_path)
    missing_artifacts: List[str] = []
    artifact_check_error = ''
    if artifact_paths:
        checks = '\n'.join(
            f'test -s {shlex.quote(path)} || printf "%s\\n" {shlex.quote(path)}'
            for path in artifact_paths
        )
        try:
            result = docker_exec(container_id, ['bash', '-lc', 'set +e\n' + checks], timeout=60)
            if result.returncode == 0:
                missing_artifacts = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            else:
                artifact_check_error = tail_chars((result.stdout + result.stderr).strip(), 2000)
        except Exception as exc:
            artifact_check_error = str(exc)
    return {
        'missing_top_level_fields': missing_top,
        'artifact_paths_checked': artifact_paths,
        'missing_artifact_paths': missing_artifacts,
        'artifact_check_error': artifact_check_error,
        'analysis_status': (model.get('status') or {}).get('analysis_status') if isinstance(model.get('status'), dict) else '',
        'confidence': (model.get('status') or {}).get('confidence') if isinstance(model.get('status'), dict) else '',
    }


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def experiment_variant(args: argparse.Namespace) -> str:
    return str(getattr(args, 'experiment_variant', 'D4') or 'D4').strip().upper()


def is_d4_variant(args: argparse.Namespace) -> bool:
    return experiment_variant(args) == 'D4'


def copy_container_text_file_if_present(container_id: str, container_path: str, host_path: Path, *, timeout: int = 60) -> str:
    text = docker_read_text(container_id, container_path, missing_ok=True, timeout=timeout)
    if text:
        host_write_optional(host_path, text)
    return text


def parse_required_json_artifact(
    *,
    container_id: str,
    container_path: str,
    host_path: Path,
    result: Dict[str, Any],
    result_key: str,
    failures: List[str],
    timeout: int = 60,
) -> Tuple[str, Any]:
    text = copy_container_text_file_if_present(container_id, container_path, host_path, timeout=timeout)
    if text:
        result[result_key] = str(host_path)
    if not text.strip():
        failures.append(f'missing artifact: {container_path}')
        return '', {}
    parsed = parse_json_any_lenient(text)
    if not parsed:
        failures.append(f'invalid or empty JSON artifact: {container_path}')
    return text, parsed


def write_json_artifact(host_path: Path, parsed: Any) -> None:
    host_path.parent.mkdir(parents=True, exist_ok=True)
    host_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def _overwrite_existing_patch_hash_fields(value: Any, actual_sha: str) -> int:
    changed = 0
    if isinstance(value, dict):
        for key, nested in list(value.items()):
            if key in {'patch_sha256', 'final_patch_sha256'}:
                if nested != actual_sha:
                    value[key] = actual_sha
                    changed += 1
            else:
                changed += _overwrite_existing_patch_hash_fields(nested, actual_sha)
    elif isinstance(value, list):
        for item in value:
            changed += _overwrite_existing_patch_hash_fields(item, actual_sha)
    return changed


def inject_d4_repair_patch_hashes(
    *,
    actual_sha: str,
    refinement: Any,
    repair_report: Any,
    test_report: Any,
    host_artifact_dir: Path,
    result: Dict[str, Any],
    warnings: List[str],
) -> None:
    """Populate exact patch hashes from the saved candidate patch, not from the LLM."""
    injected_fields: List[str] = []

    if isinstance(refinement, dict):
        _overwrite_existing_patch_hash_fields(refinement, actual_sha)
        if refinement.get('final_patch_sha256') != actual_sha:
            refinement['final_patch_sha256'] = actual_sha
        injected_fields.append('refinement_log.final_patch_sha256')
        write_json_artifact(host_artifact_dir / 'repair' / 'refinement_log.json', refinement)

    if isinstance(repair_report, dict):
        _overwrite_existing_patch_hash_fields(repair_report, actual_sha)
        if repair_report.get('patch_sha256') != actual_sha:
            repair_report['patch_sha256'] = actual_sha
        injected_fields.append('repair_report.patch_sha256')
        final_security = repair_report.get('final_security_validation')
        if isinstance(final_security, dict):
            if final_security.get('patch_sha256') != actual_sha:
                final_security['patch_sha256'] = actual_sha
            injected_fields.append('repair_report.final_security_validation.patch_sha256')
        write_json_artifact(host_artifact_dir / 'repair' / 'repair_report.json', repair_report)

    if isinstance(test_report, dict):
        _overwrite_existing_patch_hash_fields(test_report, actual_sha)
        if test_report.get('final_patch_sha256') != actual_sha:
            test_report['final_patch_sha256'] = actual_sha
        injected_fields.append('test_report.final_patch_sha256')
        write_json_artifact(host_artifact_dir / 'repair' / 'test_report.json', test_report)

    if injected_fields:
        result['d4_hash_injection'] = {
            'source': '/workspace/candidate-cve-fix.patch',
            'sha256': actual_sha,
            'fields_populated_by_harness': injected_fields,
        }
        warnings.append('patch hash fields were populated by the D4 harness from /workspace/candidate-cve-fix.patch')


def collect_repair_iteration_artifacts(container_id: str, work_dir: str, host_artifact_dir: Path, result: Dict[str, Any]) -> None:
    iterations_dir = f'{work_dir}/.repair/iterations'
    cmd = f'test -d {shlex.quote(iterations_dir)} && find {shlex.quote(iterations_dir)} -maxdepth 1 -type f -print | sort || true'
    listing = docker_exec(container_id, ['bash', '-lc', cmd], timeout=60)
    copied: List[str] = []
    for raw_path in listing.stdout.splitlines():
        container_path = raw_path.strip()
        if not container_path:
            continue
        name = PurePosixPath(container_path).name
        host_path = host_artifact_dir / 'repair' / 'iterations' / name
        text = docker_read_text(container_id, container_path, missing_ok=True, timeout=60)
        if text:
            host_write_optional(host_path, text)
            copied.append(str(host_path))
    if copied:
        result['d_repair_iteration_artifact_paths'] = copied


def collect_d_repair_artifacts(container_id: str, work_dir: str, host_artifact_dir: Path, result: Dict[str, Any]) -> None:
    def read_optional(container_path: str) -> str:
        try:
            return docker_read_text(container_id, container_path, missing_ok=True, timeout=60)
        except Exception as exc:
            result.setdefault('d_repair_artifact_collection_warnings', []).append({
                'path': container_path,
                'error': str(exc),
            })
            return ''

    for name in ['repair_brief.json', 'refinement_log.json', 'repair_report.json', 'test_report.json']:
        container_path = f'{work_dir}/.repair/{name}'
        text = read_optional(container_path)
        if text:
            host_path = host_artifact_dir / 'repair' / name
            host_write_optional(host_path, text)
            result[f'd_{Path(name).stem}_path'] = str(host_path)
    for name in [
        'repair_state.json',
        'review_result.json',
        'refinement_history.json',
        'final_repair_rationale.md',
        'validation_matrix.json',
        'patch_review_findings.json',
        'candidate.patch',
    ]:
        container_path = f'{work_dir}/.repair/{name}'
        text = read_optional(container_path)
        if text:
            host_path = host_artifact_dir / 'repair_mas' / name
            host_write_optional(host_path, text)
            result[f'd_repair_mas_{Path(name).stem}_path'] = str(host_path)
            continue
        legacy_container_path = f'{work_dir}/.repair-mas/{name}'
        legacy_text = read_optional(legacy_container_path)
        if legacy_text:
            host_path = host_artifact_dir / 'repair_mas' / name
            host_write_optional(host_path, legacy_text)
            result[f'd_repair_mas_{Path(name).stem}_path'] = str(host_path)
    try:
        collect_repair_iteration_artifacts(container_id, work_dir, host_artifact_dir, result)
    except Exception as exc:
        result.setdefault('d_repair_artifact_collection_warnings', []).append({
            'path': f'{work_dir}/.repair/iterations',
            'error': str(exc),
        })


def _json_lookup(mapping: Any, *keys: str) -> Any:
    cur = mapping
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _nonempty(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, list):
        return bool(value)
    if isinstance(value, str):
        return bool(value.strip())
    return value is not None


def _iter_status_records(value: Any) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    if isinstance(value, dict):
        if 'status' in value:
            found.append(value)
        for nested in value.values():
            found.extend(_iter_status_records(nested))
    elif isinstance(value, list):
        for item in value:
            found.extend(_iter_status_records(item))
    return found


def validate_d4_repair_gate(
    *,
    container_id: str,
    work_dir: str,
    candidate_patch: str,
    host_artifact_dir: Path,
    result: Dict[str, Any],
) -> Dict[str, Any]:
    failures: List[str] = []
    warnings: List[str] = []
    actual_sha = sha256_text(candidate_patch)
    repair_dir = f'{work_dir}/.repair'
    _, refinement = parse_required_json_artifact(
        container_id=container_id,
        container_path=f'{repair_dir}/refinement_log.json',
        host_path=host_artifact_dir / 'repair' / 'refinement_log.json',
        result=result,
        result_key='d_refinement_log_path',
        failures=failures,
    )
    _, repair_report = parse_required_json_artifact(
        container_id=container_id,
        container_path=f'{repair_dir}/repair_report.json',
        host_path=host_artifact_dir / 'repair' / 'repair_report.json',
        result=result,
        result_key='d_repair_report_path',
        failures=failures,
    )
    _, test_report = parse_required_json_artifact(
        container_id=container_id,
        container_path=f'{repair_dir}/test_report.json',
        host_path=host_artifact_dir / 'repair' / 'test_report.json',
        result=result,
        result_key='d_test_report_path',
        failures=failures,
    )

    inject_d4_repair_patch_hashes(
        actual_sha=actual_sha,
        refinement=refinement,
        repair_report=repair_report,
        test_report=test_report,
        host_artifact_dir=host_artifact_dir,
        result=result,
        warnings=warnings,
    )

    iterations = refinement.get('iterations') if isinstance(refinement, dict) else None
    if not isinstance(iterations, list) or not iterations:
        failures.append('refinement_log.json has no iterations')
    exact_recheck = None
    if isinstance(refinement, dict):
        exact_recheck = refinement.get('final_exact_patch_recheck')
    if not _nonempty(exact_recheck) and isinstance(test_report, dict):
        exact_recheck = test_report.get('final_exact_patch_recheck')
    if not _nonempty(exact_recheck):
        failures.append('final exact-patch recheck is missing or empty')

    repair_status = repair_report.get('repair_status') if isinstance(repair_report, dict) else ''
    if repair_status not in {'completed', 'completed_with_limitations', 'candidate_only'}:
        failures.append(f'repair_report.repair_status is invalid or missing: {repair_status!r}')
    report_sha = str(repair_report.get('patch_sha256') or '').strip() if isinstance(repair_report, dict) else ''
    if not report_sha:
        failures.append('repair_report.patch_sha256 is missing')
    elif report_sha != actual_sha:
        failures.append('repair_report.patch_sha256 does not match /workspace/candidate-cve-fix.patch')
    refinement_sha = str(refinement.get('final_patch_sha256') or '').strip() if isinstance(refinement, dict) else ''
    if refinement_sha and refinement_sha != actual_sha:
        failures.append('refinement_log.final_patch_sha256 does not match /workspace/candidate-cve-fix.patch')
    test_report_sha = str(test_report.get('final_patch_sha256') or '').strip() if isinstance(test_report, dict) else ''
    if test_report_sha and test_report_sha != actual_sha:
        failures.append('test_report.final_patch_sha256 does not match /workspace/candidate-cve-fix.patch')

    final_security = repair_report.get('final_security_validation') if isinstance(repair_report, dict) else {}
    if not isinstance(final_security, dict):
        final_security = {}
    if repair_status == 'completed':
        if final_security.get('semantic_verdict') != 'secure':
            failures.append('completed repair lacks final_security_validation.semantic_verdict=secure')
        if final_security.get('observes_exact_patch') is not True:
            failures.append('completed repair lacks final security evidence observing the exact patch')
        if str(final_security.get('patch_sha256') or '').strip() != actual_sha:
            failures.append('completed repair final_security_validation.patch_sha256 does not match exact patch')
        if final_security.get('mode') in {'baseline_only_model', 'unknown', ''}:
            failures.append('completed repair final_security_validation mode is not patch-coupled or source-qualified')
    if repair_status == 'completed_with_limitations':
        if final_security.get('semantic_verdict') == 'insecure':
            failures.append('completed_with_limitations repair has insecure final semantic verdict')
        if final_security.get('mode') in {'baseline_only_model', 'unknown', ''}:
            failures.append('completed_with_limitations repair relies on baseline-only or unknown final security mode')

    final_status_sources = []
    if isinstance(refinement, dict):
        final_status_sources.extend(_iter_status_records(refinement.get('final_exact_patch_recheck')))
        if isinstance(iterations, list):
            selected_attempt = refinement.get('selected_attempt_id')
            for item in iterations:
                if isinstance(item, dict) and item.get('attempt_id') == selected_attempt:
                    final_status_sources.extend(_iter_status_records(item.get('self_review')))
    if isinstance(test_report, dict):
        for key in ['final_patch_integrity', 'vulnerability_tests', 'compatibility_tests', 'final_exact_patch_recheck', 'clean_environment_validation']:
            final_status_sources.extend(_iter_status_records(test_report.get(key)))
    failed_final_statuses = [
        item for item in final_status_sources
        if str(item.get('status') or '').strip().lower() in {'fail', 'failed', 'error'}
    ]
    if failed_final_statuses and repair_status == 'completed':
        failures.append('repair_status=completed despite failed final/core gate status records')
    elif failed_final_statuses:
        warnings.append('final/core gate status records include failures; repair_status must not be completed')

    gate = {
        'schema_version': 'd4.repair_gate.v1',
        'actual_candidate_patch_sha256': actual_sha,
        'repair_status': repair_status,
        'final_security_validation': final_security,
        'passed': not failures,
        'failures': failures,
        'warnings': warnings,
    }
    result['d4_repair_gate'] = gate
    result['d4_candidate_patch_sha256'] = actual_sha
    result['d4_repair_status'] = repair_status
    return gate


def d_model_post_repair_validation(
    *,
    container_id: str,
    work_dir: str,
    model: Dict[str, Any],
    args: argparse.Namespace,
    host_artifact_dir: Path,
) -> Dict[str, Any]:
    validation: Dict[str, Any] = {
        'schema_version': 'd.post_repair_validation.v1',
        'attempted': [],
        'failures': [],
        'notes': [],
    }
    reproducer = model.get('reproducer') if isinstance(model.get('reproducer'), dict) else {}
    artifacts = model.get('artifacts') if isinstance(model.get('artifacts'), dict) else {}
    rep_path = str(reproducer.get('path') or '').strip()
    rep_command = str(reproducer.get('command') or artifacts.get('candidate_reproducer') or '').strip()
    rep_target = rep_command or rep_path
    if rep_target:
        resolved_rep_path = resolve_model_artifact_path(work_dir, rep_path) if rep_path else ''
        resolved_command = rep_command
        if not resolved_command and resolved_rep_path:
            resolved_command = resolved_rep_path
        result = docker_exec(container_id, ['bash', '-lc', f'test -n {shlex.quote(resolved_command)}'], timeout=30)
        if result.returncode == 0:
            rc, output = run_model_shell_command(container_id, work_dir, resolved_command, args.reproducer_timeout_seconds)
            validation['attempted'].append({
                'kind': 'candidate_reproducer_after_patch',
                'path': rep_path,
                'command': rep_command,
                'resolved_path': resolved_rep_path,
                'resolved_command': resolved_command,
                'return_code': rc,
                'output_tail': tail_chars(output, 3000),
            })
            if 'VULNERABILITY_REPRODUCED' in output and 'REGRESSION_CONTROL_FAILED' not in output:
                validation['failures'].append('candidate reproducer still reports VULNERABILITY_REPRODUCED after repair')
        else:
            validation['notes'].append(f'candidate reproducer command from model is empty or unavailable: {rep_target}')
    control_path = str(artifacts.get('control_tests') or '').strip()
    if control_path:
        resolved_control_path = resolve_model_artifact_path(work_dir, control_path)
        result = docker_exec(container_id, ['bash', '-lc', f'test -f {shlex.quote(resolved_control_path)}'], timeout=30)
        if result.returncode == 0:
            rc, output = run_reproducer(container_id, work_dir, resolved_control_path, args.reproducer_timeout_seconds)
            validation['attempted'].append({'kind': 'control_tests_after_patch', 'path': control_path, 'resolved_path': resolved_control_path, 'return_code': rc, 'output_tail': tail_chars(output, 3000)})
            if 'REGRESSION_CONTROL_FAILED' in output:
                validation['failures'].append('control tests failed after repair')
            elif rc != 0:
                validation['notes'].append(
                    'control_tests exited nonzero without REGRESSION_CONTROL_FAILED; '
                    'treated as advisory because analysis control scripts may include vulnerable-behavior probes that should fail after repair'
                )
        else:
            validation['notes'].append(f'control_tests path from model is absent after reset/apply: {control_path}')
    out = json.dumps(validation, ensure_ascii=False, indent=2) + '\n'
    host_write_optional(host_artifact_dir / 'repair_context' / 'd_post_repair_validation.json', out)
    return validation


def secbench_post_repair_validation(
    *,
    container_id: str,
    work_dir: str,
    host_artifact_dir: Path,
    total_deadline: Optional[float] = None,
) -> Dict[str, Any]:
    validation: Dict[str, Any] = {
        'benchmark': 'secbench',
        'work_dir': work_dir,
        'commands': [],
        'failures': [],
        'notes': [],
    }

    def run_cmd(label: str, command: str, timeout_seconds: int) -> Dict[str, Any]:
        timeout = deadline_limited_timeout(timeout_seconds, total_deadline, f'benchmark total timeout before {label}')
        result = docker_exec(container_id, ['bash', '-lc', f'cd {shlex.quote(work_dir)} && {command}'], timeout=timeout)
        output = (result.stdout + result.stderr).strip()
        entry = {
            'label': label,
            'command': command,
            'return_code': result.returncode,
            'output_tail': tail_chars(output, 5000),
        }
        validation['commands'].append(entry)
        return entry

    build = run_cmd('secb_build', 'secb build', 1800)
    if build['return_code'] != 0:
        validation['failures'].append(f'secb build failed with exit code {build["return_code"]}')
    else:
        repro = run_cmd('secb_repro', 'timeout 10 secb repro', 120)
        repro_text = str(repro.get('output_tail') or '')
        sanitizer_markers = [
            'ERROR: AddressSanitizer',
            'ERROR: UndefinedBehaviorSanitizer',
            'ERROR: MemorySanitizer',
            'ERROR: LeakSanitizer',
            'runtime error:',
        ]
        if any(marker in repro_text for marker in sanitizer_markers):
            validation['failures'].append('secb repro still triggered sanitizer output')
        elif repro['return_code'] == 124:
            validation['notes'].append(
                'secb repro timed out after 10 seconds without recognized sanitizer output; '
                'treating local post-validation as inconclusive and leaving final interpretation to official SEC-bench evaluation.'
            )
        elif repro['return_code'] != 0:
            validation['notes'].append(
                f'secb repro exited {repro["return_code"]} without recognized sanitizer output; '
                'official SEC-bench evaluator will apply its own mode-specific interpretation.'
            )
    out = json.dumps(validation, ensure_ascii=False, indent=2) + '\n'
    host_write_optional(host_artifact_dir / 'repair_context' / 'secbench_post_repair_validation.json', out)
    return validation


def run_d_analysis_mas_repair_workflow(
    *,
    args: argparse.Namespace,
    record: Any,
    outputs: Path,
    result: Dict[str, Any],
    container_id: str,
    opencode: OpenCodeRunner,
    artifact_dir: str,
    repair_context_dir: str,
    host_artifact_dir: Path,
    host_repair_context_dir: Path,
    persist_result: Optional[Callable[[], None]] = None,
    total_deadline: Optional[float] = None,
) -> Dict[str, Any]:
    variant = experiment_variant(args)
    variant_lower = variant.lower()
    result['workflow'] = f'{variant}_analysis_mas_vulnerability_model_repair_direct_eval'
    result['experiment_variant'] = variant
    if persist_result:
        persist_result()
    analysis_dir = f'{record.work_dir}/.vulnerability-analysis'
    repair_dir = f'{record.work_dir}/.repair'
    repair_mas_dir = f'{record.work_dir}/.repair-mas'
    prompt_values = stage_values(record, artifact_dir)
    final_patch_path = prompt_values.get('FINAL_PATCH_PATH', '/workspace/fix.patch')
    reset_ok, reset_output = reset_worktree_preserve(container_id, record.work_dir, ['.vulnerability-analysis/', '.repair/', '.repair-mas/', '.opencode/'])
    if not reset_ok:
        raise RuntimeError('failed to reset worktree before D analysis MAS: ' + reset_output)
    ensure_agent_writable_dir(container_id, analysis_dir)
    ensure_agent_writable_dir(container_id, repair_dir)
    ensure_agent_writable_dir(container_id, repair_mas_dir)
    ensure_agent_writable_dir(container_id, repair_context_dir)
    mas_config_paths = write_d_analysis_mas_config_files(container_id, args, artifact_dir)
    result['d_analysis_mas_config'] = mas_config_paths
    if persist_result:
        persist_result()
    result['d_opencode_subagents'] = install_d_opencode_subagents(opencode, args, record)
    if persist_result:
        persist_result()

    result['stage'] = 'd_analysis_mas'
    if persist_result:
        persist_result()
    model_path = f'{analysis_dir}/vulnerability_model.json'
    summary_path = f'{analysis_dir}/vulnerability_model_summary.md'
    vulnerability_model: Dict[str, Any] = {}
    model_text = ''
    host_summary = ''
    validation: Dict[str, Any] = {}
    analysis_resumed = False
    if getattr(args, 'resume', False):
        cached_model_path = host_artifact_dir / 'vulnerability_model.json'
        cached_summary_path = host_artifact_dir / 'vulnerability_model_summary.md'
        if cached_model_path.exists() and cached_model_path.stat().st_size > 0:
            cached_model_text = cached_model_path.read_text(encoding='utf-8', errors='replace')
            cached_model = parse_json_lenient(cached_model_text)
            if cached_model:
                cached_summary = ''
                files_to_restore = {model_path: cached_model_text}
                if cached_summary_path.exists() and cached_summary_path.stat().st_size > 0:
                    cached_summary = cached_summary_path.read_text(encoding='utf-8', errors='replace')
                    files_to_restore[summary_path] = cached_summary
                docker_write_text_files(container_id, files_to_restore)
                cached_validation = validate_vulnerability_model(container_id, record.work_dir, cached_model)
                if not cached_validation['missing_top_level_fields']:
                    vulnerability_model = cached_model
                    model_text = cached_model_text
                    host_summary = cached_summary
                    validation = cached_validation
                    analysis_resumed = True
                    result['d_analysis_mas_resumed_from_host_artifacts'] = {
                        'model_path': str(cached_model_path),
                        'summary_path': str(cached_summary_path) if cached_summary else '',
                    }
                    result['stage'] = 'd_analysis_mas_resumed'
                    if persist_result:
                        persist_result()
                else:
                    result['d_analysis_mas_resume_skipped_reason'] = (
                        'cached vulnerability_model.json missing required top-level fields: '
                        + ', '.join(cached_validation['missing_top_level_fields'])
                    )
            else:
                result['d_analysis_mas_resume_skipped_reason'] = 'cached vulnerability_model.json is invalid JSON'
    analysis_delegation_instructions = prompt_values.get('ANALYSIS_DELEGATION_INSTRUCTIONS', '').strip()
    lead_prompt = (
        d_prompt_front_matter('Analysis lead for canonical vulnerability_model.json', 'Bash, Read, Glob, Grep, Task, Write, LS')
        + read_prompt_body(Path(args.analysis_lead_system_prompt))
        + '\n\n# Rendered User Task\n\n'
        + render_template(read_prompt_body(Path(args.analysis_lead_user_prompt)), prompt_values)
        + '\n\n# D Runtime Integration\n\n'
        + 'Specialized analysis roles are available through the task delegation tool. '
        + 'Use Task with these exact role names when their narrow responsibilities are needed: '
        + ', '.join(D_ANALYSIS_WORKERS) + '.\n'
        + 'Task templates are available at: ' + mas_config_paths['config_dir'] + '/tasks\n'
        + 'Do not paste all worker system prompts into your own context. Delegate using Task so each worker keeps its own role prompt. '
        + 'If the Task tool or a named role is unexpectedly unavailable, record the concrete blocker in evidence_loop_state.json and do not claim that delegated review or worker evidence exists.\n'
        + (
            '\nBenchmark-specific delegation guidance:\n'
            + analysis_delegation_instructions
            + '\n'
            if analysis_delegation_instructions
            else ''
        )
    )
    analysis_expected_artifacts = [model_path]
    analysis_subagent_trace_index_path = outputs / 'subagent_trace_index' / f'{record.cve_id}.d_analysis_mas.subagents.json'
    result['d_analysis_mas_subagent_trace_index_path'] = str(analysis_subagent_trace_index_path)
    result['d_analysis_mas_subagent_log_manifest_path'] = str(outputs / 'subagent_logs' / record.cve_id / 'd_analysis_mas' / 'latest_manifest.json')
    if not analysis_resumed:
        analysis_log_path = outputs / 'agent_logs' / f'{record.cve_id}.d_analysis_mas.log'
        analysis_stage_timeout = deadline_limited_timeout(args.analysis_timeout_seconds, total_deadline, 'benchmark total timeout before analysis MAS')
        analysis_closeout_reserve = forced_closeout_reserve(
            analysis_stage_timeout,
            int(getattr(args, 'analysis_closeout_reserve_seconds', 900) or 0),
        )
        result['stage'] = 'd_analysis_mas'
        if persist_result:
            persist_result()
        analysis_run_started = time.time()
        try:
            run_opencode_stage(
                opencode,
                stage_name='d_analysis_mas',
                prompt_text=lead_prompt,
                prompt_path=f'/tmp/{record.cve_id}_d_analysis_mas_lead.md',
                message='Run the analysis workflow and write the canonical vulnerability_model.json. Do not repair code.',
                timeout_seconds=analysis_stage_timeout,
                host_log_path=analysis_log_path,
                expected_artifacts=analysis_expected_artifacts,
                artifact_grace_seconds=30,
                container_live_log_path=f'{artifact_dir}/opencode_logs/{record.cve_id}.d_analysis_mas.stdout.jsonl',
                subagent_trace_index_path=analysis_subagent_trace_index_path,
                cve_id=record.cve_id,
                artifact_dir=artifact_dir,
                closeout_reserve_seconds=analysis_closeout_reserve,
            )
        except (StageSoftTimeout, StageMissingArtifact) as exc:
            analysis_remaining = analysis_stage_timeout - (time.time() - analysis_run_started)
            if analysis_remaining <= 0:
                raise
            analysis_closeout_timeout = max(1, min(analysis_closeout_reserve, int(math.ceil(analysis_remaining))))
            session_id = run_same_session_closeout(
                opencode,
                stage_name='d_analysis_mas',
                original_log_path=analysis_log_path,
                closeout_log_path=outputs / 'agent_logs' / f'{record.cve_id}.d_analysis_mas.closeout.log',
                message=(
                    'Continue this exact analysis session. Your very next tool call MUST be Write to the required JSON path. '
                    'Do not call Bash, Read, Grep, Glob, Task, or any other exploratory tool. Do not delegate, install, or test. '
                    'Using only evidence and tool results already present in this session, immediately write the best '
                    f'evidence-qualified vulnerability model to {model_path}. Mark unsupported claims unknown and record limitations. '
                    'Do not finish with only a conversational answer.'
                ),
                timeout_seconds=analysis_closeout_timeout,
                expected_artifacts=analysis_expected_artifacts,
                require_expected_artifacts=True,
                container_kill_pattern='',
                container_live_log_path=f'{artifact_dir}/opencode_logs/{record.cve_id}.d_analysis_mas.closeout.stdout.jsonl',
                cve_id=record.cve_id,
                artifact_dir=artifact_dir,
            )
            result['d_analysis_mas_same_session_closeout'] = {
                'trigger': str(exc),
                'session_id': session_id,
                'reserve_seconds': analysis_closeout_timeout,
            }
            if persist_result:
                persist_result()
        except subprocess.TimeoutExpired:
            if container_files_nonempty(container_id, [model_path]):
                opencode._log_process_step('d_analysis_mas_timeout_salvage', {'model_path': model_path})
            else:
                raise
        model_text = docker_read_text(container_id, model_path, missing_ok=False, timeout=60)
        vulnerability_model = parse_json_lenient(model_text)
        if not vulnerability_model:
            raise RuntimeError('analysis workflow produced an invalid vulnerability_model.json')
    if not host_summary:
        try:
            host_summary = docker_read_text(container_id, summary_path, missing_ok=True, timeout=60)
        except Exception as exc:
            host_summary = ''
            result.setdefault('analysis_artifact_warnings', []).append({'path': summary_path, 'error': str(exc)})
    host_write_optional_files({
        host_artifact_dir / 'vulnerability_model.json': model_text,
        host_artifact_dir / 'vulnerability_model_summary.md': host_summary,
    })
    result['vulnerability_model_path'] = str(host_artifact_dir / 'vulnerability_model.json')
    result['vulnerability_model_summary_path'] = str(host_artifact_dir / 'vulnerability_model_summary.md') if host_summary else ''
    if persist_result:
        persist_result()

    copy_cmd = (
        f'mkdir -p {shlex.quote(artifact_dir)}/analysis_mas_snapshot && '
        f'cp -a {shlex.quote(analysis_dir)}/. {shlex.quote(artifact_dir)}/analysis_mas_snapshot/'
    )
    try:
        docker_exec(container_id, ['bash', '-lc', copy_cmd], timeout=120)
    except Exception as exc:
        result.setdefault('analysis_artifact_warnings', []).append({'path': analysis_dir, 'error': str(exc)})
    if not analysis_resumed:
        validation = validate_vulnerability_model(container_id, record.work_dir, vulnerability_model)
    result['d_vulnerability_model_validation'] = validation
    if persist_result:
        persist_result()
    if validation['missing_top_level_fields']:
        raise RuntimeError('vulnerability_model.json missing required top-level fields: ' + ', '.join(validation['missing_top_level_fields']))

    result['stage'] = 'd_repair_mas'
    if persist_result:
        persist_result()
    reset_ok, reset_output = reset_worktree_preserve(container_id, record.work_dir, ['.vulnerability-analysis/', '.repair/', '.repair-mas/', '.opencode/'])
    if not reset_ok:
        raise RuntimeError('failed to reset worktree before D repair MAS: ' + reset_output)
    ensure_agent_writable_dir(container_id, repair_mas_dir)
    result['d_repair_mas_subagents'] = install_d_repair_mas_subagents(opencode, args, record)
    if persist_result:
        persist_result()
    repair_prompt = (
        d_prompt_front_matter('Repair lead for vulnerability_model.json handoff', 'Bash, Read, Glob, Grep, Task, Write, Edit, LS')
        + read_prompt_body(Path(args.d_repair_system_prompt))
        + '\n\n# Rendered User Task\n\n'
        + render_template(read_prompt_body(Path(args.d_repair_user_prompt)), prompt_values)
        + '\n\n# D Runtime Integration\n\n'
        + 'The analysis workflow has produced the canonical repair handoff at `'
        + model_path
        + '`. Read that JSON before editing code and use it as the primary vulnerability-analysis input. '
        + 'Treat it as evidence to verify against the repository, not as unquestionable ground truth.\n'
        + 'If present, the optional summary is at `'
        + summary_path
        + '`. Do not bulk-load `.vulnerability-analysis/`; read only narrowly relevant artifacts explicitly referenced by the vulnerability model when needed for patch design, oracle interpretation, or validation.\n'
        + 'Specialized repair roles are available through the task delegation tool. '
        + 'Use Task with these exact role names when their narrow responsibilities are needed: patch_generator, patch_reviewer.\n'
        + 'Maintain repair state and refinement history under `'
        + f'{record.work_dir}/.repair'
        + '`.\n'
        + '\nBenchmark-specific validation instructions:\n'
        + prompt_values.get('VALIDATION_INSTRUCTIONS', '').strip()
        + '\n\n'
        + 'Always write the final generated patch to `'
        + final_patch_path
        + '`. This workflow submits that generated patch directly to evaluation and does not run an extra patch postprocess step.\n'
    )
    repair_expected_artifacts = [final_patch_path]
    repair_subagent_trace_index_path = outputs / 'subagent_trace_index' / f'{record.cve_id}.d_repair_mas.subagents.json'
    result['d_repair_mas_subagent_trace_index_path'] = str(repair_subagent_trace_index_path)
    result['d_repair_mas_subagent_log_manifest_path'] = str(outputs / 'subagent_logs' / record.cve_id / 'd_repair_mas' / 'latest_manifest.json')
    repair_log_path = outputs / 'agent_logs' / f'{record.cve_id}.d_repair_mas.log'
    repair_stage_timeout = deadline_limited_timeout(args.repair_timeout_seconds, total_deadline, 'benchmark total timeout before repair MAS')
    repair_closeout_reserve = forced_closeout_reserve(
        repair_stage_timeout,
        int(getattr(args, 'repair_closeout_reserve_seconds', 600) or 0),
    )
    repair_closeout_done = False
    repair_run_started = time.time()
    try:
        run_opencode_stage(
            opencode,
            stage_name='d_repair_mas',
            prompt_text=repair_prompt,
            prompt_path=f'/tmp/{record.cve_id}_d_repair_mas.md',
            message=f'Repair using vulnerability_model.json handoff and write {final_patch_path}.',
            timeout_seconds=repair_stage_timeout,
            host_log_path=repair_log_path,
            expected_artifacts=repair_expected_artifacts,
            require_expected_artifacts=False,
            artifact_grace_seconds=30,
            container_live_log_path=f'{artifact_dir}/opencode_logs/{record.cve_id}.d_repair_mas.stdout.jsonl',
            subagent_trace_index_path=repair_subagent_trace_index_path,
            cve_id=record.cve_id,
            artifact_dir=artifact_dir,
            closeout_reserve_seconds=repair_closeout_reserve,
        )
    except StageSoftTimeout as exc:
        salvaged_patch = extract_candidate_patch(
            container_id,
            record.work_dir,
            patch_path=final_patch_path,
            allow_worktree_fallback=True,
        )
        if salvaged_patch.strip():
            docker_write_text(container_id, salvaged_patch, final_patch_path)
            opencode._log_process_step('d_repair_mas_soft_timeout_worktree_salvage', simple_patch_stats(salvaged_patch))
        else:
            repair_remaining = repair_stage_timeout - (time.time() - repair_run_started)
            if repair_remaining <= 0:
                raise
            repair_closeout_timeout = max(1, min(repair_closeout_reserve, int(math.ceil(repair_remaining))))
            session_id = run_same_session_closeout(
                opencode,
                stage_name='d_repair_mas',
                original_log_path=repair_log_path,
                closeout_log_path=outputs / 'agent_logs' / f'{record.cve_id}.d_repair_mas.closeout.log',
                message=(
                    'Continue this exact repair session. Your very next tool call MUST be Write to the required patch path. '
                    'Do not call Bash, Read, Grep, Glob, Task, or any other exploratory tool. Do not delegate, install, or test. '
                    'Using only the existing vulnerability model, current edits, repair artifacts, and tool results in this session, '
                    f'immediately write the best-supported unified diff to {final_patch_path}. '
                    'Prefer a focused candidate over returning without a patch.'
                ),
                timeout_seconds=repair_closeout_timeout,
                expected_artifacts=repair_expected_artifacts,
                require_expected_artifacts=False,
                container_kill_pattern='',
                container_live_log_path=f'{artifact_dir}/opencode_logs/{record.cve_id}.d_repair_mas.closeout.stdout.jsonl',
                cve_id=record.cve_id,
                artifact_dir=artifact_dir,
            )
            repair_closeout_done = True
            result['d_repair_mas_same_session_closeout'] = {
                'trigger': str(exc),
                'session_id': session_id,
                'reserve_seconds': repair_closeout_timeout,
            }
            if persist_result:
                persist_result()
    except subprocess.TimeoutExpired as exc:
        try:
            salvaged_patch = extract_candidate_patch(
                container_id,
                record.work_dir,
                patch_path=final_patch_path,
                allow_worktree_fallback=True,
            )
        except Exception:
            raise
        if not salvaged_patch.strip():
            raise
        docker_write_text(container_id, salvaged_patch, final_patch_path)
        export_candidate_patch(
            outputs=outputs,
            cve_id=record.cve_id,
            candidate_patch=salvaged_patch,
            result=result,
            source='d_repair_mas_timeout_salvaged_patch',
        )
        result['d_repair_mas_timeout_salvaged'] = {
            'error': str(exc),
            'patch_stats': simple_patch_stats(salvaged_patch),
        }
        if persist_result:
            persist_result()

    result['stage'] = 'candidate_patch_extract'
    patch_file_present = container_files_nonempty(container_id, [final_patch_path])
    candidate_patch = extract_candidate_patch(
        container_id,
        record.work_dir,
        patch_path=final_patch_path,
        allow_worktree_fallback=True,
    )
    repair_remaining = repair_stage_timeout - (time.time() - repair_run_started)
    if not candidate_patch.strip() and not repair_closeout_done and repair_closeout_reserve > 0 and repair_remaining > 0:
        repair_closeout_timeout = max(1, min(repair_closeout_reserve, int(math.ceil(repair_remaining))))
        session_id = run_same_session_closeout(
            opencode,
            stage_name='d_repair_mas',
            original_log_path=repair_log_path,
            closeout_log_path=outputs / 'agent_logs' / f'{record.cve_id}.d_repair_mas.closeout.log',
            message=(
                'Continue this exact repair session. Your very next tool call MUST be Write to the required patch path. '
                'Do not call Bash, Read, Grep, Glob, Task, or any exploratory tool. Do not delegate, install, or test. '
                'Using only the existing vulnerability model, source analysis, current files, and tool results, make the '
                f'best-supported focused repair now and write its unified diff to {final_patch_path}.'
            ),
            timeout_seconds=repair_closeout_timeout,
            expected_artifacts=repair_expected_artifacts,
            require_expected_artifacts=False,
            container_kill_pattern='',
            container_live_log_path=f'{artifact_dir}/opencode_logs/{record.cve_id}.d_repair_mas.closeout.stdout.jsonl',
            cve_id=record.cve_id,
            artifact_dir=artifact_dir,
        )
        repair_closeout_done = True
        result['d_repair_mas_same_session_closeout'] = {
            'trigger': 'normal_exit_without_patch_or_worktree_diff',
            'session_id': session_id,
            'reserve_seconds': repair_closeout_timeout,
        }
        patch_file_present = container_files_nonempty(container_id, [final_patch_path])
        candidate_patch = extract_candidate_patch(
            container_id,
            record.work_dir,
            patch_path=final_patch_path,
            allow_worktree_fallback=True,
        )
        if persist_result:
            persist_result()
    if not candidate_patch.strip():
        raise RuntimeError('D repair agent produced an empty candidate patch')
    docker_write_text(container_id, candidate_patch, final_patch_path)
    export_candidate_patch(
        outputs=outputs,
        cve_id=record.cve_id,
        candidate_patch=candidate_patch,
        result=result,
        source=(
            'd_generated_patch_normalized'
            if patch_file_present
            else 'd_worktree_git_diff_head_fallback'
        ),
    )
    collect_d_repair_artifacts(container_id, record.work_dir, host_artifact_dir, result)
    if is_d4_variant(args):
        result['d4_repair_gate'] = {
            'passed': True,
            'skipped': True,
            'reason': 'patch-only repair prompt does not request .repair JSON artifacts',
        }
    if persist_result:
        persist_result()

    result['stage'] = 'd_candidate_patch_apply_check'
    if persist_result:
        persist_result()
    try:
        result['candidate_patch_apply_for_validation'] = apply_candidate_patch_for_validation(
            container_id,
            record.work_dir,
            patch_path=final_patch_path,
        )
    except (TimeoutError, subprocess.TimeoutExpired) as exc:
        result['candidate_patch_apply_for_validation'] = {
            'skipped': True,
            'reason': 'sandbox_exec_timeout_after_patch_export',
            'error': str(exc),
            'patch_path': final_patch_path,
            'work_dir': record.work_dir,
        }
        result.setdefault('diagnostic_warnings', []).append(
            'candidate patch was exported, but clean-apply validation timed out in sandbox; official eval should validate apply/build behavior.'
        )
        if persist_result:
            persist_result()
    result['stage'] = 'd_post_repair_validation'
    if persist_result:
        persist_result()
    if benchmark_name(args) == 'secbench':
        d_validation = secbench_post_repair_validation(
            container_id=container_id,
            work_dir=record.work_dir,
            host_artifact_dir=host_artifact_dir,
            total_deadline=total_deadline,
        )
    else:
        d_validation = d_model_post_repair_validation(
            container_id=container_id,
            work_dir=record.work_dir,
            model=vulnerability_model,
            args=args,
            host_artifact_dir=host_artifact_dir,
        )
    result['d_post_repair_validation'] = d_validation
    if d_validation.get('failures') and not args.allow_repair_validation_failure:
        result['postprocess_skipped_reason'] = 'd_post_repair_validation_failed'
        raise RuntimeError('D post-repair validation failed: ' + '; '.join(d_validation['failures']))

    if args.skip_postprocess:
        result['stage'] = 'completed_without_postprocess'
        result['is_success'] = True
        return result

    result['stage'] = 'postprocess_existing_mas'
    if persist_result:
        persist_result()
    postprocess_outputs = outputs / 'postprocess_raw' / record.cve_id
    pp_args = build_postprocess_args(args, record, candidate_host_path, postprocess_outputs)
    pp_result = postprocess_runner.run(pp_args)
    result['postprocess_outputs_root'] = str(postprocess_outputs)
    result['postprocess_result'] = pp_result
    if not pp_result.get('is_success'):
        raise RuntimeError('existing MAS postprocessor failed: ' + str(pp_result.get('error_message', '')))
    post_patch = postprocess_outputs / 'patches' / f'{record.cve_id}.patch'
    if not post_patch.exists() or post_patch.stat().st_size == 0:
        raise RuntimeError(f'postprocessor reported success but patch is missing: {post_patch}')
    final_patch_path = outputs / 'patches' / f'{record.cve_id}.patch'
    post_patch_text = post_patch.read_text(encoding='utf-8', errors='replace')
    result['patch_path_validation'] = assert_submission_patch_paths(post_patch_text)
    shutil.copyfile(post_patch, final_patch_path)
    result['patch_path'] = str(final_patch_path)
    result['patch_stats'] = simple_patch_stats(post_patch_text)
    result['stage'] = 'completed'
    result['is_success'] = True
    return result


def build_fallback_knowledge_artifacts(record: Any) -> Tuple[str, str]:
    candidate_files = extract_vulnerability_locations(record.problem_statement)
    summary = tail_chars((record.problem_statement or '').strip(), 5000)
    findings = {
        'cve_id': record.cve_id,
        'candidate_files': candidate_files,
        'candidate_functions': [],
        'security_boundary': 'Derived from CVE problem statement; knowledge agent artifact missing.',
        'suspected_root_cause': 'See CVE description and vulnerability locations in the problem statement.',
        'reproduction_hypotheses': [
            'Construct a deterministic local reproducer that exercises the vulnerable behavior described in the CVE statement.',
            'Focus first on the listed vulnerability location files and the nearest public API or test harness.',
        ],
        'test_commands': [],
        'repair_constraints': [
            'Modify production source only.',
            'Do not include generated PoC, temporary files, or benchmark artifacts in the final patch.',
            'Keep the repair minimal and targeted to the vulnerability boundary.',
        ],
    }
    report_lines = [
        f'# Fallback Knowledge Report for {record.cve_id}',
        '',
        'The Knowledge Collection Agent did not produce the required artifacts. This fallback was generated by the orchestrator so downstream agents can continue.',
        '',
        '## CVE Summary',
        summary or '(problem statement unavailable)',
        '',
        '## Repository Map',
        f'- Repository work_dir: {record.work_dir}',
        f'- Repository name: {Path(record.work_dir).name}',
        '',
        '## Relevant Source Files and Line-Level Evidence',
    ]
    if candidate_files:
        report_lines.extend(f'- {item}' for item in candidate_files)
    else:
        report_lines.append('- No explicit file_path entries were parsed from the problem statement.')
    report_lines.extend([
        '',
        '## Existing Tests and Commands',
        '- Not collected by fallback. The Test Case / PoC Agent should inspect package metadata and local test harnesses.',
        '',
        '## Vulnerability Hypothesis',
        'Use the CVE description and parsed vulnerability locations as the starting point for a deterministic local reproducer.',
        '',
        '## Reproduction Hypotheses for the Test Case / PoC Agent',
        '- Exercise the vulnerable data flow described in the CVE statement.',
        '- Prefer a minimal local script that exits 0 and prints VULNERABILITY_REPRODUCED only for the vulnerable behavior.',
        '',
        '## Repair Constraints and Likely Safe Fix Locations',
        '- Prefer production source files listed above.',
        '- Avoid test, PoC, docs, generated, lock, and benchmark harness changes in the candidate/final patch.',
    ])
    newline = chr(10)
    return newline.join(report_lines).strip() + newline, json.dumps(findings, ensure_ascii=False, indent=2) + newline


def build_constructed_poc_field(
    *,
    record: Any,
    testcase_plan: str,
    reproducer_script: str,
    reproducer_output: str,
    reproduced_iteration: int,
    verified_reproducer_path: str,
    max_chars: int,
) -> str:
    script_budget = max(4000, max_chars // 2)
    output_budget = max(2000, max_chars // 4)
    plan_budget = max(2000, max_chars // 6)
    lines = [
        f'# Constructed PoC/Test Case for {record.cve_id}',
        '',
        'This PoC/test case was generated by the upstream Test Case/Reproduction agents and verified on the vulnerable checkout.',
        'It is provided to the Direct Repair Agent in the same role as the `poc` field in the no-pre PoC ablation.',
        '',
        '## Reproduction Command',
        f'cd {record.work_dir} && bash {verified_reproducer_path}',
        '',
        '## Expected Vulnerable-Checkout Signal',
        '- Exit code: 0',
        '- Output contains VULNERABILITY_REPRODUCED',
        '- Output does not contain REGRESSION_CONTROL_FAILED',
        f'- Reproduced iteration: {reproduced_iteration}',
        '',
        '## Testcase Plan',
        '<begin_of_testcase_plan>',
        tail_chars(testcase_plan or '(no testcase_plan.md captured)', plan_budget),
        '<end_of_testcase_plan>',
        '',
        '## Verified Reproducer Script',
        '<begin_of_reproducer_sh>',
        tail_chars(reproducer_script, script_budget),
        '<end_of_reproducer_sh>',
        '',
        '## Observed Vulnerable-Checkout Output',
        '<begin_of_reproducer_output>',
        tail_chars(reproducer_output, output_budget),
        '<end_of_reproducer_output>',
    ]
    return '\n'.join(lines).strip() + '\n'


def build_repair_context_summary(
    *,
    record: Any,
    knowledge_findings_text: str,
    knowledge_report: str,
    final_feedback_text: str,
    final_reproducer_output: str,
    reproduced_iteration: int,
    verified_reproducer_path: str,
) -> str:
    findings = parse_json_lenient(knowledge_findings_text)
    feedback = parse_json_lenient(final_feedback_text)
    lines = [
        f'# Repair Context Summary for {record.cve_id}',
        '',
        'This is the only upstream-agent context intended for the Repair + Validation Agent.',
        'It intentionally omits Test Case / PoC Agent refinement history and failed reproduction attempts.',
        '',
        '## Root-Cause Hints',
        f'- Suspected root cause: {findings.get("suspected_root_cause", "unknown")}',
        f'- Security boundary: {findings.get("security_boundary", "unknown")}',
        f'- Candidate files: {json.dumps(findings.get("candidate_files", []), ensure_ascii=False)}',
        f'- Candidate functions: {json.dumps(findings.get("candidate_functions", []), ensure_ascii=False)}',
        f'- Repair constraints: {json.dumps(findings.get("repair_constraints", []), ensure_ascii=False)}',
        '',
        '## Verified Reproduction',
        f'- Reproduced iteration: {reproduced_iteration}',
        f'- Verified reproducer path: {verified_reproducer_path}',
        f'- Reproduction judge status: {feedback.get("status", "unknown")}',
        f'- Oracle quality: {feedback.get("oracle_quality", "unknown")}',
        f'- Public entrypoint OK: {feedback.get("public_entrypoint_ok", "unknown")}',
        f'- Compatibility controls OK: {feedback.get("compatibility_controls_ok", "unknown")}',
        f'- Weak reason: {feedback.get("weak_reason", "")}',
        '- Reproducer contract: exits 0 and prints VULNERABILITY_REPRODUCED only when vulnerable behavior is present and compatibility controls pass.',
        '- Repair validation contract: after the patch, this reproducer should not exit 0, must not print VULNERABILITY_REPRODUCED, and must not print REGRESSION_CONTROL_FAILED.',
        '- If the reproducer exits 2 or prints REGRESSION_CONTROL_FAILED after a patch, treat the patch as overbroad even if the vulnerable signal disappeared.',
        f'- Reproduction evidence: {feedback.get("evidence", "see output tail below")}',
        f'- Expected fixed-state signal and controls: {feedback.get("expected_next_test_signal", "reproducer no longer reports vulnerable behavior while compatibility controls still pass")}',
        '',
        '## Successful Reproducer Output Tail',
        '```',
        tail_chars(final_reproducer_output, 3000),
        '```',
        '',
        '## Existing Test Commands Suggested by Knowledge Agent',
        json.dumps(findings.get('test_commands', []), ensure_ascii=False, indent=2),
    ]
    if not findings:
        lines.extend([
            '',
            '## Fallback Knowledge Report Excerpt',
            tail_chars(knowledge_report, 4000),
        ])
    return '\n'.join(lines).strip() + '\n'


def build_postprocess_args(args: argparse.Namespace, record: Any, candidate_patch: Path, outputs_root: Path) -> argparse.Namespace:
    if args.postprocess_api_key and not os.environ.get(args.postprocess_api_key_env):
        os.environ[args.postprocess_api_key_env] = args.postprocess_api_key
    elif not os.environ.get(args.postprocess_api_key_env):
        fallback_key = args.agent_api_key or os.environ.get(args.agent_api_key_env) or os.environ.get('GLM_API_KEY') or ''
        if fallback_key:
            os.environ[args.postprocess_api_key_env] = fallback_key
    return argparse.Namespace(
        cve_id=record.cve_id,
        dataset=str(args.dataset),
        candidate_patch=str(candidate_patch),
        outputs_root=str(outputs_root),
        model=args.postprocess_model,
        base_url=args.postprocess_base_url,
        api_key_env=args.postprocess_api_key_env,
        prompt=args.postprocess_prompt,
        llm_timeout_seconds=args.postprocess_llm_timeout_seconds,
        max_output_tokens=args.postprocess_max_output_tokens,
        max_patch_chars=args.postprocess_max_patch_chars,
        max_file_context_chars=args.postprocess_max_file_context_chars,
        max_total_file_context_chars=args.postprocess_max_total_file_context_chars,
        context_window_lines=args.postprocess_context_window_lines,
        cleanup_local_image=args.cleanup_local_image,
    )


def run(args: argparse.Namespace) -> Dict[str, Any]:
    start = time.time()
    timeout_profile = apply_benchmark_timeouts(args)
    total_deadline = benchmark_total_deadline(args, start)
    sandbox_runtime = str(os.getenv('PATCHEVAL_RUNTIME', '')).strip().lower() in {'sandbox', 'sandbox_api', 'brainbox'}
    if benchmark_name(args) == 'secbench' and not sandbox_runtime:
        raise RuntimeError(
            'SEC-bench inference must run with PATCHEVAL_RUNTIME=sandbox_api; '
            'local Docker inference is disabled for this adapter.'
        )
    outputs = Path(args.outputs_root)
    for sub in [
        'patches',
        'candidate_patches',
        'agent_logs',
        'process_logs',
        'mas_repro_artifacts',
        'postprocess_raw',
        'subagent_trace_index',
        'subagent_logs',
        'opencode_session_traces',
    ]:
        (outputs / sub).mkdir(parents=True, exist_ok=True)

    record = load_record(Path(args.dataset), args.cve_id, args)
    artifact_dir = f'/workspace/mas_repro/{record.cve_id}'
    repair_context_dir = f'{artifact_dir}/repair_context'
    host_artifact_dir = outputs / 'mas_repro_artifacts' / record.cve_id
    host_repair_context_dir = host_artifact_dir / 'repair_context'
    process_log_path = outputs / 'process_logs' / f'{record.cve_id}.process.json'
    host_artifact_dir.mkdir(parents=True, exist_ok=True)
    host_repair_context_dir.mkdir(parents=True, exist_ok=True)

    result: Dict[str, Any] = {
        'problem_id': record.problem_id,
        'cve_id': record.cve_id,
        'task_id': getattr(record, 'task_id', record.cve_id),
        'benchmark': getattr(record, 'benchmark', benchmark_name(args)),
        'is_success': False,
        'stage': 'initialization',
        'agent': 'full-no-knowledge-chain',
        'agent_model': args.agent_model,
        'agent_base_url': args.agent_base_url,
        'postprocess_model': args.postprocess_model,
        'postprocess_base_url': args.postprocess_base_url,
        'reproduction_passed': False,
        'reproduction_status': '',
        'reproduction_iterations': [],
        'repair_context_summary_path': '',
        'verified_reproducer_path': '',
        'constructed_poc_input_path': '',
        'direct_repair_report_path': '',
        'repair_fit_context_path': '',
        'candidate_patch_path': '',
        'patch_path': '',
        'postprocess_outputs_root': '',
        'postprocess_result': {},
        'static_trace_path': '',
        'static_trace_summary_path': '',
        'static_trace_prepass': {},
        'd_analysis_mas_subagent_trace_index_path': '',
        'd_analysis_mas_subagent_log_manifest_path': '',
        'd_repair_mas_subagent_trace_index_path': '',
        'd_repair_mas_subagent_log_manifest_path': '',
        'error_message': '',
        'total_duration': 0.0,
        'timeout_profile': dict(timeout_profile),
    }
    if total_deadline is not None:
        result['total_timeout_seconds'] = int(timeout_profile['total_timeout_seconds'])
        result['total_deadline_epoch'] = total_deadline

    def persist_partial_result() -> None:
        result['total_duration_so_far'] = time.time() - start
        snapshot = dict(result)
        snapshot['is_partial'] = True
        write_json(process_log_path, snapshot)

    container_id = ''
    container_tag = getattr(args, 'container_name_suffix', 'mas_repro_agents')
    safe_container_tag = re.sub(r'[^A-Za-z0-9_.-]+', '_', container_tag).strip('_') or 'mas_repro_agents'
    container_name = f'bench.{record.problem_id}.{safe_container_tag}.work'
    opencode: Optional[OpenCodeRunner] = None
    reproduced_iteration = 0
    reproduced_iteration_dir = ''
    final_feedback_text = ''
    final_reproducer_output = ''
    artifact_snapshot = ''
    static_trace: Dict[str, Any] = {}
    static_trace_json_text = ''
    static_trace_report = ''
    root_cause_invariant_text = ''
    repair_brief = ''
    pre_mas_semaphore, pre_mas_limit = get_pre_mas_semaphore()
    pre_mas_slot_held = False

    def release_pre_mas_slot(reason: str) -> None:
        nonlocal pre_mas_slot_held
        if pre_mas_semaphore is not None and pre_mas_slot_held:
            pre_mas_semaphore.release()
            pre_mas_slot_held = False
            result['pre_mas_slot_released_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
            result['pre_mas_slot_release_reason'] = reason
            LOGGER.info('released pre-MAS slot cve=%s limit=%s reason=%s', record.cve_id, pre_mas_limit, reason)

    try:
        if pre_mas_semaphore is not None:
            result['stage'] = 'pre_mas_wait'
            result['pre_mas_max_concurrency'] = pre_mas_limit
            persist_partial_result()
            LOGGER.info('waiting for pre-MAS slot cve=%s limit=%s', record.cve_id, pre_mas_limit)
            pre_mas_semaphore.acquire()
            pre_mas_slot_held = True
            result['stage'] = 'pre_mas_slot_acquired'
            result['pre_mas_slot_acquired_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
            persist_partial_result()

        result['stage'] = 'docker_pull'
        persist_partial_result()
        semaphore = threading.Semaphore(1)
        enforce_deadline(total_deadline, 'benchmark total timeout before image preparation')
        if benchmark_name(args) == 'secbench':
            if sandbox_api_client is None or not sandbox_api_client.enabled():
                raise RuntimeError('SEC-bench sandbox runtime was requested, but sandbox_api_client is unavailable')
            pull_image_with_retry(record.image_name, semaphore)
            result['secbench_image_load'] = {
                'runtime': 'sandbox_api',
                'image_name': record.image_name,
                'local_archive_load': 'skipped',
            }
        else:
            pull_image_with_retry(record.image_name, semaphore)

        result['stage'] = 'work_container'
        persist_partial_result()
        enforce_deadline(total_deadline, 'benchmark total timeout before work container')
        container_id = run_work_container_no_mount(record.image_name, record.problem_id, semaphore, safe_container_tag)
        result['container_id'] = container_id
        result['container_name'] = container_name
        persist_partial_result()

        agent_api_key = args.agent_api_key or os.environ.get(args.agent_api_key_env) or os.environ.get('GLM_API_KEY') or DEFAULT_API_KEY
        opencode = OpenCodeRunner(
            container_id=container_id,
            work_dir=record.work_dir,
            model=args.agent_model,
            base_url=args.agent_base_url,
            api_key=agent_api_key,
            opencode_version=args.opencode_version,
            allow_git_diff_fallback=True,
            enable_detailed_logging=not args.quiet,
        )

        setup_semaphore, setup_limit = get_opencode_setup_semaphore()
        if setup_semaphore is not None:
            result['stage'] = 'opencode_setup_wait'
            result['opencode_setup_max_concurrency'] = setup_limit
            persist_partial_result()
            LOGGER.info('waiting for OpenCode setup slot cve=%s limit=%s', record.cve_id, setup_limit)
            setup_semaphore.acquire()
            result['opencode_setup_slot_acquired_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
        try:
            result['stage'] = 'opencode_setup'
            if setup_limit:
                result['opencode_setup_max_concurrency'] = setup_limit
            persist_partial_result()
            enforce_deadline(total_deadline, 'benchmark total timeout before OpenCode setup')
            if not opencode.setup_environment(record, 'default'):
                raise RuntimeError('OpenCode environment setup failed')
            if setup_limit:
                result['stage'] = 'opencode_setup_done'
                persist_partial_result()
        finally:
            if setup_semaphore is not None:
                setup_semaphore.release()
                LOGGER.info('released OpenCode setup slot cve=%s limit=%s', record.cve_id, setup_limit)
        result['stage'] = 'brainbox_container_proxy'
        persist_partial_result()
        container_proxy = start_brainbox_container_proxy(container_id, result)
        if container_proxy:
            opencode._log_process_step('brainbox_container_proxy_ready', container_proxy)
        persist_partial_result()

        result['stage'] = 'oracle_file_isolation'
        persist_partial_result()
        if benchmark_name(args) == 'secbench':
            oracle_isolation = {
                'skipped': True,
                'reason': 'SEC-bench evaluation images do not use PatchEval root-level /workspace oracle files; benchmark harness is exposed through secb.',
            }
        else:
            oracle_isolation = remove_workspace_oracle_files(container_id, record.work_dir)
            remaining_oracle_files = list_workspace_oracle_files(container_id, record.work_dir)
            oracle_isolation['remaining_visible_files'] = remaining_oracle_files
            if remaining_oracle_files:
                raise RuntimeError('oracle files remain visible after isolation: ' + ', '.join(remaining_oracle_files))
        result['oracle_isolation'] = oracle_isolation
        opencode._log_process_step('oracle_file_isolation', oracle_isolation)

        result['stage'] = 'opencode_user_runtime'
        persist_partial_result()
        if benchmark_name(args) == 'secbench':
            runtime_alignment = {
                'skipped': True,
                'reason': (
                    'SEC-bench uses benchmark images with their own exposed harness/runtime; '
                    'PatchEval root-runtime alignment is skipped to avoid failing on unrelated '
                    'root-visible tools such as cargo.'
                ),
            }
        else:
            runtime_alignment = ensure_opencode_user_runtime(container_id)
        result['opencode_user_runtime'] = runtime_alignment
        opencode._log_process_step('opencode_user_runtime', runtime_alignment)

        result['stage'] = 'agent_workspace_permissions'
        persist_partial_result()
        ensure_agent_writable_dir(container_id, artifact_dir)
        ensure_agent_writable_dir(container_id, repair_context_dir)
        opencode._log_process_step('agent_workspace_permissions', {'writable_dirs': [artifact_dir, repair_context_dir]})

        if getattr(args, 'workflow', 'd_analysis_mas') == 'd_analysis_mas':
            enforce_deadline(total_deadline, 'benchmark total timeout before D analysis/repair workflow')
            if pre_mas_slot_held:
                result['stage'] = 'pre_mas_done'
                release_pre_mas_slot('entering_d_analysis_mas')
                persist_partial_result()
            return run_d_analysis_mas_repair_workflow(
                args=args,
                record=record,
                outputs=outputs,
                result=result,
                container_id=container_id,
                opencode=opencode,
                artifact_dir=artifact_dir,
                repair_context_dir=repair_context_dir,
                host_artifact_dir=host_artifact_dir,
                host_repair_context_dir=host_repair_context_dir,
                persist_result=persist_partial_result,
                total_deadline=total_deadline,
            )

        if pre_mas_slot_held:
            result['stage'] = 'pre_mas_done'
            release_pre_mas_slot('entering_static_trace_prepass')
            persist_partial_result()

        result['stage'] = 'static_trace_prepass'
        static_trace, static_trace_json_text, static_trace_report = run_static_trace_prepass(container_id, record, artifact_dir, host_artifact_dir)
        result['static_trace_path'] = str(host_artifact_dir / 'static_trace.json')
        result['static_trace_summary_path'] = str(host_artifact_dir / 'static_trace_summary.md')
        result['static_trace_prepass'] = {
            'schema_version': static_trace.get('schema_version'),
            'confidence': static_trace.get('confidence'),
            'key_files': static_trace.get('key_files', [])[:8],
            'chain_count': len(static_trace.get('candidate_call_chains', [])),
        }
        opencode._log_process_step('static_trace_prepass', result['static_trace_prepass'])

        result['stage'] = 'poc_direction_planner'
        result['knowledge_agent_used'] = False
        reset_worktree(container_id, record.work_dir)

        directions_path = f'{artifact_dir}/poc_directions.json'
        direction_plan_path = f'{artifact_dir}/poc_direction_plan.md'
        planner_prompt = render_template(
            read_text(Path(args.direction_planner_prompt)),
            stage_values(record, artifact_dir, {
                'MAX_DIRECTIONS': str(args.max_poc_directions),
                'STATIC_TRACE_REPORT': tail_chars(static_trace_report, args.max_prompt_artifact_chars),
                'STATIC_TRACE_JSON': tail_chars(static_trace_json_text, args.max_prompt_artifact_chars),
            }),
        )
        try:
            run_opencode_stage(
                opencode,
                stage_name='poc_direction_planner',
                prompt_text=planner_prompt,
                prompt_path=f'/tmp/{record.cve_id}_poc_direction_planner.md',
                message='Plan a small set of candidate PoC directions. Do not write PoCs or repair code.',
                timeout_seconds=args.stage_timeout_seconds,
                host_log_path=outputs / 'agent_logs' / f'{record.cve_id}.poc_direction_planner.log',
                expected_artifacts=[directions_path, direction_plan_path],
            )
        except subprocess.TimeoutExpired:
            if container_files_nonempty(container_id, [directions_path]):
                opencode._log_process_step('poc_direction_planner_timeout_salvage', {'directions_path': directions_path})
            else:
                raise
        poc_directions_text = docker_read_text(container_id, directions_path, missing_ok=True)
        poc_direction_plan = docker_read_text(container_id, direction_plan_path, missing_ok=True)
        if poc_directions_text:
            (host_artifact_dir / 'poc_directions.json').write_text(poc_directions_text, encoding='utf-8')
            result['poc_directions_path'] = str(host_artifact_dir / 'poc_directions.json')
        if poc_direction_plan:
            (host_artifact_dir / 'poc_direction_plan.md').write_text(poc_direction_plan, encoding='utf-8')
            result['poc_direction_plan_path'] = str(host_artifact_dir / 'poc_direction_plan.md')
        poc_directions = parse_poc_directions(poc_directions_text, record.cve_id, args.max_poc_directions)
        result['poc_direction_count'] = len(poc_directions)
        result['poc_directions'] = [{
            'direction_id': item.get('direction_id'),
            'title': item.get('title', ''),
            'oracle_strength': item.get('oracle_strength', ''),
            'confidence': item.get('confidence', ''),
        } for item in poc_directions]

        testcase_stage_records: List[Dict[str, Any]] = []
        for direction_index, direction in enumerate(poc_directions, 1):
            direction_id = sanitize_direction_id(str(direction.get('direction_id', '')), f'dir_{direction_index}')
            direction['direction_id'] = direction_id
            iteration = 1
            iteration_dir = f'{artifact_dir}/directions/{direction_id}/iteration_{iteration}'
            ensure_agent_writable_dir(container_id, iteration_dir)
            host_iter_dir = host_artifact_dir / 'directions' / direction_id / f'iteration_{iteration}'
            host_iter_dir.mkdir(parents=True, exist_ok=True)
            direction_text = json.dumps(direction, ensure_ascii=False, indent=2)

            testcase_knowledge_path = f'{iteration_dir}/testcase_knowledge.md'
            testcase_plan_path = f'{iteration_dir}/testcase_plan.md'
            reproducer_path = f'{iteration_dir}/reproducer.sh'
            poc_spec_path = f'{iteration_dir}/poc_spec.json'
            control_tests_path = f'{iteration_dir}/control_tests.sh'
            oracle_summary_path = f'{iteration_dir}/oracle_summary.md'
            testcase_artifacts = [
                testcase_knowledge_path,
                testcase_plan_path,
                reproducer_path,
                poc_spec_path,
                control_tests_path,
                oracle_summary_path,
            ]

            run_record: Dict[str, Any] = {
                'direction_index': direction_index,
                'direction_id': direction_id,
                'direction': direction,
                'direction_text': direction_text,
                'iteration': iteration,
                'iteration_dir': iteration_dir,
                'testcase_artifacts': testcase_artifacts,
                'testcase_knowledge_path': testcase_knowledge_path,
                'testcase_plan_path': testcase_plan_path,
                'reproducer_path': reproducer_path,
                'poc_spec_path': poc_spec_path,
                'control_tests_path': control_tests_path,
                'oracle_summary_path': oracle_summary_path,
                'status': 'unusable',
                'return_code': None,
                'artifact_dir': str(host_iter_dir),
                'error': '',
                'feedback': {},
            }
            testcase_stage_records.append(run_record)

        direction_runs: List[Dict[str, Any]] = []
        result['testcase_generation_mode'] = 'parallel_wait_all_then_serial_reproduction'
        testcase_workers = max(1, min(len(testcase_stage_records) or 1, int(getattr(args, 'testcase_parallel_workers', args.max_poc_directions) or 1)))
        result['testcase_parallel_workers'] = testcase_workers
        result['stage'] = 'testcase_agents_parallel'
        reset_worktree(container_id, record.work_dir)
        opencode._log_process_step('testcase_agents_parallel_start', {
            'direction_ids': [item.get('direction_id') for item in testcase_stage_records],
            'workers': testcase_workers,
            'policy': 'wait for every testcase agent to finish before deterministic reproduction starts',
        })

        def run_testcase_agent_for_direction(stage_record: Dict[str, Any]) -> Dict[str, Any]:
            direction_id = str(stage_record.get('direction_id') or '')
            iteration_dir = str(stage_record.get('iteration_dir') or '')
            host_iter_dir = Path(str(stage_record.get('artifact_dir') or ''))
            direction_text = str(stage_record.get('direction_text') or '')
            testcase_artifacts = list(stage_record.get('testcase_artifacts') or [])
            run_record = dict(stage_record)
            prompt_path = f'/tmp/{record.cve_id}_testcase_agent_{direction_id}.md'
            testcase_prompt = render_template(
                read_text(Path(args.testcase_prompt)),
                stage_values(record, artifact_dir, {
                    'DIRECTION_ID': direction_id,
                    'POC_DIRECTION': tail_chars(direction_text, args.max_prompt_artifact_chars),
                    'ITERATION_DIR': iteration_dir,
                    'ITERATION': str(stage_record.get('iteration') or 1),
                    'PREVIOUS_FEEDBACK': '(none)',
                    'STATIC_TRACE_REPORT': tail_chars(static_trace_report, args.max_prompt_artifact_chars),
                    'STATIC_TRACE_JSON': tail_chars(static_trace_json_text, args.max_prompt_artifact_chars),
                }),
            )
            try:
                run_opencode_stage(
                    opencode,
                    stage_name=f'testcase_agent_{direction_id}',
                    prompt_text=testcase_prompt,
                    prompt_path=prompt_path,
                    message='Construct one direction-specific vulnerability PoC/test case. Do not repair code.',
                    timeout_seconds=args.stage_timeout_seconds,
                    host_log_path=outputs / 'agent_logs' / f'{record.cve_id}.testcase_agent_{direction_id}.log',
                    expected_artifacts=testcase_artifacts,
                    container_kill_pattern=prompt_path,
                )
            except subprocess.TimeoutExpired as exc:
                if container_files_nonempty(container_id, testcase_artifacts):
                    opencode._log_process_step(f'testcase_agent_{direction_id}_timeout_salvage', {'artifacts': testcase_artifacts})
                else:
                    run_record['error'] = f'testcase timeout: {exc}'
            except Exception as exc:
                run_record['error'] = f'testcase error: {exc}'

            testcase_knowledge = docker_read_text(container_id, str(stage_record.get('testcase_knowledge_path')), missing_ok=True)
            testcase_plan = docker_read_text(container_id, str(stage_record.get('testcase_plan_path')), missing_ok=True)
            reproducer = docker_read_text(container_id, str(stage_record.get('reproducer_path')), missing_ok=True)
            poc_spec = docker_read_text(container_id, str(stage_record.get('poc_spec_path')), missing_ok=True)
            control_tests = docker_read_text(container_id, str(stage_record.get('control_tests_path')), missing_ok=True)
            oracle_summary = docker_read_text(container_id, str(stage_record.get('oracle_summary_path')), missing_ok=True)
            for name, text_value in [
                ('testcase_knowledge.md', testcase_knowledge),
                ('testcase_plan.md', testcase_plan),
                ('reproducer.sh', reproducer),
                ('poc_spec.json', poc_spec),
                ('control_tests.sh', control_tests),
                ('oracle_summary.md', oracle_summary),
            ]:
                if text_value:
                    (host_iter_dir / name).write_text(text_value, encoding='utf-8')
            if control_tests:
                docker_exec(container_id, ['bash', '-lc', f'chmod 0755 {shlex.quote(str(stage_record.get("control_tests_path")))}'], timeout=30)

            run_record.update({
                'testcase_knowledge': testcase_knowledge,
                'testcase_plan': testcase_plan,
                'reproducer': reproducer,
                'poc_spec': poc_spec,
                'control_tests': control_tests,
                'oracle_summary': oracle_summary,
            })
            return run_record

        testcase_completed: List[Dict[str, Any]] = []
        with futures.ThreadPoolExecutor(max_workers=testcase_workers) as executor:
            future_to_stage = {executor.submit(run_testcase_agent_for_direction, item): item for item in testcase_stage_records}
            for future in futures.as_completed(future_to_stage):
                stage_record = future_to_stage[future]
                try:
                    testcase_completed.append(future.result())
                except Exception as exc:
                    failed_record = dict(stage_record)
                    failed_record['status'] = 'unusable'
                    failed_record['error'] = f'testcase worker error: {exc}'
                    testcase_completed.append(failed_record)

        testcase_run_records = sorted(testcase_completed, key=lambda item: int(item.get('direction_index') or 0))
        result['testcase_generation_results'] = [{
            'direction_id': run.get('direction_id'),
            'has_reproducer': bool(str(run.get('reproducer', '')).strip()),
            'has_control_tests': bool(str(run.get('control_tests', '')).strip()),
            'artifact_dir': run.get('artifact_dir'),
            'error': run.get('error', ''),
        } for run in testcase_run_records]
        opencode._log_process_step('testcase_agents_parallel_done', result['testcase_generation_results'])

        for run_record in testcase_run_records:
            direction_id = str(run_record.get('direction_id') or '')
            direction = run_record.get('direction') or {}
            direction_text = str(run_record.get('direction_text') or json.dumps(direction, ensure_ascii=False, indent=2))
            iteration = int(run_record.get('iteration') or 1)
            iteration_dir = str(run_record.get('iteration_dir') or f'{artifact_dir}/directions/{direction_id}/iteration_{iteration}')
            host_iter_dir = Path(str(run_record.get('artifact_dir') or host_artifact_dir / 'directions' / direction_id / f'iteration_{iteration}'))
            reproducer_path = str(run_record.get('reproducer_path') or f'{iteration_dir}/reproducer.sh')
            testcase_knowledge = str(run_record.get('testcase_knowledge') or '')
            testcase_plan = str(run_record.get('testcase_plan') or '')
            reproducer = str(run_record.get('reproducer') or '')
            poc_spec = str(run_record.get('poc_spec') or '')
            control_tests = str(run_record.get('control_tests') or '')
            oracle_summary = str(run_record.get('oracle_summary') or '')

            if not reproducer.strip():
                run_record['status'] = 'unusable'
                run_record['error'] = run_record.get('error') or 'missing reproducer.sh'
                direction_runs.append(run_record)
                result['reproduction_iterations'].append({
                    'direction_id': direction_id,
                    'iteration': iteration,
                    'status': 'unusable',
                    'return_code': None,
                    'reason': run_record['error'],
                })
                reset_worktree(container_id, record.work_dir)
                continue

            reset_worktree(container_id, record.work_dir)
            result['stage'] = f'deterministic_reproducer_{direction_id}'
            return_code, repro_output = run_reproducer(container_id, record.work_dir, reproducer_path, args.reproducer_timeout_seconds)
            repro_output_text = f'return_code={return_code}\n{repro_output}\n'
            docker_write_text(container_id, repro_output_text, f'{iteration_dir}/reproducer_output.txt')
            (host_iter_dir / 'reproducer_output.txt').write_text(repro_output_text, encoding='utf-8')
            run_record['return_code'] = return_code
            run_record['reproducer_output'] = repro_output

            result['stage'] = f'reproduction_agent_{direction_id}'
            reproduction_prompt = render_template(
                read_text(Path(args.reproduction_prompt)),
                stage_values(record, artifact_dir, {
                    'DIRECTION_ID': direction_id,
                    'POC_DIRECTION': tail_chars(direction_text, args.max_prompt_artifact_chars),
                    'ITERATION_DIR': iteration_dir,
                    'ITERATION': str(iteration),
                    'REPRODUCER_PATH': reproducer_path,
                    'TESTCASE_KNOWLEDGE': tail_chars(testcase_knowledge, args.max_prompt_artifact_chars),
                    'TESTCASE_PLAN': tail_chars(testcase_plan, args.max_prompt_artifact_chars),
                    'POC_SPEC': tail_chars(poc_spec, args.max_prompt_artifact_chars),
                    'CONTROL_TESTS': tail_chars(control_tests, args.max_prompt_artifact_chars),
                    'ORACLE_SUMMARY': tail_chars(oracle_summary, args.max_prompt_artifact_chars),
                    'REPRODUCER_RETURN_CODE': str(return_code),
                    'REPRODUCER_OUTPUT': tail_chars(repro_output, args.max_prompt_artifact_chars),
                }),
            )
            try:
                run_opencode_stage(
                    opencode,
                    stage_name=f'reproduction_agent_{direction_id}',
                    prompt_text=reproduction_prompt,
                    prompt_path=f'/tmp/{record.cve_id}_reproduction_agent_{direction_id}.md',
                    message='Validate this direction-specific reproducer and write feedback only. Do not repair code.',
                    timeout_seconds=args.stage_timeout_seconds,
                    host_log_path=outputs / 'agent_logs' / f'{record.cve_id}.reproduction_agent_{direction_id}.log',
                    expected_artifacts=[f'{iteration_dir}/reproduction_feedback.json', f'{iteration_dir}/reproduction_feedback.md'],
                )
            except Exception as exc:
                run_record['error'] = (run_record.get('error') + '; ' if run_record.get('error') else '') + f'reproduction agent error: {exc}'
            feedback_json = docker_read_text(container_id, f'{iteration_dir}/reproduction_feedback.json', missing_ok=True)
            feedback_md = docker_read_text(container_id, f'{iteration_dir}/reproduction_feedback.md', missing_ok=True)
            if feedback_json:
                (host_iter_dir / 'reproduction_feedback.json').write_text(feedback_json, encoding='utf-8')
            if feedback_md:
                (host_iter_dir / 'reproduction_feedback.md').write_text(feedback_md, encoding='utf-8')
            status, parsed_feedback = parse_reproduction_feedback(feedback_json, return_code, repro_output)
            run_record.update({
                'status': status,
                'feedback': parsed_feedback,
                'feedback_json': feedback_json,
                'feedback_md': feedback_md,
            })
            result['reproduction_iterations'].append({
                'direction_id': direction_id,
                'iteration': iteration,
                'status': status,
                'return_code': return_code,
                'feedback': parsed_feedback,
                'output_tail': tail_chars(repro_output, 1200),
            })
            if status in {'reproduced', 'reproduced_but_weak'}:
                result['reproduction_passed'] = True
            direction_runs.append(run_record)
            reset_worktree(container_id, record.work_dir)

        result['direction_results'] = [{
            'direction_id': run.get('direction_id'),
            'status': run.get('status'),
            'return_code': run.get('return_code'),
            'oracle_quality': (run.get('feedback') or {}).get('oracle_quality') if isinstance(run.get('feedback'), dict) else '',
            'public_entrypoint_ok': (run.get('feedback') or {}).get('public_entrypoint_ok') if isinstance(run.get('feedback'), dict) else '',
            'compatibility_controls_ok': (run.get('feedback') or {}).get('compatibility_controls_ok') if isinstance(run.get('feedback'), dict) else '',
            'artifact_dir': run.get('artifact_dir'),
            'error': run.get('error', ''),
        } for run in direction_runs]
        if not direction_runs:
            raise RuntimeError('no PoC directions were attempted')

        result['stage'] = 'invariant_summarizer'
        direction_results_text = direction_runs_for_prompt(direction_runs, args.max_prompt_artifact_chars)
        docker_write_text(container_id, direction_results_text, f'{artifact_dir}/direction_results_for_summarizer.md')
        (host_artifact_dir / 'direction_results_for_summarizer.md').write_text(direction_results_text, encoding='utf-8')
        root_cause_invariant_path = f'{repair_context_dir}/root_cause_invariant.json'
        repair_brief_path = f'{repair_context_dir}/repair_brief.md'
        selected_direction_path = f'{repair_context_dir}/selected_direction.json'
        summarizer_prompt = render_template(
            read_text(Path(args.invariant_summarizer_prompt)),
            stage_values(record, artifact_dir, {
                'REPAIR_CONTEXT_DIR': repair_context_dir,
                'STATIC_TRACE_REPORT': tail_chars(static_trace_report, args.max_prompt_artifact_chars),
                'STATIC_TRACE_JSON': tail_chars(static_trace_json_text, args.max_prompt_artifact_chars),
                'POC_DIRECTIONS': tail_chars(poc_directions_text or json.dumps({'directions': poc_directions}, ensure_ascii=False, indent=2), args.max_prompt_artifact_chars),
                'DIRECTION_RESULTS': tail_chars(direction_results_text, args.max_prompt_artifact_chars),
            }),
        )
        run_opencode_stage(
            opencode,
            stage_name='invariant_summarizer',
            prompt_text=summarizer_prompt,
            prompt_path=f'/tmp/{record.cve_id}_invariant_summarizer.md',
            message='Synthesize all direction results into a clean root-cause invariant and repair brief. Do not repair code.',
            timeout_seconds=args.stage_timeout_seconds,
            host_log_path=outputs / 'agent_logs' / f'{record.cve_id}.invariant_summarizer.log',
            expected_artifacts=[root_cause_invariant_path, repair_brief_path, selected_direction_path],
        )
        root_cause_invariant_text = docker_read_text(container_id, root_cause_invariant_path, missing_ok=True)
        repair_brief = docker_read_text(container_id, repair_brief_path, missing_ok=True)
        selected_direction_text = docker_read_text(container_id, selected_direction_path, missing_ok=True)
        if root_cause_invariant_text:
            (host_repair_context_dir / 'root_cause_invariant.json').write_text(root_cause_invariant_text, encoding='utf-8')
            result['root_cause_invariant_path'] = str(host_repair_context_dir / 'root_cause_invariant.json')
        if repair_brief:
            (host_repair_context_dir / 'repair_brief.md').write_text(repair_brief, encoding='utf-8')
            result['repair_brief_path'] = str(host_repair_context_dir / 'repair_brief.md')
        if selected_direction_text:
            (host_repair_context_dir / 'selected_direction.json').write_text(selected_direction_text, encoding='utf-8')
            result['selected_direction_path'] = str(host_repair_context_dir / 'selected_direction.json')

        invariant = parse_json_lenient(root_cause_invariant_text)
        selected_direction = parse_json_lenient(selected_direction_text)
        selected_direction_id = str(selected_direction.get('selected_direction_id') or invariant.get('selected_direction_id') or '').strip()
        primary_runs = choose_primary_direction_runs(direction_runs)
        if not primary_runs:
            raise RuntimeError('no reproduced direction is available as a C2 primary repair gate')
        selected_run = choose_direction_run(primary_runs, selected_direction_id) or primary_runs[0]
        result['selected_direction_id'] = selected_run.get('direction_id', '')
        result['primary_direction_ids'] = [run.get('direction_id', '') for run in primary_runs]
        result['reproduction_status'] = 'all_primary_reproduced'
        repair_ready = bool(invariant.get('repair_ready')) or bool(primary_runs)
        result['repair_ready'] = repair_ready
        if not repair_ready:
            raise RuntimeError('invariant summarizer marked repair_ready=false and no direction reproduced')

        result['stage'] = 'repair_context_compaction'
        primary_direction_artifacts: Dict[str, Dict[str, Any]] = {}
        for run in primary_runs:
            direction_id = str(run.get('direction_id') or 'direction')
            safe_direction_id = safe_path_segment(direction_id)
            container_direction_dir = f'{repair_context_dir}/primary_directions/{safe_direction_id}'
            host_direction_dir = host_repair_context_dir / 'primary_directions' / safe_direction_id
            host_direction_dir.mkdir(parents=True, exist_ok=True)
            artifacts: Dict[str, Any] = {
                'direction_id': direction_id,
                'artifact_dir': container_direction_dir,
                'host_artifact_dir': str(host_direction_dir),
            }
            if str(run.get('testcase_knowledge', '')).strip():
                path_in_container = f'{container_direction_dir}/testcase_knowledge.md'
                docker_write_text(container_id, run.get('testcase_knowledge', ''), path_in_container)
                (host_direction_dir / 'testcase_knowledge.md').write_text(run.get('testcase_knowledge', ''), encoding='utf-8')
                artifacts['testcase_knowledge_path'] = path_in_container
            if str(run.get('testcase_plan', '')).strip():
                path_in_container = f'{container_direction_dir}/testcase_plan.md'
                docker_write_text(container_id, run.get('testcase_plan', ''), path_in_container)
                (host_direction_dir / 'testcase_plan.md').write_text(run.get('testcase_plan', ''), encoding='utf-8')
                artifacts['testcase_plan_path'] = path_in_container
            if str(run.get('reproducer', '')).strip():
                path_in_container = f'{container_direction_dir}/reproducer.sh'
                docker_write_text(container_id, run.get('reproducer', ''), path_in_container)
                docker_exec(container_id, ['bash', '-lc', f'chmod 0755 {shlex.quote(path_in_container)}'], timeout=30)
                (host_direction_dir / 'reproducer.sh').write_text(run.get('reproducer', ''), encoding='utf-8')
                artifacts['reproducer_path'] = path_in_container
            if str(run.get('control_tests', '')).strip():
                path_in_container = f'{container_direction_dir}/control_tests.sh'
                docker_write_text(container_id, run.get('control_tests', ''), path_in_container)
                docker_exec(container_id, ['bash', '-lc', f'chmod 0755 {shlex.quote(path_in_container)}'], timeout=30)
                (host_direction_dir / 'control_tests.sh').write_text(run.get('control_tests', ''), encoding='utf-8')
                artifacts['control_tests_path'] = path_in_container
            if str(run.get('poc_spec', '')).strip():
                path_in_container = f'{container_direction_dir}/poc_spec.json'
                docker_write_text(container_id, run.get('poc_spec', ''), path_in_container)
                (host_direction_dir / 'poc_spec.json').write_text(run.get('poc_spec', ''), encoding='utf-8')
                artifacts['poc_spec_path'] = path_in_container
            oracle_summary = chr(10).join(part for part in [repair_brief, run.get('oracle_summary', '')] if str(part).strip())
            if oracle_summary.strip():
                path_in_container = f'{container_direction_dir}/oracle_summary.md'
                docker_write_text(container_id, oracle_summary, path_in_container)
                (host_direction_dir / 'oracle_summary.md').write_text(oracle_summary, encoding='utf-8')
                artifacts['oracle_summary_path'] = path_in_container
            primary_direction_artifacts[direction_id] = artifacts

        first_artifacts = primary_direction_artifacts.get(str(selected_run.get('direction_id') or ''), {})
        selected_reproducer_path = first_artifacts.get('reproducer_path', '')
        control_tests_verified_path = first_artifacts.get('control_tests_path', '')
        verified_reproducer_path = selected_reproducer_path
        result['verified_reproducer_path'] = verified_reproducer_path
        result['primary_reproducer_paths'] = [art.get('reproducer_path', '') for art in primary_direction_artifacts.values() if art.get('reproducer_path')]
        result['primary_control_tests_paths'] = [art.get('control_tests_path', '') for art in primary_direction_artifacts.values() if art.get('control_tests_path')]

        if selected_reproducer_path:
            result['poc_spec_path'] = str(host_repair_context_dir / 'primary_directions' / safe_path_segment(selected_run.get('direction_id')) / 'poc_spec.json')
        if control_tests_verified_path:
            result['control_tests_path'] = str(host_repair_context_dir / 'primary_directions' / safe_path_segment(selected_run.get('direction_id')) / 'control_tests.sh')
        if first_artifacts.get('oracle_summary_path'):
            result['oracle_summary_path'] = str(host_repair_context_dir / 'primary_directions' / safe_path_segment(selected_run.get('direction_id')) / 'oracle_summary.md')

        final_reproducer_output = selected_run.get('reproducer_output', '')
        reproduced_iteration = int(selected_run.get('iteration') or 0)
        repair_fit_context = build_repair_fit_context(
            selected_direction_id=selected_direction_id,
            selected_run=selected_run,
            direction_runs=direction_runs,
            primary_runs=primary_runs,
            static_trace=static_trace,
            invariant=invariant,
        )
        repair_fit_context_path = f'{repair_context_dir}/repair_fit_context.md'
        docker_write_text(container_id, repair_fit_context, repair_fit_context_path)
        (host_repair_context_dir / 'repair_fit_context.md').write_text(repair_fit_context, encoding='utf-8')
        result['repair_fit_context_path'] = str(host_repair_context_dir / 'repair_fit_context.md')

        repair_context_contract = build_c1_repair_context_contract(
            record=record,
            static_trace=static_trace,
            invariant=invariant,
            repair_brief=repair_brief,
            selected_direction_id=selected_direction_id,
            selected_run=selected_run,
            direction_runs=direction_runs,
            primary_runs=primary_runs,
            primary_direction_artifacts=primary_direction_artifacts,
            selected_reproducer_path=selected_reproducer_path,
            control_tests_path=control_tests_verified_path,
            repair_context_dir=repair_context_dir,
            artifact_dir=artifact_dir,
            repair_fit_context_path=repair_fit_context_path,
            final_reproducer_output=final_reproducer_output,
            reproduced_iteration=reproduced_iteration,
        )
        repair_context_json_text = json.dumps(repair_context_contract, ensure_ascii=False, indent=2) + chr(10)
        repair_context_json_path = f'{repair_context_dir}/repair_context.json'
        repair_context_contract_path = f'{repair_context_dir}/repair_context_contract.json'
        docker_write_text(container_id, repair_context_json_text, repair_context_json_path)
        docker_write_text(container_id, repair_context_json_text, repair_context_contract_path)
        (host_repair_context_dir / 'repair_context.json').write_text(repair_context_json_text, encoding='utf-8')
        (host_repair_context_dir / 'repair_context_contract.json').write_text(repair_context_json_text, encoding='utf-8')
        result['repair_context_json_path'] = str(host_repair_context_dir / 'repair_context.json')
        result['repair_context_contract_path'] = str(host_repair_context_dir / 'repair_context_contract.json')

        repair_context_summary = c1_repair_context_contract_markdown(repair_context_contract)
        repair_context_summary_path = f'{repair_context_dir}/repair_context_summary.md'
        docker_write_text(container_id, repair_context_summary, repair_context_summary_path)
        (host_repair_context_dir / 'repair_context_summary.md').write_text(repair_context_summary, encoding='utf-8')
        result['repair_context_summary_path'] = str(host_repair_context_dir / 'repair_context_summary.md')

        constructed_poc = build_c1_compact_constructed_poc_field(repair_context_contract, record)
        constructed_poc_path = f'{repair_context_dir}/constructed_poc_input.md'
        docker_write_text(container_id, constructed_poc, constructed_poc_path)
        (host_repair_context_dir / 'constructed_poc_input.md').write_text(constructed_poc, encoding='utf-8')
        result['constructed_poc_input_path'] = str(host_repair_context_dir / 'constructed_poc_input.md')

        result['stage'] = 'direct_repair_agent'
        reset_worktree(container_id, record.work_dir)
        repair_knowledge_report = build_c1_repair_knowledge_digest(repair_context_contract)
        compact_poc_spec_for_repair = json.dumps(repair_context_contract.get('primary_directions', []), ensure_ascii=False, indent=2) + chr(10)
        primary_reproducer_lines = []
        for item in repair_context_contract.get('primary_directions', []):
            regression = item.get('regression_contract', {})
            primary_reproducer_lines.append(f"- {item.get('direction_id', '')}: {regression.get('reproducer_path', '')}")
        compact_reproducer_reference = 'Raw reproducer scripts are not inlined. Every primary reproducer below is a required post-repair gate:' + chr(10) + chr(10).join(primary_reproducer_lines) + chr(10)
        compact_plan_reference = f"Raw testcase plans are not inlined. Use repair_context.json and primary_directions artifacts under: {repair_context_dir}/primary_directions" + chr(10)
        direct_repair_report_path = f'{artifact_dir}/direct_repair_report.md'
        repair_prompt = render_template(
            read_text(Path(args.repair_prompt)),
            stage_values(record, artifact_dir, {
                'REPAIR_CONTEXT_DIR': repair_context_dir,
                'REPRODUCER_PATH': verified_reproducer_path,
                'PRIMARY_REPRODUCER_PATHS': chr(10).join(primary_reproducer_lines),
                'DIRECT_REPAIR_REPORT_PATH': direct_repair_report_path,
                'REPAIR_REPORT_PATH': direct_repair_report_path,
                'REPAIR_CONTEXT_SUMMARY': tail_chars(repair_context_summary, 12000),
                'REPAIR_FIT_CONTEXT': tail_chars(repair_fit_context, 9000),
                'KNOWLEDGE_REPORT': tail_chars(repair_knowledge_report, 5000),
                'CONSTRUCTED_POC': tail_chars(constructed_poc, 7000),
                'REPRODUCER_SCRIPT': compact_reproducer_reference,
                'REPRODUCER_OUTPUT': json.dumps(repair_context_contract.get('validation', {}).get('before_fix_observations', {}), ensure_ascii=False, indent=2) + chr(10),
                'TESTCASE_PLAN': compact_plan_reference,
                'POC_SPEC': tail_chars(compact_poc_spec_for_repair, 8000),
                'CONTROL_TESTS': c1_control_context(repair_context_contract),
                'ORACLE_SUMMARY': c1_oracle_context(repair_context_contract),
                'ROOT_CAUSE_INVARIANT': c1_root_cause_context(repair_context_contract),
                'REPAIR_BRIEF': tail_chars(repair_context_contract.get('vulnerability_summary', {}).get('repair_brief_summary', ''), 2500),
                'REPRODUCTION_STATUS': result.get('reproduction_status', ''),
            }),
        )
        run_opencode_stage(
            opencode,
            stage_name='direct_repair_agent',
            prompt_text=repair_prompt,
            prompt_path=f'/tmp/{record.cve_id}_direct_repair_agent.md',
            message='Repair the CVE using all primary PoC/test-case gates and write /workspace/candidate-cve-fix.patch only.',
            timeout_seconds=args.repair_timeout_seconds,
            host_log_path=outputs / 'agent_logs' / f'{record.cve_id}.direct_repair_agent.log',
            expected_artifacts=['/workspace/candidate-cve-fix.patch'],
            artifact_grace_seconds=20,
        )

        direct_repair_report = docker_read_text(container_id, direct_repair_report_path, missing_ok=True)
        if direct_repair_report:
            (host_artifact_dir / 'direct_repair_report.md').write_text(direct_repair_report, encoding='utf-8')
            result['direct_repair_report_path'] = str(host_artifact_dir / 'direct_repair_report.md')

        result['stage'] = 'candidate_patch_extract'
        candidate_patch = extract_candidate_patch(container_id, record.work_dir)
        if not candidate_patch.strip():
            raise RuntimeError('repair agent produced an empty candidate patch')
        candidate_host_path = outputs / 'candidate_patches' / f'{record.cve_id}.patch'
        candidate_host_path.write_text(candidate_patch, encoding='utf-8')
        result['candidate_patch_path'] = str(candidate_host_path)
        result['candidate_patch_stats'] = simple_patch_stats(candidate_patch)

        result['patch_path_validation'] = assert_submission_patch_paths(candidate_patch)
        exported_patch_path = outputs / 'patches' / f'{record.cve_id}.patch'
        exported_patch_path.write_text(candidate_patch, encoding='utf-8')
        result['patch_path'] = str(exported_patch_path)
        result['patch_stats'] = simple_patch_stats(candidate_patch)
        result['patch_export_source'] = 'candidate_patch_before_postprocess'

        result['stage'] = 'direct_repair_patch_apply'
        result['candidate_patch_apply_for_validation'] = apply_candidate_patch_for_validation(container_id, record.work_dir)

        result['stage'] = 'direct_repair_post_validation'
        validation: Dict[str, Any] = {
            'primary_direction_ids': [run.get('direction_id', '') for run in primary_runs],
            'enforced': not args.allow_repair_validation_failure,
            'failures': [],
            'primary_reproducers': {},
            'primary_control_tests': {},
        }
        for run in primary_runs:
            direction_id = str(run.get('direction_id') or 'direction')
            artifacts = primary_direction_artifacts.get(direction_id, {})
            reproducer_path = artifacts.get('reproducer_path', '')
            if not reproducer_path:
                validation['failures'].append(f'{direction_id} missing primary reproducer path')
                continue
            rc, output = run_reproducer(container_id, record.work_dir, reproducer_path, args.reproducer_timeout_seconds)
            validation['primary_reproducers'][direction_id] = {'path': reproducer_path, 'return_code': rc, 'output_tail': tail_chars(output, 3000)}
            if 'VULNERABILITY_REPRODUCED' in output and 'REGRESSION_CONTROL_FAILED' not in output:
                validation['failures'].append(f'{direction_id} reproducer still reports VULNERABILITY_REPRODUCED after repair')
            if 'REGRESSION_CONTROL_FAILED' in output:
                validation['failures'].append(f'{direction_id} reproducer reports REGRESSION_CONTROL_FAILED after repair')
            control_path = artifacts.get('control_tests_path', '')
            if control_path:
                rc, output = run_reproducer(container_id, record.work_dir, control_path, args.reproducer_timeout_seconds)
                validation['primary_control_tests'][direction_id] = {'path': control_path, 'return_code': rc, 'output_tail': tail_chars(output, 3000)}
                if rc != 0 or 'REGRESSION_CONTROL_FAILED' in output:
                    validation['failures'].append(f'{direction_id} compatibility controls failed after repair')
        validation_text = json.dumps(validation, ensure_ascii=False, indent=2) + chr(10)
        docker_write_text(container_id, validation_text, f'{repair_context_dir}/post_repair_validation.json')
        (host_repair_context_dir / 'post_repair_validation.json').write_text(validation_text, encoding='utf-8')
        result['post_repair_validation'] = validation
        result['post_repair_validation_path'] = str(host_repair_context_dir / 'post_repair_validation.json')
        if validation['failures'] and not args.allow_repair_validation_failure:
            result['postprocess_skipped_reason'] = 'direct_repair_post_validation_failed'
            raise RuntimeError('direct repair post-validation failed: ' + '; '.join(validation['failures']))

        artifact_snapshot = copy_container_artifacts(
            container_id,
            record.cve_id,
            outputs,
            artifact_dir,
            extra_paths=workflow_snapshot_extra_paths(record.work_dir),
        )
        result['artifact_snapshot'] = artifact_snapshot
        if not args.keep_pre_container:
            stop_container(container_name)
            container_id = ''

        if args.skip_postprocess:
            result['stage'] = 'completed_without_postprocess'
            result['is_success'] = True
            result['patch_path'] = str(exported_patch_path)
            return result

        result['stage'] = 'postprocess_existing_mas'
        postprocess_outputs = outputs / 'postprocess_raw' / record.cve_id
        pp_args = build_postprocess_args(args, record, candidate_host_path, postprocess_outputs)
        pp_result = postprocess_runner.run(pp_args)
        result['postprocess_outputs_root'] = str(postprocess_outputs)
        result['postprocess_result'] = pp_result
        if not pp_result.get('is_success'):
            raise RuntimeError('existing MAS postprocessor failed: ' + str(pp_result.get('error_message', '')))
        post_patch = postprocess_outputs / 'patches' / f'{record.cve_id}.patch'
        if not post_patch.exists() or post_patch.stat().st_size == 0:
            raise RuntimeError(f'postprocessor reported success but patch is missing: {post_patch}')
        final_patch_path = outputs / 'patches' / f'{record.cve_id}.patch'
        post_patch_text = post_patch.read_text(encoding='utf-8', errors='replace')
        result['patch_path_validation'] = assert_submission_patch_paths(post_patch_text)
        shutil.copyfile(post_patch, final_patch_path)
        result['patch_path'] = str(final_patch_path)
        result['patch_stats'] = simple_patch_stats(post_patch_text)
        result['stage'] = 'completed'
        result['is_success'] = True
        return result
    except Exception as exc:
        result['error_message'] = str(exc)
        LOGGER.exception('full no-knowledge chain failed')
        return result
    finally:
        result['total_duration'] = time.time() - start
        release_pre_mas_slot('finally')
        if container_id:
            try:
                if not artifact_snapshot:
                    result['artifact_snapshot'] = copy_container_artifacts(
                        container_id,
                        record.cve_id,
                        outputs,
                        artifact_dir,
                        extra_paths=workflow_snapshot_extra_paths(record.work_dir),
                    )
            except Exception as copy_exc:
                result['artifact_snapshot_error'] = str(copy_exc)
            if not args.keep_pre_container:
                try:
                    stop_container(container_name)
                except Exception as cleanup_exc:
                    result['container_cleanup_error'] = str(cleanup_exc)
            else:
                result['kept_pre_container'] = container_name
        if args.cleanup_local_image and not sandbox_runtime:
            try:
                remove_local_image(record.image_name, logger=LOGGER)
                result['image_cleanup_attempted'] = True
            except Exception as image_exc:
                result['image_cleanup_error'] = str(image_exc)
        write_json(process_log_path, result)
        write_jsonl(outputs / 'run_index.jsonl', result)


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--dataset', type=Path, default=OPENCODE_DIR / 'dataset.jsonl')
    parser.add_argument('--outputs-root', type=Path, required=True)
    parser.add_argument('--benchmark', choices=['patcheval', 'secbench'], default='patcheval', help='Benchmark adapter profile used for record loading, prompt rendering, and validation.')
    parser.add_argument('--final-patch-path', default='/workspace/fix.patch', help='Container path where the repair agent must write the selected final unified diff.')
    parser.add_argument('--secbench-image-prefix', default=SECBENCH_IMAGE_PREFIX_DEFAULT)
    parser.add_argument('--secbench-image-template', default=SECBENCH_IMAGE_TEMPLATE_DEFAULT)
    parser.add_argument('--secbench-image-manifest', type=Path, default=ROOT / 'sec-datasets' / 'docker_image_archives' / 'manifest.json')
    parser.add_argument('--total-timeout-seconds', type=int, default=None, help='Override the benchmark profile wall-clock timeout; default is disabled for D14 PatchEval and SEC-bench.')
    parser.add_argument('--secbench-total-timeout-seconds', type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument('--workflow', choices=['d_analysis_mas', 'c2_multi_direction'], default='d_analysis_mas')
    parser.add_argument('--agent-model', default=os.getenv('PATCHEVAL_AGENT_MODEL', DEFAULT_MODEL))
    parser.add_argument('--agent-base-url', default=os.getenv('PATCHEVAL_AGENT_BASE_URL', DEFAULT_BASE_URL))
    parser.add_argument('--agent-api-key-env', default='PATCHEVAL_API_KEY')
    parser.add_argument('--agent-api-key', default=None)
    parser.add_argument('--opencode-version', default=DEFAULT_OPENCODE_VERSION)
    parser.add_argument('--container-name-suffix', default='mas_repro_agents')
    parser.add_argument('--knowledge-prompt', default='', help='Deprecated/no-op: this chain does not run a standalone knowledge agent.')
    parser.add_argument('--direction-planner-prompt', default=str(ROOT / 'prompts' / 'poc_direction_planner_prompt.md'))
    parser.add_argument('--invariant-summarizer-prompt', default=str(ROOT / 'prompts' / 'invariant_summarizer_prompt.md'))
    parser.add_argument('--max-poc-directions', type=int, default=3)
    parser.add_argument('--testcase-parallel-workers', type=int, default=3, help='Run testcase-generation agents in parallel; deterministic reproduction remains serial.')
    parser.add_argument('--testcase-prompt', default=str(ROOT / 'prompts' / 'testcase_agent_prompt.md'))
    parser.add_argument('--reproduction-prompt', default=str(ROOT / 'prompts' / 'reproduction_agent_prompt.md'))
    parser.add_argument('--repair-prompt', default=str(ROOT / 'prompts' / 'direct_repair_agent_prompt.md'))
    parser.add_argument('--analysis-lead-system-prompt', default=str(ROOT / 'prompts' / 'analysis_mas' / 'lead.system.md'))
    parser.add_argument('--analysis-lead-user-prompt', default=str(ROOT / 'prompts' / 'analysis_mas' / 'lead.user.md'))
    parser.add_argument('--analysis-workers-dir', default=str(ROOT / 'prompts' / 'analysis_mas' / 'workers'))
    parser.add_argument('--analysis-tasks-dir', default=str(ROOT / 'prompts' / 'analysis_mas' / 'tasks'))
    parser.add_argument('--analysis-timeout-seconds', type=int, default=None, help='Override the benchmark profile analysis timeout.')
    parser.add_argument('--analysis-closeout-reserve-seconds', type=int, default=900, help='Reserve within the analysis timeout for same-session forced closeout when no artifact exists.')
    parser.add_argument('--analysis-subagent-depth', type=int, default=1)
    parser.add_argument('--d-repair-system-prompt', default=str(ROOT / 'prompts' / 'repair_mas' / 'lead.system.md'))
    parser.add_argument('--d-repair-user-prompt', default=str(ROOT / 'prompts' / 'repair_mas' / 'lead.user.md'))
    parser.add_argument('--repair-mas-agents-dir', default=str(ROOT / 'prompts' / 'repair_mas'))
    parser.add_argument('--experiment-variant', default=os.getenv('PATCHEVAL_EXPERIMENT_VARIANT', 'D13'), choices=['D3', 'D4', 'D13'])
    parser.add_argument('--require-d4-artifacts', action='store_true', help='Fail D4 runs when required refinement/exact-patch artifacts are missing or inconsistent.')
    parser.add_argument('--max-repro-iterations', type=int, default=3)
    parser.add_argument('--stage-timeout-seconds', type=int, default=None, help='Override the benchmark profile per-stage timeout.')
    parser.add_argument('--repair-timeout-seconds', type=int, default=None, help='Override the benchmark profile repair timeout.')
    parser.add_argument('--repair-closeout-reserve-seconds', type=int, default=600, help='Reserve within the repair timeout for same-session forced closeout when no patch or worktree diff exists.')
    parser.add_argument('--reproducer-timeout-seconds', type=int, default=None, help='Override the benchmark profile reproducer timeout.')
    parser.add_argument('--max-prompt-artifact-chars', type=int, default=24000)
    parser.add_argument('--postprocess-model', default='glm-5.2')
    parser.add_argument('--postprocess-base-url', default='http://api.example.invalid/v1')
    parser.add_argument('--postprocess-api-key-env', default='GLM_API_KEY')
    parser.add_argument('--postprocess-api-key', default=None)
    parser.add_argument('--postprocess-prompt', default=str(POSTPROCESS_DIR / 'prompts' / 'llm_postprocess_agent_prompt.md'))
    parser.add_argument('--postprocess-llm-timeout-seconds', type=int, default=180)
    parser.add_argument('--postprocess-max-output-tokens', type=int, default=2048)
    parser.add_argument('--postprocess-max-patch-chars', type=int, default=60000)
    parser.add_argument('--postprocess-max-file-context-chars', type=int, default=8000)
    parser.add_argument('--postprocess-max-total-file-context-chars', type=int, default=40000)
    parser.add_argument('--postprocess-context-window-lines', type=int, default=120)
    parser.add_argument('--skip-postprocess', action='store_true')
    parser.add_argument('--allow-repair-validation-failure', action='store_true', help='Record but do not fail when C1 post-repair generated-PoC/control validation fails.')
    parser.add_argument('--keep-pre-container', action='store_true')
    parser.add_argument('--cleanup-local-image', action='store_true')
    parser.add_argument('--quiet', action='store_true')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run one benchmark vulnerability task through no-knowledge Analysis/Repair MAS.')
    parser.add_argument('--cve-id', required=True)
    add_common_args(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get('is_success') else 2


if __name__ == '__main__':
    raise SystemExit(main())
