from __future__ import annotations

import concurrent.futures as futures
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List


class StageSoftTimeout(subprocess.TimeoutExpired):
    """The exploration portion ended so the same session can close out."""


class StageMissingArtifact(RuntimeError):
    """A stage returned normally without its required delivery artifact."""


def forced_closeout_reserve(total_seconds: int, requested_seconds: int) -> int:
    total = max(1, int(total_seconds))
    requested = max(0, int(requested_seconds))
    return min(requested, max(0, total - 60))


def artifact_watchdog_action(*, artifact_ready: bool, remaining_seconds: float, closeout_reserve_seconds: int) -> str:
    if remaining_seconds <= 0:
        return 'complete_with_artifact' if artifact_ready else 'hard_timeout'
    if closeout_reserve_seconds > 0 and remaining_seconds <= closeout_reserve_seconds and not artifact_ready:
        return 'same_session_closeout'
    # An early artifact is a checkpoint. It never stops the running agent.
    return 'continue'


def extract_root_session_id_from_jsonl(text: str) -> str:
    """Return the top-level OpenCode run session, never a nested Task session."""
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if not line.startswith('{'):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        session_id = str(event.get('sessionID') or '')
        if session_id.startswith('ses_'):
            return session_id
    return ''


def extract_root_session_id_from_log(path: Path) -> str:
    try:
        return extract_root_session_id_from_jsonl(path.read_text(encoding='utf-8'))
    except OSError:
        return ''


def extract_root_session_id_from_session_list(text: str, work_dir: str = '') -> str:
    """Select the newest top-level session from OpenCode's JSON session list."""
    payload: Any = None
    stripped = (text or '').strip()
    candidates = [stripped]
    for marker in ('[', '{'):
        offset = stripped.find(marker)
        if offset > 0:
            candidates.append(stripped[offset:])
    for candidate in candidates:
        if not candidate:
            continue
        try:
            payload = json.loads(candidate)
            break
        except json.JSONDecodeError:
            continue
    if isinstance(payload, dict):
        records = payload.get('sessions') or payload.get('data') or [payload]
    else:
        records = payload
    if not isinstance(records, list):
        return ''

    roots: List[tuple[Dict[str, Any], int]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        session_id = str(record.get('id') or record.get('sessionID') or record.get('session_id') or '')
        parent_id = record.get('parentID') or record.get('parentId') or record.get('parent_id')
        if session_id.startswith('ses_') and not parent_id:
            roots.append((record, index))
    if not roots:
        return ''

    expected_dir = str(work_dir or '').rstrip('/')
    if expected_dir:
        matching = []
        for record, index in roots:
            directory = str(record.get('directory') or record.get('path') or record.get('worktree') or '').rstrip('/')
            if directory == expected_dir:
                matching.append((record, index))
        if matching:
            roots = matching

    def recency(item: tuple[Dict[str, Any], int]) -> tuple[float, str, int]:
        record, index = item
        time_info = record.get('time') if isinstance(record.get('time'), dict) else {}
        raw = (
            time_info.get('updated')
            or record.get('updatedAt')
            or record.get('updated_at')
            or time_info.get('created')
            or record.get('createdAt')
            or record.get('created_at')
            or 0
        )
        try:
            numeric = float(raw)
        except (TypeError, ValueError):
            numeric = 0.0
        return numeric, str(raw), -index

    selected, _ = max(roots, key=recency)
    return str(selected.get('id') or selected.get('sessionID') or selected.get('session_id') or '')


def build_opencode_run_command(
    *,
    opencode_bin: str,
    model: str,
    message: str,
    prompt_path: str = '',
    resume_session_id: str = '',
) -> str:
    cmd_parts = [
        shlex.quote(opencode_bin),
        'run',
        '-m',
        shlex.quote(model),
        '--dangerously-skip-permissions',
        '--format',
        'json',
    ]
    if resume_session_id:
        cmd_parts.extend(['--session', shlex.quote(resume_session_id)])
    elif prompt_path:
        cmd_parts.extend(['--file', shlex.quote(prompt_path)])
    cmd_parts.extend(['--', shlex.quote(message)])
    return ' '.join(cmd_parts)


def host_write_optional(path: Path, text: str) -> None:
    if not text:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as handle:
        handle.write(text)
        temporary_path = Path(handle.name)
    temporary_path.replace(path)


def host_write_optional_files(files: Dict[Path, str], max_workers: int = 4) -> List[str]:
    """Write independent artifacts concurrently; the mapping guarantees one writer per path."""
    nonempty = {Path(path): text for path, text in files.items() if text}
    if not nonempty:
        return []
    with futures.ThreadPoolExecutor(max_workers=min(max(1, max_workers), len(nonempty))) as executor:
        jobs = [executor.submit(host_write_optional, path, text) for path, text in nonempty.items()]
        for job in futures.as_completed(jobs):
            job.result()
    return [str(path) for path in sorted(nonempty)]


PATCHEVAL_COMMAND_BUDGET_PLUGIN = './.opencode/plugins/patcheval-command-budget.js'


def dependency_command_budget_plugin_source() -> str:
    return r'''import fs from "node:fs"
import path from "node:path"

const active = new Map()
let serial = Promise.resolve()

function withStateLock(fn) {
  const next = serial.then(fn, fn)
  serial = next.catch(() => {})
  return next
}

function positiveInt(name, fallback) {
  const parsed = Number.parseInt(process.env[name] || "", 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function classifyInstall(command) {
  const normalized = String(command || "").replace(/\s+/g, " ").trim().toLowerCase()
  const patterns = [
    ["download", /(?:^|[;&|]\s*|\s)(?:curl|wget|aria2c|git\s+clone)\b/],
    ["pip", /(?:^|[;&|]\s*|\s)(?:python\d*(?:\.\d+)?\s+-m\s+pip|pip\d*(?:\.\d+)?)\s+install\b/],
    ["npm", /(?:^|[;&|]\s*|\s)(?:npm\s+(?:install|i|ci)|yarn\s+(?:install|add)|pnpm\s+(?:install|add))\b/],
    ["system-package", /(?:^|[;&|]\s*|\s)(?:apt-get|apt|apk|dnf|yum|zypper|pacman)\s+(?:install|update|upgrade|add)\b/],
    ["python-env", /(?:^|[;&|]\s*|\s)(?:conda|mamba|micromamba|poetry|pipenv|uv)\s+(?:install|sync|add|create)\b/],
    ["runtime-bootstrap", /(?:^|[;&|]\s*|\s)(?:python\d*(?:\.\d+)?\s+-m\s+(?:ensurepip|venv)|virtualenv|pyenv\s+install|asdf\s+install|nvm\s+install)\b/],
    ["language-toolchain", /(?:^|[;&|]\s*|\s)(?:bundle\s+install|go\s+mod\s+download|cargo\s+(?:install|fetch)|rustup\s+(?:install|update|toolchain))\b/],
  ]
  for (const [kind, pattern] of patterns) {
    if (pattern.test(normalized)) return { kind, key: `${kind}:${normalized.slice(0, 400)}` }
  }
  return null
}

function emptyState() {
  return { used_seconds: 0, reserved_seconds: 0, attempts: 0, consecutive_failures: {}, history: [] }
}

function readState(statePath) {
  try {
    return { ...emptyState(), ...JSON.parse(fs.readFileSync(statePath, "utf8")) }
  } catch {
    return emptyState()
  }
}

function writeState(statePath, state) {
  fs.mkdirSync(path.dirname(statePath), { recursive: true })
  const temporary = `${statePath}.${process.pid}.tmp`
  fs.writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 })
  fs.renameSync(temporary, statePath)
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`
}

function blockedCommand(reason) {
  return `printf '%s\\n' ${shellQuote(`[patcheval command budget] ${reason}`)} >&2; exit 124`
}

export default async () => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool !== "bash") return
    const command = output.args?.command
    if (process.env.PATCHEVAL_FORCE_CLOSEOUT === "1") {
      output.args.command = blockedCommand("all shell commands are disabled during forced closeout; use the Write tool now to deliver the required artifact from existing session evidence")
      return
    }
    const classified = classifyInstall(command)
    if (!classified) return
    await withStateLock(async () => {
      const statePath = process.env.PATCHEVAL_COMMAND_BUDGET_STATE || "/tmp/patcheval-command-budget.json"
      const totalLimit = positiveInt("PATCHEVAL_DEPENDENCY_TOTAL_SECONDS", 900)
      const singleLimit = positiveInt("PATCHEVAL_DEPENDENCY_SINGLE_COMMAND_SECONDS", 300)
      const failureLimit = positiveInt("PATCHEVAL_DEPENDENCY_MAX_CONSECUTIVE_FAILURES", 2)
      const state = readState(statePath)
      const failures = Number(state.consecutive_failures?.[classified.key] || 0)
      const remaining = totalLimit - Number(state.used_seconds || 0) - Number(state.reserved_seconds || 0)
      if (failures >= failureLimit) {
        output.args.command = blockedCommand(`the same ${classified.kind} operation failed ${failures} consecutive times; change validation strategy`)
        return
      }
      if (remaining <= 0) {
        output.args.command = blockedCommand(`the ${totalLimit}s dependency/toolchain recovery budget is exhausted; use static analysis or a minimal existing harness`)
        return
      }
      const allowance = Math.max(1, Math.min(singleLimit, remaining))
      state.reserved_seconds = Number(state.reserved_seconds || 0) + allowance
      state.attempts = Number(state.attempts || 0) + 1
      state.history = Array.isArray(state.history) ? state.history.slice(-49) : []
      state.history.push({ event: "start", at: new Date().toISOString(), kind: classified.kind, key: classified.key, allowance_seconds: allowance })
      writeState(statePath, state)
      active.set(input.callID, { ...classified, statePath, allowance, started: Date.now() })
      output.args.command = `timeout -k 10s ${allowance}s bash -lc ${shellQuote(command)}`
    })
  },
  "tool.execute.after": async (input, output) => {
    if (input.tool !== "bash") return
    const attempt = active.get(input.callID)
    if (!attempt) return
    active.delete(input.callID)
    await withStateLock(async () => {
      const state = readState(attempt.statePath)
      const elapsed = Math.max(0, Math.ceil((Date.now() - attempt.started) / 1000))
      state.reserved_seconds = Math.max(0, Number(state.reserved_seconds || 0) - attempt.allowance)
      state.used_seconds = Number(state.used_seconds || 0) + elapsed
      const exitCode = Number(output.metadata?.exit ?? 0)
      const failed = Number.isFinite(exitCode) && exitCode !== 0
      state.consecutive_failures = state.consecutive_failures || {}
      state.consecutive_failures[attempt.key] = failed ? Number(state.consecutive_failures[attempt.key] || 0) + 1 : 0
      state.history = Array.isArray(state.history) ? state.history.slice(-49) : []
      state.history.push({ event: "finish", at: new Date().toISOString(), kind: attempt.kind, key: attempt.key, elapsed_seconds: elapsed, exit_code: exitCode })
      writeState(attempt.statePath, state)
    })
  },
})
'''


def install_command_budget_plugin(config: Dict[str, Any], files: Dict[str, str], work_dir: str) -> str:
    plugin_path = f'{work_dir}/.opencode/plugins/patcheval-command-budget.js'
    plugins = config.setdefault('plugin', [])
    if not isinstance(plugins, list):
        plugins = []
        config['plugin'] = plugins
    if PATCHEVAL_COMMAND_BUDGET_PLUGIN not in plugins:
        plugins.append(PATCHEVAL_COMMAND_BUDGET_PLUGIN)
    files[plugin_path] = dependency_command_budget_plugin_source()
    return plugin_path
