#!/usr/bin/env python3
"""Official PatchEval sandbox eval with a hard cap on live sandboxes.

The shared evaluator submits every case immediately. Combined with
PATCHEVAL_SANDBOX_START_TIMEOUT=0 (instant wait failure) it created hundreds
of instances before any eval ran. This wrapper:

- waits indefinitely when the start timeout is <= 0
- stops a sandbox if create/wait/start fails after the instance exists
- admits at most PATCHEVAL_EVAL_MAX_SANDBOXES live eval instances (default 50)
- clamps --max_workers to that same cap
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
from pathlib import Path


EVAL_SANDBOX_CAP = max(1, int(os.getenv("PATCHEVAL_EVAL_MAX_SANDBOXES", "50")))
VERIFIED_PATCH_EVAL = Path(
    os.environ.get(
        "VERIFIED_PATCH_EVAL",
        "/path/to/local/resource",
    )
)
OFFICIAL_DIR = VERIFIED_PATCH_EVAL / "patcheval/evaluation"

sys.path.insert(0, str(OFFICIAL_DIR))

import run_evaluation_sandbox_api as official  # noqa: E402

LOGGER = logging.getLogger("eval_capped")


def _best_effort_stop(client, sid: str) -> None:
    if not sid:
        return
    token = sid if str(sid).startswith("sandbox://") else f"sandbox://{sid}"
    try:
        client.stop(token)
    except Exception as exc:
        LOGGER.warning("failed to stop sandbox %s after start error: %s", token, exc)


def _patch_wait_for_running(client) -> None:
    original = client.wait_for_running

    def wait_for_running(sid: str):
        raw = str(os.getenv("PATCHEVAL_SANDBOX_START_TIMEOUT", "900")).strip()
        try:
            timeout = int(raw)
        except ValueError:
            timeout = 900
        try:
            if timeout > 0:
                return original(sid)
            last = {}
            started = time.time()
            last_log = -1
            while True:
                last = client.get_sandbox(sid)
                state_of = getattr(client, "_state_of")
                state = str(state_of(last)).lower()
                if state in {"running", "ready", "started"} or str(last.get("runState", "")).lower() == "running":
                    return last
                if state in {"failed", "error", "terminated", "stopped"}:
                    raise RuntimeError(f"Sandbox {sid} entered state {state}: {last}")
                elapsed = int(time.time() - started)
                if elapsed // 60 != last_log:
                    last_log = elapsed // 60
                    LOGGER.info("Waiting for sandbox %s to become running (%ss, state=%s)", sid, elapsed, state)
                time.sleep(5)
        except Exception:
            _best_effort_stop(client, sid)
            raise

    client.wait_for_running = wait_for_running


class CappedSandboxManager(official.SandboxManager):
    _slots = threading.BoundedSemaphore(EVAL_SANDBOX_CAP)

    def start_container(self, image_name: str, container_name: str, llm_patch: str) -> str | None:
        mapped_image = official.map_verified_image(image_name)
        self._slots.acquire()
        sandbox_id = None
        try:
            sandbox_id = official.sandbox_api_client.create_sandbox(
                mapped_image,
                problem_id=self.cve or container_name,
                modelname="verified-eval",
            )
            official.sandbox_api_client.write_file(sandbox_id, "/workspace/fix.patch", llm_patch or "")
            self._containers[container_name] = sandbox_id
            self.logger.info(
                "Started sandbox %s for %s using %s (live_cap=%s)",
                sandbox_id,
                self.cve,
                mapped_image,
                EVAL_SANDBOX_CAP,
            )
            return container_name
        except Exception as exc:
            self.logger.debug("Failed to start sandbox for %s: %s", self.cve, exc)
            _best_effort_stop(official.sandbox_api_client, sandbox_id)
            self._slots.release()
            return None

    def rm_container(self, container_name: str) -> None:
        try:
            super().rm_container(container_name)
        finally:
            try:
                self._slots.release()
            except ValueError:
                pass


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    _patch_wait_for_running(official.sandbox_api_client)
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=str, required=True)
    parser.add_argument("--patch_file", type=str, required=True)
    parser.add_argument("--input_file", type=str, required=False, default="../datasets/patcheval_verified.json")
    parser.add_argument("--log_level", type=str, required=False, default="INFO")
    parser.add_argument("--max_workers", type=int, default=4, required=False)
    args = parser.parse_args()
    if args.max_workers > EVAL_SANDBOX_CAP:
        LOGGER.warning("clamping eval max_workers from %s to %s", args.max_workers, EVAL_SANDBOX_CAP)
        args.max_workers = EVAL_SANDBOX_CAP

    import run_evaluation as official_eval

    official_eval.DockerManager = CappedSandboxManager
    official_eval.args = args
    official_eval.main()


if __name__ == "__main__":
    main()
