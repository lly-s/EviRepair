#!/usr/bin/env bash
set -Eeuo pipefail

# Generic model entrypoint for the existing OpenCode + PatchEval flow.
# The legacy launcher still owns dataset preparation, sandbox creation,
# inference, and evaluation. This wrapper only supplies an explicit model
# endpoint/key and disables its GLM-specific proxy route.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
LEGACY_LAUNCHER="${SCRIPT_DIR}/launch_d4_analysismas_directglm_sandbox.sh"

: "${MODEL:?MODEL is required, for example MODEL=kimi-k3}"
: "${AGENT_BASE_URL:?AGENT_BASE_URL is required, including /v1/chat/completions}"
: "${AGENT_API_KEY:?AGENT_API_KEY is required}"

if [[ ! -x "${LEGACY_LAUNCHER}" ]]; then
  chmod +x "${LEGACY_LAUNCHER}"
fi

# The legacy launcher accepts a base URL and appends /chat/completions during
# its preflight. Remove only that terminal path component; the request sent
# by OpenCode still targets the exact endpoint supplied by the caller.
LEGACY_AGENT_BASE_URL="${AGENT_BASE_URL%/chat/completions}"
if [[ "${LEGACY_AGENT_BASE_URL}" == "${AGENT_BASE_URL}" ]]; then
  echo "AGENT_BASE_URL must end with /chat/completions: ${AGENT_BASE_URL}" >&2
  exit 2
fi

REMOTE_MODEL="${MODEL}"

# OpenCode uses provider/model syntax for its own provider selection. Some
# gateways also use slash-bearing model IDs, for example
# bailian/deepseek-v4.1-flash. Route those through the OpenAI-compatible
# provider while preserving the full remote model ID sent to Chat Completions.
if [[ -n "${OPENCODE_MODEL_REF:-}" ]]; then
  MODEL="${OPENCODE_MODEL_REF}"
elif [[ "${REMOTE_MODEL}" == */* ]]; then
  MODEL="openai/${REMOTE_MODEL}"
else
  MODEL="${REMOTE_MODEL}"
fi

export MODEL
export PATCHEVAL_REMOTE_MODEL="${REMOTE_MODEL}"
export GLM_BASE_URL="${LEGACY_AGENT_BASE_URL}"
export GLM_API_KEY="${AGENT_API_KEY}"
unset GLM_API_BASE

# The gateway rejects Chat Completions requests that combine function tools
# with reasoning_effort for the target GPT model. OpenCode's existing
# openai-compatible provider uses Chat Completions, so disable that optional
# field unless the caller explicitly overrides it.
export PATCHEVAL_OPENCODE_REASONING="${PATCHEVAL_OPENCODE_REASONING:-0}"

# The current cached AI SDK emits the reasoning_effort field with a different
# expression than the legacy runner patch recognizes. Ask the runner to apply
# its provider-package compatibility rewrite during sandbox setup.
export PATCH_EVAL_DROP_REASONING_EFFORT="${PATCH_EVAL_DROP_REASONING_EFFORT:-1}"

# Do not route the model request through the Brainbox proxy unless the caller
# explicitly opts in. The supplied endpoint is the model endpoint.
export PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY="${PATCHEVAL_BRAINBOX_IN_CONTAINER_PROXY:-0}"

# The legacy launcher reads these values from stdin when present, then falls
# back to the corresponding environment variables. Supplying them here keeps
# the invocation non-interactive while leaving the sandbox key explicit.
: "${OPEN_SANDBOX_API_KEY:?OPEN_SANDBOX_API_KEY is required}"
export OPEN_SANDBOX_API_KEY
export SANDBOX_API_KEY="${SANDBOX_API_KEY:-${OPEN_SANDBOX_API_KEY}}"

exec "${LEGACY_LAUNCHER}" "$@"
