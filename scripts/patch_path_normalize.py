"""Rewrite model-produced unified diffs onto repository-relative paths.

MiniMax often emits `/workspace/<repo>/...` or `/tmp/<basename>.patched`
instead of workdir-relative paths. The extractor then rejects the patch, or
`git apply` fails on a clean tree. This module only remaps paths that can be
tied to a unique file in `git ls-files`; it does not invent hunks.
"""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath
from typing import Iterable, List, Sequence

TEMP_SUFFIXES = (
    ".original",
    ".orig",
    ".patched",
    ".fixed",
    ".bak",
    ".new",
    ".old",
    ".copy",
)


def decode_git_patch_path(path_token: str) -> str:
    path = path_token.strip()
    if not path:
        return ""
    if path in {"/dev/null", "dev/null"}:
        return ""
    if len(path) >= 2 and path[0] in {'"', "'"} and path[-1] == path[0]:
        try:
            parts = shlex.split(path)
            if parts:
                path = parts[0]
        except ValueError:
            path = path[1:-1]
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def strip_temp_filename(name: str) -> str:
    lowered = name
    for suffix in TEMP_SUFFIXES:
        if lowered.endswith(suffix):
            stem = lowered[: -len(suffix)]
            return stem or name
    if "_fixed" in name:
        head, tail = name.rsplit("_fixed", 1)
        if tail.startswith(".") or tail == "":
            return head + tail
    if "_patched" in name:
        head, tail = name.rsplit("_patched", 1)
        if tail.startswith(".") or tail == "":
            return head + tail
    return name


def _unique_suffix_match(path: str, repo_files: Sequence[str]) -> str | None:
    parts = PurePosixPath(path).parts
    if not parts:
        return None
    for length in range(len(parts), 0, -1):
        suffix = "/".join(parts[-length:])
        hits = [item for item in repo_files if item == suffix or item.endswith("/" + suffix)]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            return None
    return None


def remap_patch_path(path: str, work_dir: str = "", repo_files: Iterable[str] | None = None) -> str:
    files = [item.replace("\\", "/").lstrip("./") for item in (repo_files or []) if item.strip()]
    repo_set = set(files)
    raw = decode_git_patch_path(path)
    if not raw:
        return ""
    candidate = raw
    work = work_dir.replace("\\", "/").rstrip("/")
    if work:
        prefix = work + "/"
        if candidate == work:
            candidate = ""
        elif candidate.startswith(prefix):
            candidate = candidate[len(prefix) :]
    if candidate.startswith("/workspace/"):
        candidate = candidate[len("/workspace/") :]
        repo_name = PurePosixPath(work).name if work else ""
        if repo_name and candidate.startswith(repo_name + "/"):
            candidate = candidate[len(repo_name) + 1 :]
    elif candidate.startswith("workspace/"):
        candidate = candidate[len("workspace/") :]
    if candidate.startswith("/tmp/") or candidate.startswith("tmp/"):
        candidate = strip_temp_filename(PurePosixPath(candidate).name)
    candidate = candidate.lstrip("/")
    while candidate.startswith("./"):
        candidate = candidate[2:]
    if not candidate:
        return raw.lstrip("/")
    if candidate in repo_set:
        return candidate
    if files:
        matched = _unique_suffix_match(candidate, files)
        if matched:
            return matched
        base = strip_temp_filename(PurePosixPath(candidate).name)
        hits = [item for item in files if PurePosixPath(item).name == base]
        if len(hits) == 1:
            return hits[0]
    return candidate


def _rewrite_header_line(raw: str, mapper) -> str:
    if raw.startswith("diff --git "):
        try:
            tokens = shlex.split(raw[len("diff --git ") :])
        except ValueError:
            tokens = raw[len("diff --git ") :].split()
        if len(tokens) >= 2:
            left = mapper(decode_git_patch_path(tokens[0]))
            right = mapper(decode_git_patch_path(tokens[1]))
            if left and right:
                return f"diff --git a/{left} b/{right}"
        return raw
    if raw.startswith("--- ") or raw.startswith("+++ "):
        marker = raw[:4]
        rest = raw[4:]
        path_token, sep, trailer = rest.partition("\t")
        mapped = mapper(decode_git_patch_path(path_token))
        if not mapped:
            return raw
        prefix = "a/" if marker == "--- " else "b/"
        rewritten = f"{marker}{prefix}{mapped}"
        if sep:
            rewritten += "\t" + trailer
        return rewritten
    if raw.startswith("rename from ") or raw.startswith("rename to "):
        kind, path = raw.split(" ", 2)[0] + " " + raw.split(" ", 2)[1], raw.split(" ", 2)[2]
        mapped = mapper(decode_git_patch_path(path))
        if mapped:
            return f"{kind} {mapped}"
    return raw


def normalize_candidate_patch_paths(
    patch_text: str,
    *,
    work_dir: str = "",
    repo_files: Iterable[str] | None = None,
) -> str:
    files = list(repo_files or [])

    def mapper(path: str) -> str:
        return remap_patch_path(path, work_dir=work_dir, repo_files=files)

    ended_with_newline = patch_text.endswith("\n")
    lines = patch_text.splitlines()
    rewritten: List[str] = [_rewrite_header_line(line, mapper) for line in lines]
    text = "\n".join(rewritten)
    if ended_with_newline or patch_text.endswith("\n"):
        text += "\n"
    return text
