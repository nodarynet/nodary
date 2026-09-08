#!/usr/bin/env bash
# stage-model.sh — place a model's weights the way `source: local` expects.
#
# WHY THIS IS A SCRIPT AND NOT A VERB
#
# nodary cannot download weights. R4-33 (`source: remote` staging) is unbuilt;
# R4-34 (`source: local`) is what exists, and it verifies weights an operator
# placed rather than fetching them. That is the air-gapped path and it is
# first-class by design — docs/specs/05-catalog.md §3 — so staging by hand is
# the supported flow, not a workaround. This script is the hand.
#
# WHAT IT DOES
#
#   1. Downloads a HuggingFace repository's files, flat, into
#      <models-dir>/hub/models--<org>--<name>/
#   2. Writes nodary-manifest.sha256 there, in `sha256sum` format, which is what
#      internal/agent/staging.go reads and what `sha256sum -c` checks without
#      nodary installed at all.
#   3. Prints the catalog entry to apply, including the manifest's own digest —
#      the catalog pins that so the digest list and the files it describes
#      cannot both be replaced together.
#
# FLAT, not a real HuggingFace cache. The agent renders `--model` as the
# *directory* (internal/agent/plan.go), so config.json has to sit at its top
# level. A genuine HF cache holds blobs/, refs/ and snapshots/ instead, and
# would not load — see the note this script prints at the end.
#
# Usage:
#   sudo ./scripts/stage-model.sh Qwen/Qwen2.5-0.5B-Instruct
#   sudo ./scripts/stage-model.sh <repo> --models-dir /var/lib/nodary/models
set -u

REPO="${1:-}"
MODELS_DIR="/var/lib/nodary/models"
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --models-dir) MODELS_DIR="$2"; shift 2 ;;
    *) printf 'unknown argument %q\n' "$1" >&2; exit 2 ;;
  esac
done

if [ -z "$REPO" ]; then
  printf 'usage: %s <org/name> [--models-dir DIR]\n' "$0" >&2
  exit 2
fi
for t in curl python3 sha256sum; do
  command -v "$t" >/dev/null 2>&1 || { printf '%s is required\n' "$t" >&2; exit 1; }
done

# A gated repository — every Gemma, Llama and Mistral release — answers 401
# without one. Measured: google/gemma-3n-E2B-it and google/gemma-3-1b-it both
# refuse an anonymous config.json while Qwen/Qwen2.5-0.5B-Instruct redirects to
# a CDN. Accept the licence on huggingface.co, then:
#   sudo HF_TOKEN=hf_… ./scripts/stage-model.sh google/gemma-3n-E2B-it
AUTH=()
if [ -n "${HF_TOKEN:-}" ]; then
  AUTH=(-H "Authorization: Bearer $HF_TOKEN")
  printf '  using HF_TOKEN for a gated repository\n'
fi

DIR="$MODELS_DIR/hub/models--${REPO//\//--}"
printf '\033[1m== Staging %s\033[0m\n  into %s\n\n' "$REPO" "$DIR"

# The file list, from the API rather than guessed, so a repository that adds a
# shard does not need this script edited.
#
# Listing succeeds anonymously even for a gated repository — measured: the API
# answers for google/gemma-3n-E2B-it and the *download* is what returns 401. So
# the gate is caught below, at the first file, not here.
FILES=$(curl -fsSL "${AUTH[@]}" "https://huggingface.co/api/models/$REPO" | python3 -c '
import json, sys
r = json.load(sys.stdin)
names = [f["rfilename"] for f in r.get("siblings", [])]
# Weights are published in more than one format. Taking both doubles a download
# for files that hold the same tensors, and safetensors is what vLLM prefers.
if any(n.endswith(".safetensors") for n in names):
    names = [n for n in names if not n.endswith((".bin", ".pth", ".msgpack", ".h5"))]
# Flat: the agent points --model at this directory, so nothing may live in a
# subdirectory of it.
print("\n".join(n for n in names if "/" not in n))
') || { printf 'could not read the file list for %s\n' "$REPO" >&2; exit 1; }

[ -n "$FILES" ] || { printf 'no files to stage\n' >&2; exit 1; }

mkdir -p "$DIR" || exit 1
for f in $FILES; do
  if [ -s "$DIR/$f" ]; then
    printf '  = %s (already present)\n' "$f"
    continue
  fi
  printf '  ↓ %s\n' "$f"
  # -C - resumes a partial file; --fail so an HTML error page never lands where
  # a tensor should be.
  if ! curl -fL --progress-bar -C - "${AUTH[@]}" -o "$DIR/$f" \
       "https://huggingface.co/$REPO/resolve/main/$f"; then
    code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" \
      "https://huggingface.co/$REPO/resolve/main/$f")
    case "$code" in
      401|403)
        # The common case, and worth naming: every Gemma, Llama and Mistral
        # release is gated, and "`.gitattributes` failed" says nothing about why.
        printf '\n  ✘ %s is gated (HTTP %s).\n' "$REPO" "$code" >&2
        printf '    Accept its licence at https://huggingface.co/%s, then re-run with\n' "$REPO" >&2
        printf '    HF_TOKEN set to a token that has access:\n' >&2
        printf '      sudo HF_TOKEN=hf_… %s %s\n' "$0" "$REPO" >&2
        ;;
      *) printf '\n  ✘ %s failed (HTTP %s); nothing was staged\n' "$f" "$code" >&2 ;;
    esac
    exit 1
  fi
done

# The manifest, in the format `sha256sum -c` reads. Sorted, so re-running
# produces the same bytes and therefore the same manifest digest.
printf '\n  writing %s\n' "$(basename "$DIR")/nodary-manifest.sha256"
( cd "$DIR" && find . -type f ! -name 'nodary-manifest.sha256' -printf '%P\n' \
    | LC_ALL=C sort | xargs sha256sum > nodary-manifest.sha256 ) || exit 1

MANIFEST_SHA=$(sha256sum "$DIR/nodary-manifest.sha256" | cut -d' ' -f1)
BYTES=$(du -sb "$DIR" | cut -f1)
FILECOUNT=$(wc -l < "$DIR/nodary-manifest.sha256")

printf '\n\033[1m== Staged\033[0m  %s file(s), %s bytes\n' "$FILECOUNT" "$BYTES"
printf '   manifest_sha256 = %s\n\n' "$MANIFEST_SHA"

cat <<EOF
Add this to a configuration document and apply it with:

  sudo nodary config apply <file> --yes --justify "staging $REPO"

[[model]]
id              = "$REPO"
backend         = "vllm"
source          = "local"
artifact        = "weights"
manifest_sha256 = "$MANIFEST_SHA"
total_bytes     = $BYTES

Then a deployment naming this node and its GPU, and a route to serve it under.
\`nodary agent plan\` shows what the node would run before anything starts.

Note: the weights are flat in that directory because the agent renders
\`--model\` as the directory itself. A real HuggingFace cache — blobs/, refs/,
snapshots/ — would not load, even though docs/specs/05-catalog.md §3 says this
layout adopts one. That gap is real and is recorded against R4-34.
EOF
