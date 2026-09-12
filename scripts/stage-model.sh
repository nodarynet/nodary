#!/usr/bin/env bash
# stage-model.sh — download a model's weights so `nodary model register` can use them.
#
# WHY THIS IS A SCRIPT AND NOT A VERB
#
# nodary's own agent can fetch weights too (`--source remote`, R4-33), but only
# once a manifest exists to verify the download against, and only onto a node
# that already has a `nodary`. Producing that first manifest, or placing
# weights on a box before it ever runs an install, is the air-gapped path and
# it is first-class by design — docs/specs/05-catalog.md §3 — not a fallback.
# This script is the hand: it downloads files and hashes them, nothing more.
#
# Registering is `nodary model register`, which either digests these files
# directly (`--source local`, weights and node are the same machine) or reads
# the manifest this script wrote and hands it to a different node's agent
# (`--source remote`), looks up the image this build pins, and applies a
# configuration document through the same applier `config apply` uses. This
# script used to generate that document itself, which meant two implementations
# of the same arithmetic and one of them shipped in a repository that no install
# places on a customer machine.
#
# FLAT, not a real HuggingFace cache. The agent renders `--model` as the
# *directory* (internal/agent/plan.go), so config.json has to sit at its top
# level. A genuine HF cache holds blobs/, refs/ and snapshots/ instead, and
# would not load — see the note this script prints at the end.
#
# Usage:
#   ./stage-model.sh Qwen/Qwen2.5-0.5B-Instruct
#   ./stage-model.sh <repo> --models-dir /var/lib/nodary/models
#
# No sudo. It only downloads and writes into --models-dir, so it needs write
# access to that directory and nothing else — see the administering guide
# for granting your own user that once, rather than running a downloader as
# root.
set -u

REPO="${1:-}"
MODELS_DIR="/var/lib/nodary/models"
NODE=""
GPU="0"
PORT="8001"
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --models-dir) MODELS_DIR="$2"; shift 2 ;;
    --node)       NODE="$2"; shift 2 ;;
    --gpu)        GPU="$2"; shift 2 ;;
    --port)       PORT="$2"; shift 2 ;;
    *) printf 'unknown argument %q\n' "$1" >&2; exit 2 ;;
  esac
done

if [ -z "$REPO" ]; then
  printf 'usage: %s <org/name> [--node NAME] [--gpu N] [--port P] [--models-dir DIR]\n' "$0" >&2
  printf '       --node, --gpu and --port only fill in the command printed at the end.\n' >&2
  exit 2
fi
for t in curl python3; do
  command -v "$t" >/dev/null 2>&1 || { printf '%s is required\n' "$t" >&2; exit 1; }
done

# A gated repository — every Gemma, Llama and Mistral release — answers 401
# without one. Measured: google/gemma-3n-E2B-it and google/gemma-3-1b-it both
# refuse an anonymous config.json while Qwen/Qwen2.5-0.5B-Instruct redirects to
# a CDN. Accept the license on huggingface.co, then:
#   HF_TOKEN=hf_… ./stage-model.sh google/gemma-3n-E2B-it
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
        printf '    Accept its license at https://huggingface.co/%s, then re-run with\n' "$REPO" >&2
        printf '    HF_TOKEN set to a token that has access:\n' >&2
        printf '      HF_TOKEN=hf_… %s %s\n' "$0" "$REPO" >&2
        ;;
      *) printf '\n  ✘ %s failed (HTTP %s); nothing was staged\n' "$f" "$code" >&2 ;;
    esac
    exit 1
  fi
done

BYTES=$(du -sb "$DIR" | cut -f1)
FILECOUNT=$(find "$DIR" -maxdepth 1 -type f | wc -l)
printf '\n\033[1m== Staged\033[0m  %s file(s), %s bytes\n\n' "$FILECOUNT" "$BYTES"

# The manifest is written here, not only by `nodary model register`: it is
# what lets these bytes register a *different* node with `--source remote`
# without this script's caller ever running `nodary` at all — the machine
# producing the manifest need not be the one that ends up serving it. Plain
# python3 (already a required dependency, not sha256sum, which macOS does not
# ship) so this stays exactly the sha256sum format `nodary` reads and `sha256sum
# -c` checks, without a second implementation of the digest loop to keep in
# sync with internal/agent/staging.go's WriteManifest — `register` recomputes
# and overwrites this file identically when it digests weights already here,
# so the two never have a chance to disagree.
python3 -c '
import hashlib, os, sys
d = sys.argv[1]
names = sorted(n for n in os.listdir(d) if n != "nodary-manifest.sha256")
with open(os.path.join(d, "nodary-manifest.sha256"), "w") as out:
    for n in names:
        h = hashlib.sha256()
        with open(os.path.join(d, n), "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        out.write(f"{h.hexdigest()}  {n}\n")
' "$DIR" || { printf 'could not write the manifest\n' >&2; exit 1; }
printf 'Wrote %s/nodary-manifest.sha256\n\n' "$DIR"

printf 'Next, either:\n\n'
if [ -n "$NODE" ]; then
  printf '  sudo nodary model register %s --node %s --gpu %s --port %s\n' \
    "$REPO" "$NODE" "$GPU" "$PORT"
else
  printf '  sudo nodary model register %s --node NAME --gpu 0 --port 8001\n' "$REPO"
  printf '  (`nodary node list` names the enrolled nodes)\n'
fi
printf '    — registers these weights for the node right here; or\n\n'
printf '  sudo nodary model register %s --source remote \\\n' "$REPO"
printf '      --manifest %s/nodary-manifest.sha256 --node NAME --gpu 0 --port 8001\n' "$DIR"
printf "    — registers %s for a *different* node, whose own agent downloads its\n" "$REPO"
printf '    own copy using the manifest just written, verified against it.\n\n'
printf 'Either way this digests or reuses the files, pins the image this build was\n'
printf 'tested against, and applies a model, a deployment and a route.\n\n'
printf 'Note: the weights are flat in that directory because the agent renders --model as\n'
printf 'the directory itself. A real HuggingFace cache — blobs/, refs/, snapshots/ — would\n'
printf 'not load, even though docs/specs/05-catalog.md §3 says this layout adopts one.\n'
