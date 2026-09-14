#!/bin/sh
# R5-16 end to end on a development machine, with no root and no release key.
#
# The chain this exercises spans three languages and cannot be reached from a Go
# test: a key stamped by `-ldflags -X`, a signature produced by the real
# `minisign`, and a control plane that verifies before it publishes. Each half
# has unit tests; what nothing else proves is that the halves agree.
#
# It has already earned its keep twice. `-X` against a package the binary does
# not link is silently ignored, and `minisign -S` without `-l` produces a
# prehashed signature nodary refuses — neither is visible from inside Go.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GO=${GO:-go}
work=$(mktemp -d "${TMPDIR:-/tmp}/nodary-selfupgrade.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

pass() { printf '  \033[32m✔\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✘\033[0m %s\n' "$1"; exit 1; }

command -v minisign >/dev/null 2>&1 || { printf 'minisign is not installed; skipping\n'; exit 0; }

version=9.9.9-selfupgrade
platform=linux-amd64

printf 'keys\n'
# -W: passwordless, the way the release pipeline's key must be.
(cd "$work" && minisign -G -W -p release.pub -s release.key >/dev/null 2>&1) \
    || fail "could not generate a throwaway minisign key"
# The payload line only: ParsePublicKey takes either form, and a newline in an
# -X value is a quoting problem with no upside.
payload=$(tail -1 "$work/release.pub")
pass "throwaway release key generated"

printf 'build\n'
(cd "$root" && CGO_ENABLED=0 "$GO" build \
    -ldflags "-s -w \
        -X github.com/nodarynet/nodary/internal/buildinfo.Version=$version \
        -X github.com/nodarynet/nodary/internal/release.TrustedKey=$payload" \
    -o "$work/nodary" ./cmd/nodary) || fail "build failed"
# The trap this exists for: -X against a package nothing links is a silent
# no-op, and the binary ships its placeholder.
strings "$work/nodary" | grep -qF "$payload" \
    || fail "the release key was not stamped into the binary; -X was silently ignored"
pass "binary built with the release key stamped in"

printf 'install layout\n'
opt="$work/opt/nodary/$version"
mkdir -p "$opt" "$work/var/lib/nodary" "$work/etc/nodary"
cp "$work/nodary" "$opt/nodary"
# `-l`: stock minisign produces a prehashed signature that nodary refuses.
minisign -S -l -s "$work/release.key" -m "$opt/nodary" -x "$opt/nodary.minisig" >/dev/null 2>&1 \
    || fail "could not sign the binary"
pass "binary installed and signed, the way install.sh leaves it"

printf 'publish\n'
db="$work/var/lib/nodary/nodary.db"
NODARY_AUDIT_SINKS=none "$work/nodary" upgrade \
    --root "$work" --db "$db" --secret-key "$work/secret.key" \
    --credentials "$work/credentials" --user "" --offline \
    --yes --justify "self-upgrade simulation" >"$work/upgrade.log" 2>&1 \
    || { sed 's/^/    /' "$work/upgrade.log"; fail "upgrade failed"; }
grep -q "verified against the release key" "$work/upgrade.log" \
    || { sed 's/^/    /' "$work/upgrade.log"; fail "the upgrade did not publish a verified binary"; }
pass "control plane verified its own binary and published it"

served="$work/var/lib/nodary/dist/nodary-$version-$platform"
[ -x "$served" ] || fail "the mirror holds no binary at $served"
[ -s "$served.minisig" ] || fail "the mirror holds no signature beside the binary"
cmp -s "$served" "$opt/nodary" || fail "the published binary is not the installed one"
pass "mirror serves the binary and its signature"

printf 'what a node does\n'
# Verify the served pair exactly as internal/release does, using the same key
# the node would carry. minisign -Vm is an independent implementation, which is
# the point: if nodary and minisign disagree, one of them is wrong.
minisign -Vm "$served" -x "$served.minisig" -p "$work/release.pub" >/dev/null 2>&1 \
    || fail "the published signature does not verify"
pass "a node's verification of the served binary succeeds"

printf 'a substituted binary\n'
cp "$served" "$work/tampered"
printf 'x' >> "$work/tampered"
if minisign -Vm "$work/tampered" -x "$served.minisig" -p "$work/release.pub" >/dev/null 2>&1; then
    fail "a modified binary verified against the signature"
fi
pass "a substituted binary is refused"

printf '\nall self-upgrade checks passed\n'
