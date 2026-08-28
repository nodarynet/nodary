#!/bin/sh
#
# Release signing key management.
#
#   hack/release-key.sh generate           create a new P-256 keypair
#   hack/release-key.sh embed  <pub.pem>   splice the public key into install.sh
#   hack/release-key.sh sign   <key> FILE  sign one release artifact
#   hack/release-key.sh check  <pub> FILE  verify one release artifact
#
# The private key never belongs in this repository. Generate it once, store it
# in the release signing secret store, and keep only the public half here.
#
# See docs/specs/01-install.md §2.

set -eu

usage() { sed -n '3,16p' "$0" >&2; exit 2; }
die()   { printf 'error: %s\n' "$*" >&2; exit 1; }

cmd="${1:-}"
[ -n "$cmd" ] || usage
shift || true

case "$cmd" in

generate)
    out="${1:-nodary-release}"
    [ ! -e "$out.key" ] || die "$out.key already exists; refusing to overwrite a signing key"

    openssl ecparam -name prime256v1 -genkey -noout -out "$out.key"
    chmod 0400 "$out.key"
    openssl ec -in "$out.key" -pubout -out "$out.pub" 2>/dev/null

    printf 'wrote %s.key (private — store in the secret store, never commit)\n' "$out" >&2
    printf 'wrote %s.pub (public  — embed in install.sh and publish in the README)\n' "$out" >&2
    printf '\nfingerprint: '
    openssl pkey -pubin -in "$out.pub" -outform DER 2>/dev/null | openssl dgst -sha256 -r | awk '{print "SHA256:"$1}'
    ;;

embed)
    pub="${1:?usage: release-key.sh embed <public.pem>}"
    [ -f "$pub" ] || die "no such file: $pub"
    [ -f install.sh ] || die "run this from the repository root"

    # Replace the key body between the PEM delimiters, leaving the delimiter
    # lines untouched: in install.sh they carry the shell quoting that makes
    # NODARY_PUBKEY a single-quoted heredoc-style assignment.
    awk -v keyfile="$pub" '
        index($0, "-----BEGIN PUBLIC KEY-----") && !done {
            print
            while ((getline line < keyfile) > 0)
                if (!index(line, "PUBLIC KEY-----")) print line
            close(keyfile)
            skip = 1
            next
        }
        index($0, "-----END PUBLIC KEY-----") && skip { print; skip = 0; done = 1; next }
        !skip { print }
    ' install.sh > install.sh.tmp

    # Check inside the PEM block only. The placeholder string also appears in
    # install.sh's own guard against being run unsigned, so a whole-file grep
    # would match that and report a failure that did not happen.
    block=$(sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' install.sh.tmp)

    case "$block" in
        *REPLACE_AT_RELEASE_TIME*)
            rm -f install.sh.tmp
            die "key was not substituted; install.sh may have changed shape"
            ;;
    esac
    case "$block" in
        *"BEGIN PUBLIC KEY"*) ;;
        *) rm -f install.sh.tmp; die "result has no public key block" ;;
    esac

    mv install.sh.tmp install.sh
    chmod 0755 install.sh
    printf 'embedded %s into install.sh\n' "$pub" >&2
    ;;

sign)
    key="${1:?usage: release-key.sh sign <private.key> FILE...}"; shift
    [ "$#" -gt 0 ] || usage
    for f in "$@"; do
        openssl dgst -sha256 -sign "$key" -out "$f.sig" "$f"
        openssl dgst -sha256 -r "$f" | awk -v f="$(basename "$f")" '{print $1"  "f}' > "$f.sha256"
        printf 'signed %s\n' "$f" >&2
    done
    ;;

check)
    pub="${1:?usage: release-key.sh check <public.pem> FILE...}"; shift
    [ "$#" -gt 0 ] || usage
    rc=0
    for f in "$@"; do
        if openssl dgst -sha256 -verify "$pub" -signature "$f.sig" "$f" >/dev/null 2>&1; then
            printf '✔ %s\n' "$f" >&2
        else
            printf '✘ %s — SIGNATURE INVALID\n' "$f" >&2
            rc=1
        fi
    done
    exit "$rc"
    ;;

*) usage ;;
esac
