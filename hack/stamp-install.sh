#!/bin/sh
#
# Produce the install.sh that ships with a release.
#
# The copy in this repository is a development copy: it carries a placeholder
# signing key and the version the tree is on. Publishing it verbatim hands every
# user an installer that cannot verify anything and fetches the wrong release —
# so the release pipeline builds the shipped copy from it rather than uploading
# it directly.
#
#   hack/stamp-install.sh --version 1.2.3 --pubkey nodary-release.pub \
#                         [-o build/install.sh]
#
# The output is verified before it is written: a stamped script that still
# carries either placeholder is a failure, not a warning.
#
# See docs/specs/01-install.md §2.

set -eu

usage() { sed -n '3,17p' "$0" >&2; exit 2; }
die()   { printf 'error: %s\n' "$*" >&2; exit 1; }

version=""
pubkey=""
out="build/install.sh"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) version="${2:?--version needs a value}"; shift 2 ;;
        --pubkey)  pubkey="${2:?--pubkey needs a value}";   shift 2 ;;
        -o)        out="${2:?-o needs a value}";            shift 2 ;;
        -h|--help) usage ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$version" ] || usage
[ -n "$pubkey" ]  || usage
[ -f "$pubkey" ]  || die "no such public key: $pubkey"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ -f "$root/install.sh" ] || die "no install.sh at $root"

# A version carrying shell metacharacters would be spliced into the script
# below. Reject it rather than quoting around it.
case "$version" in
    *[!0-9A-Za-z.+-]*) die "refusing to stamp a version containing shell metacharacters: $version" ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/nodary-stamp.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

cp "$root/install.sh" "$work/install.sh"
cp "$pubkey" "$work/pub.pem"

# release-key.sh operates on ./install.sh, so run it beside the copy rather
# than against the tree. The repository copy is never modified.
(cd "$work" && "$root/hack/release-key.sh" embed pub.pem >/dev/null) \
    || die "embedding the public key failed"

sed "s|^NODARY_VERSION=\"\${NODARY_VERSION:-[^}]*}\"\$|NODARY_VERSION=\"\${NODARY_VERSION:-$version}\"|" \
    "$work/install.sh" > "$work/stamped.sh"

# --- verify before writing ---------------------------------------------------

# The key placeholder also appears in install.sh's own guard against running
# unsigned, so check inside the PEM block rather than the whole file.
case "$(sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' "$work/stamped.sh")" in
    *REPLACE_AT_RELEASE_TIME*) die "the signing key was not substituted" ;;
    *"BEGIN PUBLIC KEY"*) ;;
    *) die "the stamped script has no public key block" ;;
esac

got=$(sed -n 's|^NODARY_VERSION="\${NODARY_VERSION:-\(.*\)}"$|\1|p' "$work/stamped.sh")
[ "$got" = "$version" ] \
    || die "version was not substituted: install.sh still defaults to '${got:-<nothing>}', want '$version'"

sh -n "$work/stamped.sh" || die "the stamped script is not valid shell"

mkdir -p "$(dirname "$out")"
cp "$work/stamped.sh" "$out"
chmod 0755 "$out"

printf 'stamped %s — version %s, key %s\n' "$out" "$version" "$pubkey" >&2
