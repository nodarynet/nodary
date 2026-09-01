# 10 — CLI reference

One binary. `nodary server`, `nodary agent` and the operator verbs are subcommands of the same
executable, selected at runtime.

**The CLI and the HTTP API call the same core functions.** Neither holds business logic, and
every mutating call passes through the audit layer. This is what keeps them behaviourally
identical without duplicated effort, and it is a constraint on the implementation, not an
aspiration.

## 1. Verbs

```
nodary server   install | start | stop | status
nodary node     install | list | show | approve | drain | revoke | verify-egress
                | leave | policy | uninstall
nodary agent    audit list | audit verify | audit export | status
nodary backend  list | show | register | remove | build | rebuild
nodary model    register | list | show | enable | disable | restart
                | stage | unstage | restage
nodary route    list | show | set
nodary user     add | list | show | suspend | delete | passwd | totp
nodary token    create | list | revoke | join
nodary limits   show | set
nodary usage    show [--user] [--model] [--node] [--group_by] [--from] [--to] [--format]
nodary audit    list | verify | export
nodary policy   show | apply | diff
nodary config   show | diff | rollback | export | apply
nodary backup   create | restore
nodary components list | verify
nodary bundle   create [--platform] [--backends] [--components] -o FILE
nodary upgrade  [--to VERSION] [--check]
nodary uninstall [--purge] [--purge-models] [--force]
nodary doctor
nodary restart
nodary status
```

## 2. Global flags

| Flag | Meaning |
| :--- | :--- |
| `--justify TEXT` | Justification for a mutating action. Required by policy |
| `--dry-run` | Render and print the change plus its `intent_hash`; do not apply |
| `--yes` | Skip the interactive confirmation. Does **not** skip justification or TOTP |
| `--format text\|json\|yaml` | Output format. `json` is stable and intended for scripting |
| `--server URL` | Target control plane. Defaults to the local one |
| `-v`, `-vv` | Verbosity |

One verb does not take those `--format` values: `nodary audit export` writes `jsonl` or
`csv`, because there the flag selects an export encoding rather than a rendering style
([09 §1](09-api.md#1-surface)). It refuses `text`, `json` and `yaml` naming what it accepts.

## 3. `nodary doctor`

The diagnostic entry point, and the first thing to tell anyone to run.

```
$ nodary doctor
✔ binary            2.0.0 (linux/amd64)
✔ control plane     reachable, protocol 1
✔ certificate       valid, renews in 41d
✔ clock skew        0.3s
✔ units             nodary-agent active; 2 model units active
✔ staging           2 models staged, manifests verified
✔ gpu               8 devices, driver 570.86.15, no ECC errors
✘ egress            dep_7f3a reached 1.1.1.1:443 — ISOLATION BREACH
⚠ reboot policy     manual-console: encrypted root, no network unlock
```

Exits non-zero on any hard failure and prints a copy-pasteable summary. Egress verification
runs here as well as after every deployment start, because a control that is only checked at
creation time is a control that drifts.

## 4. Output discipline

Human output goes to stdout; diagnostics and progress to stderr. `--format json` emits a
stable schema to stdout and nothing else, so it can be piped without filtering.

Secrets — service keys, join tokens, TOTP seeds — are printed exactly once at creation, to
stdout, with no surrounding decoration, so they can be captured cleanly. They are never
written to a log, never echoed on subsequent reads, and never included in `--format json`
output for list operations.

## 5. Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | Success |
| `1` | General failure |
| `2` | Usage error — bad flags, missing arguments |
| `3` | Authentication or authorization failure |
| `4` | Precondition failed — intent hash mismatch, conflict |
| `5` | Policy refused the operation |
| `6` | Control plane unreachable |
