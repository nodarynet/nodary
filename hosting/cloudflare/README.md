# Cloudflare hosting

Serves `nodary.net/install.sh`, `nodary.net/install.sh.minisig` and
`nodary.net/releases/<version>/<asset>` from an R2 bucket.

`install.sh` hardcodes `https://nodary.net` as its origin
([01 §2](../../docs/specs/01-install.md#2-the-installsh-contract)), so the
artifacts have to be on the apex rather than a subdomain. The Worker is bound to
those three paths only, so the rest of the apex is untouched and free to serve
whatever else the zone hosts.

Pages is not an option here: its per-file limit is 25 MiB and the binaries are
20–40 MB.

```
                    ┌── nodary.net/install.sh          ┐
GitHub Actions ──►  │   nodary.net/install.sh.minisig  ├──► Worker ──► r2://nodary-releases
   (release.yml)    └── nodary.net/releases/*          ┘
```

## What Cloudflare is and is not trusted for

Nothing. The Worker is a file server, and it is not in a position to vouch for
what it serves: `install.sh` verifies the release signature and digest before
placing anything, and `install.sh` itself is verifiable against
`install.sh.minisig` using the key published in the repository README — a
different origin from the one serving the script. That separation is the whole
reason the `.minisig` exists.

The one thing that must hold is that objects are served **byte-identical**. Do
not put these paths behind anything that rewrites content; a transform breaks
both the signature and the digest.

## Setup

Once, by hand. Everything after this is `release.yml`'s job.

### 1. Bucket

```sh
npx wrangler r2 bucket create nodary-releases
```

### 2. Repository secrets for publishing

R2 → **Manage R2 API Tokens** → create a token with **Object Read & Write** on
`nodary-releases`. It gives an access key pair for the S3-compatible API.

These go on `nodarynet/nodary` as **repository** secrets — the `build` job has no
`environment:`, so an environment secret resolves to empty there.

| Secret | Where it comes from |
| :--- | :--- |
| `R2_ACCOUNT_ID` | R2 overview page |
| `R2_ACCESS_KEY_ID` | the token above |
| `R2_SECRET_ACCESS_KEY` | the token above, shown once |

### 3. DNS

A Worker route only fires if the hostname resolves to Cloudflare. An apex with
no origin server still needs a **proxied** record, and the usual answer is the
IPv6 discard prefix:

```
AAAA   nodary.net   100::   (proxied — orange cloud)
```

Without this the route is configured, matches nothing, and every request 404s
from somewhere other than the Worker. It is the least obvious step here.

### 4. Deploy

```sh
cd hosting/cloudflare
npx wrangler deploy
```

The deploying token needs **Workers Scripts: Edit**, **Workers R2 Storage:
Edit**, and **Workers Routes: Edit** on the `nodary.net` zone.

### 5. Verify

```sh
curl -fsSI https://nodary.net/install.sh | grep -i 'cache-control\|content-type'
#   cache-control: public, max-age=300
#   content-type: text/plain; charset=utf-8

curl -fsSLO https://nodary.net/install.sh
curl -fsSLO https://nodary.net/install.sh.minisig
minisign -Vm install.sh -P "$(grep -A1 '^minisign' ../../README.md | tail -1)"
```

## Tests

```sh
node test/worker.test.mjs
```

No dependencies, no network, no wrangler. The mock deliberately mirrors one R2
behaviour that is easy to get wrong: `range` is populated on a full-object get,
not only on a ranged one. A mock that omits it passes a Worker which answers
every request with a 206.

## Caching

The two policies are deliberately opposite, and are set on the object at upload
rather than in the Worker.

| Path | `Cache-Control` | Why |
| :--- | :--- | :--- |
| `releases/<version>/…` | `public, max-age=31536000, immutable` | The version is in the path, so the bytes never change |
| `install.sh`, `install.sh.minisig` | `public, max-age=300` | Overwritten every release — a long TTL pins every `curl … \| sh` to whatever shipped first |

Getting these the wrong way round is the failure worth guarding against: it does
not surface until the second release, and then it surfaces for everyone.

## Prereleases

A prerelease publishes to `releases/<version>/` and deliberately does **not**
overwrite the apex `install.sh`, so `curl … | sh` never hands out a release
candidate. `release.yml` and `.goreleaser.yaml`'s `prerelease: auto` both key off
the semver prerelease suffix.
