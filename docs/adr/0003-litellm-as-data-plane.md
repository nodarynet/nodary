# ADR 0003 — LiteLLM as the data plane

**Status:** Accepted · **Date:** 2026-08-28

## Context

nodary must issue and revoke tokens, meter usage per person, and enforce throttle limits. That
list is also an accurate description of LiteLLM's feature set, so the overlap had to be
resolved rather than left ambiguous.

Two options: absorb the proxy entirely, or keep it and put nodary's concerns in front.

## Decision

**nodary owns identity, quota, metering and audit. LiteLLM remains the data-plane proxy.**

```
client ──► nodary-gateway ──► LiteLLM ──► deployment
           auth, quota,        OpenAI-compat, routing,
           metering, audit     retries, fallbacks
```

Because identity lives in nodary, LiteLLM runs **stateless behind a single master key** that
is never exposed to clients, and requires no database.

## Rationale

An OpenAI-compatible proxy is a deceptively large surface: streaming, tool and function calls,
per-model token accounting, error mapping across backends, retries and fallbacks. It is
well-trodden ground where a reimplementation would spend months reaching parity and would
regress every time an upstream backend changed its dialect.

Splitting at identity rather than at the proxy also avoids the usual failure of this
arrangement, in which a frontend holds one broadly-scoped master key and every client
inherits its authority. Identity moves *up* into nodary
instead of being deleted, which is what makes the stateless LiteLLM configuration safe rather
than a downgrade.

## Consequences

**Gained.** No database for the proxy. One less stateful service, one less backup concern. Per-
person attribution for every inference request, which the proxy alone could not provide.

**Lost.** A dependency on an external project's release cadence and configuration format, and
an extra network hop on every request.

**Reconsider if** LiteLLM's direction diverges from nodary's needs, or if the backends nodary
supports converge on a dialect uniform enough that direct proxying becomes trivial. The
gateway boundary is deliberately placed so that absorbing the proxy later is a contained
change.
