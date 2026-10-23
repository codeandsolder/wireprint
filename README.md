# wireprint

`wireprint` is a Rust tool for **cross-layer HTTP edge fingerprinting** and **benign request-identity differential experiments**.

The project grew out of a simple annoyance: status codes are terrible summaries of what edge systems actually did. A `200` may be content, a JavaScript gate, a soft block, or an interstitial; the same HTTP headers may behave differently under a different TLS fingerprint; and two agents from the same vendor can receive completely different policy.

Wireprint keeps those dimensions separate instead of collapsing them into “WAF = vendor” or “200 = allowed”.

## Current shape

Three concepts are intentionally independent:

```text
RequestProfile × TransportProfile × Target
                    │
                    ▼
               Observation
                    │
                    ▼
             OutcomeClassifier
```

A request profile describes application identity and HTTP headers. A transport profile describes the wreq client emulation. The resulting observation retains raw provenance and a semantic outcome classification.

Each successful observation also runs the versioned network-path recognizer (`builtin-path-v3`), DNS/routing provenance (`builtin-dns-v1` / `builtin-routing-v1`), live HTTP/2 server-preface classifier (`builtin-h2-preface-v1`) and per-endpoint fusion (`builtin-endpoint-v1`). Those layers keep path participation, concrete endpoint provenance and likely outer termination separate instead of guessing hop order. `builtin-host-v1` can then aggregate saved observations into freshness-aware current/historical provider state without turning retries into votes. See [`docs/path-elements.md`](docs/path-elements.md) and [`docs/evidence-model.md`](docs/evidence-model.md).

Built-in outcome classes currently include:

- `content_like`
- `redirect`
- `challenge`
- `captcha`
- `explicit_block`
- `rate_limited`
- `application_error`
- `unknown`

`content_like` deliberately means only “no known challenge/block/error marker was recognized”. It is not a proof that useful application content was returned.

## Build

Rust **1.98.1** is pinned in `rust-toolchain.toml`.

```bash
cargo build --release
cargo test
```

The transport layer currently uses [`wreq`](https://crates.io/crates/wreq) and [`wreq-util`](https://crates.io/crates/wreq-util).

## Probe one identity

```bash
wireprint probe \
  --transport plain \
  --header 'user-agent:wireprint-control/0.1' \
  https://example.com/
```

Observations are emitted as JSONL. Add `--vantage NAME` when the collection point has a stable label; every row also records an observation timestamp, actual peer, HTTP version, exact ordered request headers, response headers, bounded raw body prefix, semantic outcome and body-prefix hash.

## Run a matrix

```bash
wireprint matrix \
  --profiles profiles/ai-retrievers-observed.json \
  --targets examples.targets.txt \
  --transport plain \
  --transport chrome149 \
  --output results.jsonl
```

Each request-profile/transport combination gets a fresh client so transport/session state does not silently bleed across identities.

## Replay captured path evidence

Classify captured response headers into network-path participants without sending a request:

```bash
wireprint path \
  --header 'via: 1.1 google, 1.1 varnish' \
  --header 'x-fastly-backend-reqs: 10' \
  --header 'server: DataDome'
```

This is intended for corpus replay: it applies exactly the same versioned path recognizer used by live observations.

## Aggregate hostname history

Aggregate probe JSONL into current and historical provider membership:

```bash
wireprint aggregate-host results.jsonl \
  --freshness-hours 6 \
  --support-bucket-minutes 60
```

The default current-provider window is six hours, anchored to the latest timed provider-bearing endpoint assessment. Support is deduplicated by provider/channel/protocol/vantage/endpoint/time bucket; repeated requests in one bucket remain one independent support group. Current multi-provider/path-split state is preserved instead of ranked to a winner, while stale providers remain visible only in the historical set.

The bundled AI-retriever profiles are **synthetic research profiles**, not claims that the transport matches the vendor's production fetcher. Provenance is stored alongside each profile so a later live capture can replace an approximation without rewriting history.

## Why semantic outcomes matter

Two regression fixtures capture the original failure mode:

- a Reddit HTTP `200` containing `js_challenge=1` and `jsc_token` is classified as `challenge`, not content;
- a DataDome `403` with `x-datadome: protected` / `captcha-delivery.com` is classified as `captcha`, not merely “403”.

The classifier is intentionally conservative and versioned (`builtin-v1`). Raw status, headers and captured body prefix remain in the observation so a newer classifier can re-evaluate old data. Each textual capture also gets both a raw prefix SHA-256 and a versioned normalized-template SHA-256 (`template-v1`) so nonce/token churn does not hide identical challenge shells.

## Evidence model

See [`docs/evidence-model.md`](docs/evidence-model.md) and [`docs/path-elements.md`](docs/path-elements.md). The short version is that request identity, agent role, HTTP shape, TLS/H2/H3 transport, source verification, network-path participation, session/reputation, response semantics and raw provenance are different axes.

## Scope

Wireprint defaults to ordinary unauthenticated requests and passive/benign differentials. It is not a CAPTCHA solver, challenge bypasser, credential tool, exploit scanner, or attack-payload generator.

The interesting part is the weird policy at the boundary, not making the boundary angry.
