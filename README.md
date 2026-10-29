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

A request profile describes application identity and HTTP headers. A transport profile separately describes a runnable transport implementation and/or transport facts observed elsewhere. Observational-only profiles are valid evidence but cannot execute. The resulting observation snapshots both axes, raw provenance and a semantic outcome classification.

Each successful observation also runs the versioned network-path recognizer (`builtin-path-v4`), DNS/routing provenance (`builtin-dns-v1` / `builtin-routing-v6`), live HTTP/2 server-preface classifier (`builtin-h2-preface-v1`) and per-endpoint fusion (`builtin-endpoint-v1`). Those layers keep path participation, concrete endpoint provenance and likely outer termination separate instead of guessing hop order. `builtin-host-v1` can then aggregate saved observations into freshness-aware current/historical provider state without turning retries into votes. See [`docs/path-elements.md`](docs/path-elements.md) and [`docs/evidence-model.md`](docs/evidence-model.md).

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

Rust **1.99.1** is pinned in `rust-toolchain.toml`.

```bash
cargo build --release
cargo test
```

The transport layer uses [`wreq`](https://crates.io/crates/wreq) for browser/reference emulations and a separate pinned `hyper` + `hyper-rustls` + `rustls/ring` backend for header-neutral reconstructed transports. `Cargo.lock` is part of the fingerprinting state: transport-relevant transitive versions can change emitted TLS/H2 morphology even when Wireprint source does not.

## Probe one identity

```bash
wireprint probe \
  --transport plain \
  --header 'user-agent:wireprint-control/0.1' \
  https://example.com/
```

Observations are emitted as JSONL. Add `--vantage NAME` when the collection point has a stable label; every row also records an observation timestamp, actual peer, HTTP version, declared ordered request-profile headers, response headers, bounded raw body prefix, semantic outcome and body-prefix hash.

## Observe HTTP/3 / QUIC

The dedicated H3 observer preserves raw peer QUIC transport-parameter order and ordered peer HTTP/3 SETTINGS before high-level decoding discards those wire facts:

```bash
wireprint h3 \
  --family auto \
  --repeat 2 \
  --vantage acer \
  https://www.cloudflare.com/
```

Successful H3 rows use the ordinary `Observation` JSON schema, including DNS/routing provenance, response path elements, `H3Transport` provider evidence when an independently validated exact signature matches, and a normal endpoint assessment. Body/outcome fields stay unset because this observer intentionally stops after final response headers. See [`docs/h3-quic.md`](docs/h3-quic.md).

## Run a matrix

```bash
wireprint matrix \
  --profiles profiles/ai-retrievers-observed.json \
  --targets examples.targets.txt \
  --transport low-fidelity \
  --transport plain \
  --transport chrome149 \
  --output results.jsonl
```

Each request-profile/transport combination gets a fresh client so transport/session state does not silently bleed across identities. `plain` means the library default without browser emulation; it is a baseline, not an intentionally bad fingerprint. `low-fidelity` is an explicit negative control for early transport-gate screening: it remains standards-valid with normal certificate verification and TLS 1.2/1.3 + H2/H1 compatibility, but deliberately emits a conspicuous non-browser TLS/H2 shape (no GREASE/ECH grease/extension permutation, P-256-only key exchange, small flow-control values, and unusual legal SETTINGS/pseudo-header order). It must not be treated as a realistic client identity or as evidence of a block unless neutral compatibility controls succeed and the semantic outcome differs from a good transport. For mechanism decomposition after a hit, `low-fidelity-tls` applies only the negative-control TLS shape while leaving HTTP/2 at the library default, and `low-fidelity-h2` applies only the negative-control HTTP/2 shape while leaving TLS at the library default. These are diagnostic ablations, not additional client identities. The positive-side mirrors `chrome149-tls` and `chrome149-h2` keep only Chrome 149 TLS or HTTP/2 respectively, making acceptance-side mechanisms decomposable too. Additional standards-valid reference transports (`safari-ios18`, `safari-ios16`, `firefox-android135`, `chromium100-era`, and `okhttp39`) sample distinct current/older mobile stacks. `chromium100-era` is a WebView-era Chromium proxy for transport-shape experiments, not a claim to exactly reproduce Android System WebView. Application identity remains a separate axis and should be paired coherently when a test requires a whole-client fingerprint rather than a transport-only ablation.

Transport profiles can also be loaded declaratively:

```bash
wireprint matrix \
  --profiles profiles/ai-retrievers-observed.json \
  --targets examples.targets.txt \
  --transport-set transports/builtins.json \
  --output results.jsonl
```

A transport set may include observational-only fingerprints with no runnable implementation. Those entries are retained as evidence and skipped by an unfiltered matrix; explicitly selecting one fails rather than synthesizing missing TLS/H2 parameters. See [`docs/transport-profiles.md`](docs/transport-profiles.md).

`transports/openai-gptbot-reconstructed.json` is a measured reconstruction profile. Its header-neutral Hyper/rustls backend was independently measured to reproduce the retained GPTBot/1.4 JA4, JA4_R and HTTP/2 fingerprint exactly. This establishes transport compatibility only; it is not sender authentication.

`transports/openai-chatgpt-user-reconstructed.json` is a separate measured Envoy-compatible transport reconstructed with wreq/BoringSSL. It reproduces the current-spec padded JA4, the saved ChatGPT-User JA3, and the complete HTTP/2 SETTINGS/window/pseudo-header morphology while leaving application headers to the request profile. It is transport evidence, not OpenAI authentication or production Envoy-version attribution.

`transports/anthropic-claudebot-observed.json` deliberately remains observational-only and JA4-only: source-network-corroborated records establish the stable JA4 family, but no independently verified ClaudeBot HTTP/2 fingerprint is currently stored.

## Replay captured path evidence

Classify captured response headers into network-path participants without sending a request:

```bash
wireprint path \
  --header 'via: 1.1 google, 1.1 varnish' \
  --header 'x-fastly-backend-reqs: 10' \
  --header 'server: DataDome'
```

This applies exactly the same versioned path recognizer used by live observations. For corpus replay, pass JSONL rows with a `headers` array; all other row fields are preserved and the output adds `path_classifier` plus `path_elements`:

```bash
wireprint path --input captured-responses.jsonl > classified-responses.jsonl
```

## Aggregate hostname history

Aggregate probe JSONL into current and historical provider membership:

```bash
wireprint aggregate-host results.jsonl \
  --freshness-hours 6 \
  --support-bucket-minutes 60
```

The default current-provider window is six hours, anchored to the latest timed provider-bearing endpoint assessment. Support is deduplicated by provider/channel/protocol/vantage/endpoint/time bucket; repeated requests in one bucket remain one independent support group. Current multi-provider/path-split state is preserved instead of ranked to a winner, while stale providers remain visible only in the historical set.

## Audit routing-context specificity

Audit whether observed endpoint ASNs are provider-specific in a corpus without turning ASN ownership into provider evidence:

```bash
wireprint audit-routing-context results.jsonl --min-labeled-hosts 2
```

The audit uses only single-candidate endpoint assessments as provider references and counts distinct hostnames rather than requests. It reports ASN→provider collisions, unlabeled/broad-network use, provider→ASN spread, prefixes, vantages and concrete endpoints. `pure_in_sample` means exactly that: the ASN was pure in the supplied sample with enough distinct labeled hosts. It is not an instruction to add an ASN→provider mapping.

For frozen or externally normalized research corpora, `--samples` accepts JSONL `RoutingAuditSample` rows instead of full `Observation` rows. This keeps historical-format adapters out of the production model.

The bundled AI-retriever **request** profiles are research inputs and do not authenticate a vendor; transport fidelity is represented separately by measured transport profiles when available. Provenance is stored alongside each profile so a later live capture can replace an approximation without rewriting history.

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
