# Transport profiles

Wireprint deliberately separates **what was observed** from **what it knows how to send**.

Transport-set files currently use `schema_version: 1`. A transport profile can therefore contain two independent things:

- `implementation`: a runnable client configuration that Wireprint can apply;
- `observations`: fingerprints or other transport facts measured or reported elsewhere.

Those fields are not interchangeable. A JA4 hash, JA4 prefix, H2 preface summary, or similar fingerprint is a lossy observation; it is not enough information to reconstruct a ClientHello or HTTP/2 client exactly. Wireprint does not invert hashes or fill missing parameters with guesses.

## Runnable profile

```json
{
  "name": "chrome149-macos",
  "provenance": "wreq Chrome149 emulation; not a vendor identity claim",
  "implementation": {
    "kind": "wreq_emulation",
    "profile": "chrome149",
    "platform": "macos",
    "http2": true
  }
}
```

Wreq emulations always have their application-level default headers disabled. HTTP header identity belongs to `RequestProfile`, where exact order and duplicate fields are recorded. This prevents a transport profile from silently contaminating the application-identity axis.

## Observational-only profile

```json
{
  "name": "published-passive-example",
  "provenance": "cite the exact capture or publication here",
  "observations": [
    {
      "scheme": "ja4",
      "value": "t13d1011h2_example_",
      "completeness": "prefix",
      "provenance": "only a prefix was retained"
    }
  ]
}
```

With no `implementation`, this is valid evidence but **not runnable**. Selecting it for a probe is an error instead of an invitation to invent the missing TLS state.

`completeness` is one of:

- `exact` — the stored value is complete for that observation scheme;
- `prefix` — only a leading portion is known;
- `partial` — some information is known, but not as a simple prefix.

## CLI

Built-in aliases remain convenient:

```bash
wireprint probe --transport chrome149 --platform macos https://example.com/
```

A declarative transport set can be used instead:

```bash
wireprint probe \
  --transport-set transports/builtins.json \
  --transport-name chrome149-macos \
  https://example.com/
```

For matrices, omit `--transport-name` to run every runnable profile in the set. Observational-only entries are retained in the file but are not executed implicitly.

Every emitted observation snapshots the complete transport profile used for that request, including provenance and attached transport observations, so later edits to a profile file do not rewrite historical meaning.

## Declared headers are not a wire capture

`request_profile_headers` records the ordered application-header input supplied by the selected `RequestProfile`. It does **not** claim to be the final serialized wire header block: protocol-required fields such as `Host`/`:authority`, library-generated headers, HPACK/QPACK encoding details, or serializer reordering require lower-level instrumentation. Keep that distinction when interpreting observations.

## Checked-in passive example

`transports/openai-gptbot-observed.json` records an independent ELLIO capture of GPTBot/1.4 observed on 2026-09-03. It includes complete JA4, JA4_R and Akamai-style HTTP/2 client fingerprint values, but deliberately has no `implementation`. Having the exact fingerprint strings is still not the same thing as having a proven runnable reproduction; that transition should happen only after the concrete TLS/H2 configuration is implemented and its emitted wire image is measured against the observation.

## Measured GPTBot-compatible reconstruction

`transports/openai-gptbot-reconstructed.json` is a separate runnable profile backed by pinned `hyper 1.12.0`, `hyper-rustls 0.27.10`, `rustls 0.23.42` with the ring provider, and the locked transitive HTTP/2 stack. It was promoted only after independent reflector measurements reproduced all retained stable targets exactly:

- JA4 `t13d1011h2_61a7ad8aa9b6_3fcd1a44f3e3`;
- JA4_R `t13d1011h2_00ff,1301,1302,1303,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,0023,002b,002d,0033_0503,0403,0807,0806,0805,0804,0601,0501,0401`;
- H2 `2:0;4:2097152;5:16384;6:16384|5177345|0|m,s,a,p`.

The backend is deliberately one layer below reqwest because reqwest 0.12.28 injects `Accept: */*` as a client default. Raw Hyper with the same rustls/H2 family produced the same transport fingerprints while emitting no application headers beyond HTTP/2 pseudo-headers, preserving Wireprint's RequestProfile/TransportProfile separation. The native backend implements response decompression and redirect following itself; sensitive request headers are not forwarded after a cross-origin redirect.

The reconstruction proves compatibility with the measured reqwest/rustls-family transport. It does **not** authenticate OpenAI or prove that any arbitrary sender using the profile is GPTBot. Keep the passive observation and runnable reconstruction as separate provenance objects.

## Reproducibility

For a fingerprinting tool, the lockfile is evidence, not housekeeping. A semver-compatible update to `h2`, Hyper, rustls, or related transport dependencies can change emitted SETTINGS, window behavior, cipher/signature support, or extension morphology. Commit `Cargo.lock` for runnable measurements and record the lock state with any published transport capture.

## Measured ChatGPT-User Envoy-compatible reconstruction

`transports/openai-chatgpt-user-reconstructed.json` is a second measured runnable profile. It reproduces the outbound transport morphology independently observed with ChatGPT-User, without embedding application headers into the transport:

- current-spec full-handshake JA4 `t13d1712h2_5b57614c22b0_ef7df7f74e48`;
- JA3 `f5bd742fa88333052a1deec09f821012`;
- H2 `2:0;1:4096;8:0;3:1024;4:1048576|25100289|0|a,p,m,s`;
- HTTP/2 pseudo-header order `:authority, :path, :method, :scheme`.

A direct Envoy 1.39.1 control reproduced the H2 SETTINGS order, 24 MiB connection window and pseudo-header order with defaults; setting only the stream window to 1 MiB produced the observed H2 fingerprint exactly. With the observed TLS policy, the same control reproduced the 17-cipher set, groups, signature algorithms, ALPN, key share and JA3. Envoy also generated `x-request-id` and `x-envoy-expected-rq-timeout-ms: 15000` in the same application-header sequence seen in the saved trace. This identifies an Envoy-compatible outbound stack very strongly, but **does not attribute the production Envoy version**.

Stock `wreq 0.16.1` can express the same TLS and H2 parameters directly and reproduced JA4, JA4_R, JA3 and H2 exactly while an empty request profile emitted no ordinary application headers. Wireprint therefore uses wreq for this transport rather than requiring an Envoy sidecar.

### Legacy peet JA4 note

The older ChatGPT-User reflector snapshot reported JA4 suffix `78e6aca7449b` and a JA4_R list without TLS padding `0015`. That string is retained in `openai-chatgpt-user-observed.json` as `ja4_peet_legacy` evidence rather than current-spec JA4. The same snapshot says the ClientHello had 12 extensions, while its JA4_R list plus the two intentionally omitted JA4 fields (SNI and ALPN) accounts for only 11. Its JA3 hash is also exactly the padded ClientHello reproduced by Envoy and wreq. Current JA4 specifies that padding participates in the extension hash. The wire evidence therefore supports padding being present; the old JA4 renderer omitted it from JA4_c/JA4_R.

TLS session resumption creates another legitimate variant. Direct Envoy reconnects with a PSK extension and produces current-spec JA4 suffix `02c8e53ee398` while H2 stays unchanged. Public Microsoft/OpenAI egress telemetry also contains `d5fe2c511efa`, corresponding to the same resumed extension set with padding omitted by the collector. Treat these as session/collector variants of one transport family, not separate application identities.

As with GPTBot, transport compatibility is not sender authentication. ChatGPT-User, OAI-SearchBot and other callers may share an outbound stack, and one application identity may use multiple transport families across endpoints or time.

## Verified ClaudeBot JA4 observation

`transports/anthropic-claudebot-observed.json` records a source-network-corroborated ClaudeBot/1.0 JA4 family. Anthropic publishes `216.73.216.0/22` as bot egress, and independent passive records for two addresses inside that range (`216.73.217.37` and `216.73.217.73`) report the full ClaudeBot User-Agent with the same JA4 `t13d1011h2_61a7ad8aa9b6_3fcd1a44f3e3`.

The records have different JA3 values, and no independently verified HTTP/2 SETTINGS fingerprint is available. Therefore the checked-in profile is deliberately **observational-only and JA4-only**. Its collision with the GPTBot/reqwest-rustls-compatible JA4 is useful implementation-family evidence, not permission to inherit GPTBot H2 settings or a sender-authentication primitive.
