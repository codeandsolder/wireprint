# HTTP/3 and QUIC server transport evidence

`wireprint h3` is a dedicated HTTP/3 observer built on quiche. It sends an ordinary certificate-verified HTTPS GET and stops after the first final response headers; it does not need the response body to collect transport evidence.

The observer deliberately preserves facts that high-level QUIC APIs often normalize away:

- the peer QUIC transport-parameter extension as exact TLS-authenticated bytes;
- QUIC transport parameters parsed as ordered `{id, length, raw_hex}` entries;
- the peer HTTP/3 SETTINGS frame in received order, including unknown/reserved settings;
- selected DNS candidate and actual UDP peer separately;
- ordinary response headers and path-element evidence.

The raw transport-parameter bytes are copied from BoringSSL during the QUIC TLS handshake through `SSL_get_peer_quic_transport_params`. quiche still owns packet protection, certificate verification and QUIC state; wireprint only copies the already-authenticated peer extension before quiche's decoded representation loses wire order.

## Classifier

`builtin-h3-quic-v1` ports the 2026-10-09 research catalog into the reusable Rust path. It keeps three levels separate:

1. **exact current-corpus signatures** — normalized HTTP/3 SETTINGS plus stable decoded QUIC transport values;
2. **middle-tier structure** — SETTINGS plus source-CID/reset-token/version/min-ACK-delay structure;
3. **family rules** — broader implementation relationships such as the nginx HTTP/3 flow-control invariant.

GREASE HTTP/3 setting IDs and QUIC transport-parameter IDs are normalized to `GREASE` for comparison. Exact raw order is retained in every observation but is intentionally not part of the exact provider key: some stacks, notably Google/Akamai families in the historical corpus, legitimately randomize transport-parameter serialization.

Only exact signatures that already passed independent-label validation may originate `H3Transport` provider evidence. Structural/family matches remain implementation evidence. In particular, the nginx source-derived relationship does not manufacture a Sucuri/OpenResty/provider attribution by itself.

## Usage

```bash
wireprint h3 --family auto --repeat 2 --vantage acer https://www.cloudflare.com/
```

Successful rows use the ordinary `Observation` JSON schema. The H3 observer fills `h3_server_fingerprint`, `provider_signals`, DNS/routing provenance and `endpoint_assessment`, so saved rows can be fed directly to `wireprint aggregate-host` alongside ordinary HTTP observations.

Because the observer stops at response headers, body-derived semantic `outcome` is deliberately left unset rather than classifying an unseen body as content-like.
