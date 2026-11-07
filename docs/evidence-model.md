# Evidence model

Wireprint deliberately keeps independent observations independent.

A useful request observation has at least these axes:

1. **request application identity** — for example `ChatGPT-User`, `Claude-User`, or a neutral control;
2. **agent role** — user fetch, search crawler, training crawler, local client, control;
3. **HTTP header shape** — separate from the semantic identity token;
4. **transport identity** — TLS/H2/H3/client emulation and concrete network endpoint; live H2 preserves peer SETTINGS/window/control order, while the H3 observer additionally preserves ordered peer SETTINGS and the raw TLS-authenticated QUIC transport-parameter extension before normalization;
5. **source verification** — source-network or authenticated-bot evidence when available;
6. **network-path participation** — explicit evidence for serving edge, downstream platform/origin service, proxy/cache, load balancer, API gateway, service mesh, WAF/security, bot-management and server implementation, kept as independent claims rather than one vendor field;
7. **session / reputation state**;
8. **response semantics** — content-like response, redirect, challenge, CAPTCHA, explicit block, rate limit, application error, unknown;
9. **raw provenance** — timestamp, vantage, target, declared ordered request-profile headers, final URI, peer, HTTP version, response headers and bounded captured body prefix;
10. **hostname history** — freshness-gated current provider membership, historical provider membership, protocol/vantage/endpoint route groups and deduplicated independent support groups.

## Important non-equivalences

- HTTP `200` is not equivalent to content. Reddit currently provides a useful regression example: an HTTP `200` can be a JS challenge shell.
- A User-Agent string does not authenticate a vendor.
- A browser-looking TLS fingerprint does not prove a browser.
- A CDN/edge provider identity does not imply its WAF is enabled.
- A downstream platform/proxy marker does not prove that component is the outer TLS termination provider.
- Response metadata can prove multiple path participants without proving their linear hop order.
- Missing evidence is unknown, not negative evidence.
- Historical provider evidence cannot resurrect a provider into the current set; it may only corroborate a provider that has fresh originating evidence.
- Host aggregation recomputes the current endpoint fusion assessment from raw saved observations; it does not trust a stale serialized endpoint assessment from an older classifier.
- Repeated requests are observations, not votes. Independent support is keyed by channel, protocol, vantage, endpoint and time bucket.
- Multi-provider/path-split state is preserved rather than collapsed to a numeric winner.
- ASN/prefix ownership describes the concrete selected/peer network context only. It does not originate or corroborate provider identity; hostname-wide DNS candidates must not be substituted for the actual serving endpoint.
- `pure_in_sample` routing-audit output is a corpus statistic, not a provider-mapping recommendation. Repeated requests do not improve ASN purity; distinct hostnames are the audit unit.
- Independent routing DNS now retains per-query A/AAAA answer groups rather than one merged CNAME path. Each group preserves RR owner/target CNAME links, exact returned IPs, an unambiguous chain from the requested host, and only those terminal addresses whose RR owner concludes that chain. Endpoint-v4 requires individual DNS evidence tokens to bind to the selected peer in the **same** answer group before originating/corroborating termination; matched address union membership alone cannot bind CloudFront IPv6 CNAME evidence to a Fastly IPv4 socket. All alternative route names remain participation evidence. DNS-v2 deliberately changes the raw observation schema; old ungrouped snapshots cannot contribute DNS termination votes.
- `connection_address_family` (`auto`, `ipv4`, `ipv6`) records the connector address-family policy in each successful or error observation. Only actual dial candidates are family-filtered; the independently captured routing DNS snapshot still includes available A and AAAA records so the selected peer can be checked for consistency.
- The Wreq and separate Hyper/Rustls HTTP transports both honor `probe --family` and `matrix --family`. Existing TLS and H3 observers use the same shared typed family selector. A strict-family DNS miss is an error, never a silent fallback to a different address family. Historical observations without this field deserialize as `auto`, meaning that no explicit family restriction was imposed.
- Header order and duplicates are evidence; do not round-trip request profiles through unordered maps.

## Safety boundary

The default tool is for ordinary unauthenticated requests and passive/benign differentials. It does not solve CAPTCHAs, forge server-issued state, brute force, authenticate, or send attack payloads.
