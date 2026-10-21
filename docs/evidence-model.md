# Evidence model

Wireprint deliberately keeps independent observations independent.

A useful request observation has at least these axes:

1. **request application identity** — for example `ChatGPT-User`, `Claude-User`, or a neutral control;
2. **agent role** — user fetch, search crawler, training crawler, local client, control;
3. **HTTP header shape** — separate from the semantic identity token;
4. **transport identity** — TLS/H2/H3/client emulation and concrete network endpoint;
5. **source verification** — source-network or authenticated-bot evidence when available;
6. **network-path participation** — explicit evidence for serving edge, downstream platform, proxy/cache, load balancer, API gateway, service mesh, WAF/security, bot-management and server implementation, kept as independent claims rather than one vendor field;
7. **session / reputation state**;
8. **response semantics** — content-like response, redirect, challenge, CAPTCHA, explicit block, rate limit, application error, unknown;
9. **raw provenance** — timestamp, vantage, target, exact ordered request headers, final URI, peer, HTTP version, response headers and bounded captured body prefix.

## Important non-equivalences

- HTTP `200` is not equivalent to content. Reddit currently provides a useful regression example: an HTTP `200` can be a JS challenge shell.
- A User-Agent string does not authenticate a vendor.
- A browser-looking TLS fingerprint does not prove a browser.
- A CDN/edge provider identity does not imply its WAF is enabled.
- A downstream platform/proxy marker does not prove that component is the outer TLS termination provider.
- Response metadata can prove multiple path participants without proving their linear hop order.
- Missing evidence is unknown, not negative evidence.
- Header order and duplicates are evidence; do not round-trip request profiles through unordered maps.

## Safety boundary

The default tool is for ordinary unauthenticated requests and passive/benign differentials. It does not solve CAPTCHAs, forge server-issued state, brute force, authenticate, or send attack payloads.
