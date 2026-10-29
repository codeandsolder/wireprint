# Network path elements

Wireprint recognizes ordinary-response evidence for multiple independent network-path participants. The output is an **unordered participation set**, not a guessed linear topology.

That distinction matters. A response can preserve evidence from an outer CDN, a downstream application platform, an API gateway, a reverse proxy, and bot-management middleware at the same time. A downstream marker does not prove that product terminated the client connection.

## Roles

`builtin-path-v4` currently separates these roles:

- `edge_provider` — managed serving/edge layer with explicit provider evidence;
- `application_platform` — downstream delivery/application platform participation;
- `origin_service` — explicit backend/origin service participation preserved through upstream layers;
- `reverse_proxy` — proxy implementation observed in response metadata;
- `cache` — HTTP cache/proxy participation;
- `load_balancer` — load-balancer-specific cookie or response marker;
- `api_gateway` — API gateway participation;
- `service_mesh` — service-mesh participation;
- `identity_proxy` — identity-aware access proxy participation;
- `traffic_management` — virtual waiting room / request-admission layer participation;
- `waf` — explicit WAF/product evidence;
- `security_middleware` — security/challenge state that is not specific enough to call a WAF;
- `bot_management` — bot-management product evidence;
- `server_implementation` — origin/proxy server implementation evidence that should not be promoted into managed-provider identity.

Each element stores the role, product label, classifier version, and the concrete evidence marker(s) that triggered it.

## Current explicit markers

The v4 recognizer includes:

- edge/provider: Cloudflare, CloudFront, Akamai, Fastly, F5 Distributed Cloud/Volt, Imperva, Sucuri, BunnyCDN, Google Front End, OpenResty Edge, Vercel, Netlify, Fly.io, Railway, KeyCDN, QUIC.cloud, CDN77, Tencent EdgeOne, Alibaba Cloud edge family;
- downstream platforms: Vercel, Netlify, Azure Front Door, Render, Railway, Pantheon, Acquia Cloud Platform, Heroku;
- origin services: Amazon S3, generic S3-compatible object storage, MinIO, Akamai NetStorage, Google Cloud Storage, Azure Blob Storage, Backblaze B2;
- API gateways: AWS API Gateway, Kong, Apache APISIX, KrakenD, Tyk, Gravitee;
- load balancers: AWS Application Load Balancer, AWS Classic Load Balancer, Google Cloud Application Load Balancer, F5 BIG-IP LTM, NetScaler ADC, Azure Application Gateway, Azure/Microsoft ARR affinity family, Cloudflare Load Balancer, Oracle Cloud Load Balancer;
- reverse proxies / caches: Envoy, nghttpx, HAProxy, Traefik, Varnish, Squid, Apache Traffic Server;
- service mesh: Istio when explicitly exposed as `istio-envoy`, and Linkerd when `l5d-*` response markers are exposed;
- identity proxies: Google Cloud IAP, Cloudflare Access, OAuth2 Proxy, Authelia, authentik;
- traffic management: Cloudflare Waiting Room, Queue-it;
- server implementations: nginx, OpenResty, Caddy, Apache HTTP Server, Microsoft IIS, LiteSpeed, Google UploadServer, SFFE, GSE;
- WAF/security: AWS WAF (including `aws-waf-token` state), AWS ALB authentication, Cloudflare security/challenge and rate-limiting state, Imperva WAF, F5 BIG-IP ASM, FortiWeb;
- bot management: Cloudflare Bot Management, Akamai Bot Manager, DataDome, HUMAN/PerimeterX.

Fastly-specific `Fastly-Debug-*`, `fastly-restarts`, `x-fastly-backend-reqs`, and explicit Fastly `Via` responses are treated as Fastly cache participation rather than automatically asserting that Fastly was the outer edge. Generic `X-Cache-Hits` is deliberately excluded because Acquia and Pantheon also emit it. The same conservative rule is used for BunnyCDN's `cdn-*` cache metadata. Railway is different: its own documentation defines `X-Railway-Edge` as the POP that received the request and terminated TLS, so that marker supports an edge-provider claim while `X-Railway-Upstream-Zone` remains downstream platform/origin-zone evidence.

Origin-service markers are deliberately separate from edge identity. `Server: AkamaiNetStorage` is Akamai NetStorage origin evidence, not proof that an Akamai edge terminated the client connection. Likewise, `Server: UploadServer` is kept as a Google server-implementation marker; Google Cloud Storage is only claimed from storage-specific `x-goog-*` response metadata. `x-amz-bucket-region` is only S3-compatible object-storage evidence by itself because non-AWS implementations can emit the S3 header; `Server: AmazonS3` is required for the stronger `aws-s3` label, while `x-minio-deployment-id` identifies MinIO directly.

The v3 additions follow the same positive-evidence rule. CDN77 documents `X-77-POP` as the edge location that handled and delivered the response, while `X-77-Cache` / `X-77-Age` describe cache state; cache-only evidence therefore does not promote itself to `edge_provider`. Oracle Cloud Load Balancer's default generated stickiness cookie `X-Oracle-BMC-LBS-Route` is load-balancer evidence when present. OAuth2 Proxy's `_oauth2_proxy`, Authelia's `authelia_session`, and authentik's `/outpost.goauthentik.io/` redirect namespace are identity-proxy evidence. The OAuth2 Proxy and Authelia cookie names are configurable, so their absence is especially meaningless.

The v4 edge expansion keeps provider identity separate from cache identity. Tencent EdgeOne documents `EO-LOG-UUID` as its request identifier and `Server: TencentEdgeOne` as the node-added fallback server banner, so either can identify EdgeOne participation; `EO-Cache-Status` is cache participation only. Alibaba Cloud documents `EagleID` as an edge/CDN-node marker, but live ESA responses also expose it, so v4 deliberately emits the broader `alibaba-cloud-edge` provider-family label instead of claiming the CDN product. The CDN-specific `X-Swift-SaveTime`, `X-Swift-CacheTime`, and `Ali-Swift-Global-Savetime` headers independently identify `alibaba-cloud-cdn` cache participation. Generic `X-Cache` remains insufficient by itself.

Routing evidence is versioned independently. `builtin-routing-v2` adds Tencent EdgeOne provider-managed edge CNAME families (`*.acc.edgeonedy1.com` and `*.acc.tyxcdn.com`) as `edge_provider` evidence, while `*.eo.dnseN.com` stays on the separate `traffic_management` role: EdgeOne can use that scheduling CNAME to distribute traffic across EdgeOne, another CDN provider, or the origin. If a DNS chain contains both forms, both roles are preserved. Alibaba Cloud edge CNAME roots (`kunlun*.com` plus the documented `alikunlun.com` family) emit the broad `alibaba-cloud-edge` provider family. The same Kunlun CNAME lineage is used by multiple Alibaba delivery products, so DNS alone does not identify one product.

Absence of a marker is not negative evidence. Products can strip, rename, disable, or route around these markers.

## Deliberately conservative rules

The recognizer does **not** treat generic cache vocabulary such as `x-served-by` + `x-cache` as Fastly. That combination already produced a false Fastly attribution for an Azure Front Door route in the research corpus.

Likewise:

- `x-vercel-id`, `x-nf-request-id`, and `x-azure-ref` are participation evidence, not automatic outer-provider claims;
- `ARRAffinity` / `ARRAffinitySameSite` prove an Azure/Microsoft ARR-style affinity layer, not Azure App Service specifically; Application Gateway v1 overlaps on `ARRAffinity`;
- generic `x-amzn-requestid` does not imply API Gateway; API Gateway uses more specific markers such as `x-amz-apigw-id` / `apigw-requestid`;
- `Server: UploadServer` does not imply Google Front End or Cloud Storage by itself;
- gateway/platform request IDs are accepted only when the product documents them as its own generated/default response metadata;
- transport/server implementation evidence does not become managed-provider identity by itself;
- no hop order is inferred from response headers alone.

## Example

A single ordinary response can legitimately yield a set like:

```text
cache: fastly
cache: varnish
bot_management: datadome
```

That is more useful than collapsing everything into one `vendor` field, and more defensible than guessing which internal hop emitted every preserved header.
