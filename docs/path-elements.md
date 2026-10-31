# Network path elements

Wireprint recognizes ordinary-response evidence for multiple independent network-path participants. The output is an **unordered participation set**, not a guessed linear topology.

That distinction matters. A response can preserve evidence from an outer CDN, a downstream application platform, an API gateway, a reverse proxy, and bot-management middleware at the same time. A downstream marker does not prove that product terminated the client connection.

## Roles

`builtin-path-v7` currently separates these roles:

- `edge_provider` — managed serving/edge layer with explicit provider evidence;
- `application_platform` — downstream delivery/application platform participation;
- `origin_service` — explicit backend/origin service participation preserved through upstream layers;
- `reverse_proxy` — proxy implementation observed in response metadata;
- `cache` — HTTP cache/proxy participation;
- `load_balancer` — load-balancer-specific cookie or response marker;
- `api_gateway` — API gateway participation;
- `service_mesh` — service-mesh participation;
- `identity_proxy` — identity-aware access proxy participation;
- `traffic_management` — traffic steering/orchestration or request-admission layer participation;
- `waf` — explicit WAF/product evidence;
- `security_middleware` — security/challenge state that is not specific enough to call a WAF;
- `bot_management` — bot-management product evidence;
- `server_implementation` — origin/proxy server implementation evidence that should not be promoted into managed-provider identity.

Each element stores the role, product label, classifier version, and the concrete evidence marker(s) that triggered it.

## Current explicit markers

The v7 recognizer includes:

- edge/provider: Cloudflare, CloudFront, Akamai, Fastly, F5 Distributed Cloud/Volt, Imperva, Sucuri, BunnyCDN, Google Front End, OpenResty Edge, Vercel, Netlify, Fly.io, Railway, KeyCDN, QUIC.cloud, CDN77, Tencent EdgeOne, Alibaba Cloud edge family;
- downstream platforms: Vercel, Netlify, Azure Front Door, Render, Railway, Pantheon, Acquia Cloud Platform, Heroku, GitHub;
- origin services: Amazon S3, generic S3-compatible object storage, MinIO, Akamai NetStorage, Google Cloud Storage, Azure Blob Storage, Alibaba OSS, Backblaze B2;
- API gateways: AWS API Gateway, Kong, Apache APISIX, KrakenD, Tyk, Gravitee;
- load balancers: AWS Application Load Balancer, AWS Classic Load Balancer, Google Cloud Application Load Balancer, F5 BIG-IP LTM, NetScaler ADC, Azure Application Gateway, Azure/Microsoft ARR affinity family, Cloudflare Load Balancer, Oracle Cloud Load Balancer;
- reverse proxies / caches: Fastly Image Optimizer, Akamai cache, Hostinger CDN cache, LiteSpeed cache/Web ADC, Envoy, nghttpx, HAProxy, Traefik, Varnish, Squid, Apache Traffic Server;
- service mesh: Istio when explicitly exposed as `istio-envoy`, and Linkerd when `l5d-*` response markers are exposed;
- identity proxies: Google Cloud IAP, Cloudflare Access, OAuth2 Proxy, Authelia, authentik;
- traffic management: IO River, Cloudflare Waiting Room, Queue-it;
- server implementations: nginx, OpenResty, Caddy, Apache HTTP Server, Microsoft IIS, LiteSpeed, Google UploadServer, SFFE, GSE;
- WAF/security: AWS WAF (including `aws-waf-token` state), AWS ALB authentication, Cloudflare security/challenge and rate-limiting state, Imperva WAF, F5 BIG-IP ASM, FortiWeb;
- bot management: Cloudflare Bot Management, Akamai Bot Manager, DataDome, HUMAN/PerimeterX.

Fastly-specific `Fastly-Debug-*`, `fastly-restarts`, `x-fastly-backend-reqs`, explicit Fastly `Via` responses, and `X-Timer` values matching Fastly's documented `S{unixStartTimeSeconds},VS0,VE{durationMilliseconds}` grammar are treated as Fastly cache participation rather than automatically asserting that Fastly was the outer edge. The value-shape check is deliberate: the historical corpus also contains unrelated numeric `X-Timer` values, so the header name alone is not sufficient despite Fastly documenting its own generated form as proprietary. Generic `X-Cache-Hits` is deliberately excluded because Acquia and Pantheon also emit it. The same conservative rule is used for BunnyCDN's `cdn-*` cache metadata. Railway is different: its own documentation defines `X-Railway-Edge` as the POP that received the request and terminated TLS, so that marker supports an edge-provider claim while `X-Railway-Upstream-Zone` remains downstream platform/origin-zone evidence.

Path v7 also recognizes an Akamai Global Request Number carried in the observed `X-CDN-TraceID` header, but only when the value has the documented GRN shape `0.<hex>.<decimal timestamp>.<hex>`. Akamai documents GRNs as identifiers generated on its edge network and allows the response-header name to be customer-configured. The value grammar is therefore the provider evidence; `X-CDN-TraceID` presence alone is not. Historical negative controls on `vcf.bing.com` use a different `...-WAW` value form and are deliberately excluded. Arbitrary headers containing a GRN-looking string are also not matched.

Path v7 expands response provenance using provider-documented markers found by a wide historical-header census and then validated compositionally rather than from co-occurrence alone. `X-HCDN-Request-ID` identifies Hostinger CDN delivery while `X-HCDN-Cache-Status` is a separate Hostinger cache role. `Akamai-Cache-Status` likewise contributes `cache: akamai` without upgrading itself into an outer-edge claim. Fastly Image Optimizer's documented `Fastly-IO-Info`, `Fastly-Stats`, warning, and error response headers contribute Fastly cache/transform participation; they can coexist with a different outer edge or preserved origin metadata.

The same release broadens downstream and origin provenance. Azure Front Door's reserved `X-MSEdge-Ref` joins `X-Azure-Ref` as application-platform participation only. Current `Via: ... heroku-router` values join legacy `vegur` as Heroku platform evidence. `X-Railway-Request-Id` adds Railway platform evidence without implying TLS termination, while `X-Railway-Edge` remains the stronger edge marker. `X-GitHub-Request-Id` identifies GitHub platform participation. Google Cloud Storage now accepts its documented `X-Guploader-UploadID` and stored-content response headers; Azure Blob accepts `X-MS-Access-Tier`; Alibaba OSS accepts `X-OSS-Request-ID` or `Server: AliyunOSS`. These remain origin-service claims even when Cloudflare, Akamai, Fastly, CDN77, or another delivery layer preserves them.

Finally, `X-IORiver` is deliberately modeled as `traffic_management: ioriver`, not as a serving CDN. IO River documents that the header is present on traffic served through its service and that the header value identifies the CDN provider actually handling the request. This lets one response correctly preserve both the orchestration layer and the concrete downstream CDN/cache participant.

Origin-service markers are deliberately separate from edge identity. `Server: AkamaiNetStorage` is Akamai NetStorage origin evidence, not proof that an Akamai edge terminated the client connection. Likewise, `Server: UploadServer` is kept as a Google server-implementation marker; Google Cloud Storage is only claimed from storage-specific `x-goog-*` response metadata. `x-amz-bucket-region` is only S3-compatible object-storage evidence by itself because non-AWS implementations can emit the S3 header. The stronger `aws-s3` label accepts `Server: AmazonS3` or the paired S3 extended/request-ID response headers when `x-amz-request-id` has the 16-character uppercase-alphanumeric form observed in current AWS general-purpose S3 responses. This shape constraint is deliberate: historical controls include Scaleway/Ceph `tx...` IDs, 32-hex IDs, UUIDs, and `HEX:B` IDs alongside `x-amz-id-2`. `x-minio-deployment-id` continues to identify MinIO directly.

The v3 additions follow the same positive-evidence rule. CDN77 documents `X-77-POP` as the edge location that handled and delivered the response, while `X-77-Cache` / `X-77-Age` describe cache state; cache-only evidence therefore does not promote itself to `edge_provider`. Oracle Cloud Load Balancer's default generated stickiness cookie `X-Oracle-BMC-LBS-Route` is load-balancer evidence when present. OAuth2 Proxy's `_oauth2_proxy`, Authelia's `authelia_session`, and authentik's `/outpost.goauthentik.io/` redirect namespace are identity-proxy evidence. The OAuth2 Proxy and Authelia cookie names are configurable, so their absence is especially meaningless.

The v4 edge expansion keeps provider identity separate from cache identity. Tencent EdgeOne documents `EO-LOG-UUID` as its request identifier and `Server: TencentEdgeOne` as the node-added fallback server banner, so either can identify EdgeOne participation; `EO-Cache-Status` is cache participation only. Alibaba Cloud documents `EagleID` as an edge/CDN-node marker, but live ESA responses also expose it, so v4 deliberately emits the broader `alibaba-cloud-edge` provider-family label instead of claiming the CDN product. The CDN-specific `X-Swift-SaveTime`, `X-Swift-CacheTime`, and `Ali-Swift-Global-Savetime` headers independently identify `alibaba-cloud-cdn` cache participation. Generic `X-Cache` remains insufficient by itself.

Routing evidence is versioned independently. `builtin-routing-v2` adds Tencent EdgeOne provider-managed edge CNAME families (`*.acc.edgeonedy1.com` and `*.acc.tyxcdn.com`) as `edge_provider` evidence, while `*.eo.dnseN.com` stays on the separate `traffic_management` role: EdgeOne can use that scheduling CNAME to distribute traffic across EdgeOne, another CDN provider, or the origin. If a DNS chain contains both forms, both roles are preserved. Alibaba Cloud edge CNAME roots (`kunlun*.com` plus the documented `alikunlun.com` family) emit the broad `alibaba-cloud-edge` provider family. The same Kunlun CNAME lineage is used by multiple Alibaba delivery products, so DNS alone does not identify one product.

`builtin-routing-v3` expands exact provider-managed DNS coverage without broad suffix guessing. Akamai now covers its documented production/shared-certificate edge hostname families (`edgekey.net`, `edgesuite.net`, `akamaized.net`, `akamaihd.net`) and their documented staging counterparts (`edgekey-staging.net`, `edgesuite-staging.net`). QUIC.cloud routing recognizes only the assigned CDN CNAME grammar (`c<digits>.tier1.quicns.com`); generic `quicns.com` names such as provider DNS nameservers are intentionally not edge-provider evidence.

`builtin-routing-v4` adds exact provider-managed public application hostnames where current provider documentation also identifies the client-facing global edge. Railway HTTP/HTTPS service names match exactly one label under `up.railway.app` and emit `edge_provider: railway`; its separate `proxy.rlwy.net` raw-TCP proxy namespace is intentionally excluded. Fly Apps match exactly one label under `fly.dev` and emit `edge_provider: fly-io`. Neither rule infers provider identity from IP/ASN ownership or arbitrary custom domains.

`builtin-routing-v5` corrects the Vercel/Netlify ingress-role boundary. Exact Vercel serving names (`cname.vercel-dns.com`, one-label `*.vercel-dns-<digits>.com`, and one-label `*.vercel.app`) now emit both `edge_provider: vercel` and `application_platform: vercel`; authoritative nameservers such as `ns1.vercel-dns.com` are explicitly outside that grammar. Exact Netlify ingress names (one-label `*.netlify.app` and `apex-loadbalancer.netlify.com`) likewise emit both edge-provider and application-platform participation. Legacy/broader `*.netlify.com` names remain platform-only unless they are the documented apex load balancer. No rule infers either provider from generic A/AAAA records, ASN ownership, or arbitrary custom domains.

`builtin-routing-v6` corrects the legacy Azure CDN namespace role. Exactly one endpoint label under `azureedge.net` or `vo.msecnd.net` emits the broad `edge_provider: azure-cloud-edge` family. Microsoft still documents both namespaces as Azure CDN delivery names, while `azureedge.net` can be retained across migration to Azure Front Door and current examples can resolve through newer Microsoft edge infrastructure. DNS therefore identifies the Azure-managed delivery family without overclaiming the active product engine. The specific `azurefd.net` namespace remains `edge_provider: azure-front-door`; if one observed DNS chain exposes both a legacy family name and an `azurefd.net` name, the routing classifier refines the broad family into the specific Front Door claim while preserving both CNAMEs as evidence, avoiding two fake competing termination candidates. Response-only `x-azure-ref` remains application-platform participation and cannot originate an outer-provider candidate by itself. Parent domains, deeper lookalikes and arbitrary Azure-owned names are excluded.

`builtin-routing-v7` expands provider-managed application-platform DNS provenance without promoting hosting names into outer termination. Specific `azurefd.net` Front Door routing names, Railway `*.up.railway.app`, and Fly `*.fly.dev` retain their existing edge-provider claims and now also emit their matching application-platform role. Exact Render `*.onrender.com`, bounded Heroku `herokuapp.com` / `herokudns.com` / `herokuspace.com` targets, and one-label Pantheon `*.pantheonsite.io` names emit application-platform evidence only. Acquia's documented two-label default environment names under `acquia-sites.com` emit both `application_platform: acquia-cloud-platform` and `origin_service: acquia-cloud-platform`, reflecting Acquia's documented direct-origin/CDN-bypass semantics; three-label SSH management names such as `site.ssh.prod.acquia-sites.com` are excluded. Render validation-only `renderdns.com` names, parent domains, and deeper lookalikes are likewise excluded. These participation/origin roles remain non-originating in endpoint fusion.

`builtin-routing-v8` begins explicit managed-origin DNS provenance and fixes an Akamai specificity bug. Akamai NetStorage HTTP API/origin hostnames matching exactly one non-empty `<prefix>-nsu.akamaihd.net` label now emit `origin_service: akamai-netstorage` before the broader `akamaihd.net` edge-family rule, so they no longer become false `edge_provider: akamai` claims; other recognized Akamai delivery names keep their existing edge semantics. Exact `c.storage.googleapis.com` emits `origin_service: google-cloud-storage`; exactly one account label under `blob.core.windows.net` emits `origin_service: azure-blob-storage`; and exact Backblaze S3 regional/service forms `s3.<region>.backblazeb2.com` and `<bucket>.s3.<region>.backblazeb2.com` emit `origin_service: backblaze-b2`. AWS S3 public data endpoints are matched as an explicit family table: both the standard `amazonaws.com` and China `amazonaws.com.cn` roots accept exact S3 service endpoints plus documented legacy/global, regional virtual-hosted (including dotted bucket names), dash-region compatibility, and regional dual-stack bucket forms; the standard partition additionally accepts documented Transfer Acceleration, single-region access points with a 12-digit account ID, and MRAP `*.mrap.accesspoint.s3-global.amazonaws.com` names. These forms emit `origin_service: aws-s3`. Website endpoints, Object Lambda, Outposts, private/VPC-specific names, malformed access points, Azure `asverify` validation names, static-website endpoints, parent/deeper lookalikes, and arbitrary provider-owned names are excluded. All of these origin roles remain non-originating in endpoint fusion.

Absence of a marker is not negative evidence. Products can strip, rename, disable, or route around these markers.

## Deliberately conservative rules

The recognizer does **not** treat generic cache vocabulary such as `x-served-by` + `x-cache` as Fastly. That combination already produced a false Fastly attribution for an Azure Front Door route in the research corpus.

Likewise:

- `x-vercel-id`, `x-nf-request-id`, and `x-azure-ref` response markers are participation evidence, not automatic outer-provider claims; routing-v5 exact provider-managed ingress names are a separate DNS evidence channel;
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
