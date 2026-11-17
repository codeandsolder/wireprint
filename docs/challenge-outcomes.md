# Response challenge outcomes (builtin-v6)

`classify_response(status, headers, body)` determines the **observed response action**, separately from the unordered network-path participant recognizer (`builtin-path-v14`). These are different questions: a Cloudflare, DataDome, AWS WAF, or Anubis cookie does not by itself prove a challenge was issued.

## Action-specific evidence

| Kind | Recognized evidence | Limits |
| --- | --- | --- |
| `challenge` | `CF-Mitigated: challenge` | [Cloudflare documents this specific response header on challenged HTML responses](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/). Ordinary `CF-Ray` and Turnstile widgets do not imply a challenge. |
| `challenge` | Both `_cf_chl_opt` and `/cdn-cgi/challenge-platform/` in a captured body | Strong paired Cloudflare interstitial shape. A lone script or documentation mention is insufficient. |
| `challenge` | `X-Amzn-Waf-Action: challenge` | [AWS WAF explicitly identifies challenge responses](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html), usually status 202. |
| `captcha` | `X-Amzn-Waf-Action: captcha` | [AWS WAF specifies this CAPTCHA response action](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html), usually status 405. |
| `challenge` | Both `<script id="anubis_version">` and `<script id="anubis_challenge">` in the captured body | Anubis-authored page structure; only actual script tags count. A cookie alone identifies participation, not an active challenge. |
| `challenge` | DataDome first-party browser-check shell with `var dd` runtime `rt:'i'` | Device verification, not automatically an interactive CAPTCHA. `X-DataDome: protected` alone is neutral. |
| `captcha` | DataDome first-party CAPTCHA shell with `var dd` runtime `rt:'c'` | Complete bounded runtime descriptor and vendor challenge host required. |
| `challenge` | Paired Reddit JS challenge form markers or AWSWAF challenge body | Existing v1 behavior preserved. |

These checks run before generic HTTP status handling, so a 200 challenge page, 403 Cloudflare challenge, or 405 AWS WAF CAPTCHA is not misclassified as ordinary content, a generic block, or an application error. The remaining 429, 401/403, redirect, server error and content rules are unchanged.

## Additional reviewed first-party document gates (builtin-v4)

The full archived browser-body census completed **all 5,650 capture directories** using 29 persisted chunks: 26,634 document responses, 20,009 saved readable body prefixes, and 4,212 **broad marker candidates**. That last number is *not* an observed challenge count: 2,084 document matches contain reCAPTCHA references, many on ordinary pages. Source inspection separated actual first-party interstitials from SDKs, documentation and third-party widgets.

| Outcome | Strong observed body evidence | Source and negative controls |
| --- | --- | --- |
| `captcha` | Tencent Cloud EdgeOne branded `Security Verification` document **and** `TEOCaptchaWidgetV1-global.js` **and** `Protected by Tencent Cloud EdgeOne` | First-party archived `apkpure.net`, status 200, not normal content. [Tencent documents EdgeOne's CAPTCHA Page feature](https://www-sg.tencentcloud.com/ind/document/product/1145/82077). A widget or footer alone is insufficient. |
| `challenge` | Full-page `Client Challenge` plus paired disabled-JavaScript / enable-JavaScript-to-proceed instructions | Archived HTTP 200 interstitial on CNET and Softonic; an ordinary site requiring JavaScript is not sufficient. |
| `challenge` | `Pardon Our Interruption` **and** browser identified as bot-like | Five archived HTML 200 documents across `www.boots.com` and `www.zacks.com`. Regular Imperva/Incapsula scripts in normal pages and a title-only mention are negatives. |
| `captcha` | Denied document (403 or 429) **and** `px-captcha` **and** a `Press & Hold` human check | One archived first-party `www.dreamstime.com` 403. The same JS integration on an ordinary 200 page or a lone press-and-hold phrase is not a challenge. |
| `challenge` | Denied document (403) **and** `Verify you are human` **and** `challenges.cloudflare.com/turnstile/v0/api.js` | One archived `liquipedia.net` verification gate. [Cloudflare distinguishes embedded Turnstile widgets from interstitial Challenge Pages](https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/). A Turnstile widget on a normal 200 app is *not* an HTTP challenge. |
| `challenge` | `Security verification in progress`, `verify your browser to protect against automated access` **and** `Verifying connection` | One archived first-party `discussions.apple.com` 200. Generic security-verification documentation/title alone is negative. |
| `explicit_block` (enriched evidence) | 401/403 body has both `Sucuri Website Firewall` and `Access Denied` | One archived `www.medsengage.com` 403; same kind as v2 but extra `body:sucuri-website-firewall` evidence. No extra WAF edge-role claim. |

These are **response outcome** rules only, not new network-path participants, not claims about client-facing TLS peers, and not assertions that a challenge was successfully solved. Real original HTML bodies stay in the local corpus; the Git repository contains authored synthetic regressions and high-level source descriptions. The replay script can extract small selected positive/negative first-party bodies from the archive to verify the rules independently.

**Intentionally excluded:** reCAPTCHA/hCaptcha/Arkose scripts on ordinary pages, HUMAN/PerimeterX JavaScript SDKs without an active press-and-hold CAPTCHA, Kasada `k.twitchcdn.net` 429 with a script but no verified challenge outcome, and ordinary Cloudflare challenge-platform subresource references without paired bootstrap evidence. Avoid converting broad census marker presence into a claimed enforcement event.

## Further saved browser challenge gates (builtin-v4)

Two additional actual **root-frame** archived HTML interstitials were inspected using the already-checkpointed first-party document-body index; no full archive rescan was needed.

- **Hostinger CDN JS challenge**: `/hcdn-cgi/jschallenge` embedded in an HTML document **and** `Checking your browser before accessing` in the body. Real `affcommunity.org` HTTP 403, server `hcdn`, matched independently by documented [browser-check reports](https://www.gdgsoft.info/t/setting-up-trial-versions.8077/) and [observed HTTP traffic](https://tria.ge/260621-ak2ghsaw9l/behavioral1). This is a challenge action in the response, not proof of the actual client-facing TLS endpoint; `Server: hcdn` alone cannot establish a challenge.
- **Unattributed security-verification JavaScript/robot check**: a full-page `Security Verification` together with `verify that you are not a robot`, `This requires JavaScript`, and `Enable JavaScript and then reload the page`. Real `netflix.apponic.com` HTTP 405 with no authenticated WAF action header. It is classified as `challenge`, **not necessarily CAPTCHA**, and **no vendor identity is inferred**. If a documented `X-Amzn-Waf-Action: captcha` header is independently present, that takes precedence over this generic body interpretation.

Both detectors require paired body evidence. Source-reviewed 200 success pages containing only generic JS requirements, hcdn branding, a script path mentioned in documentation, or ordinary security forms are negative controls. The original HTML body bytes stay in the archive; a reproducible fixture manifest records exact capture IDs and SHA-256 hashes.

## Dedicated reCAPTCHA browser-verification documents (builtin-v5)

The archived NIH PubMed and PMC captures include genuine first-party root-frame
HTTP 200 documents containing the Google-authored title
`Checking your browser - reCAPTCHA`, the reserved document base
`https://www.google.com/recaptcha/challengepage/`, and the
`RecaptchaChallengePageUi` bootstrap. Their visible message states the
browser is being checked before it can access the requested page.

Wireprint treats this complete **three-part document shell** as an active
`challenge` (evidence `body:recaptcha-challengepage+browser-check`),
not a demonstrated interactive `captcha` puzzle. Ordinary embedded
reCAPTCHA forms, script references, documentation, title-only pages and
incomplete marker combinations are negative controls. Authenticated
response-action headers continue to take precedence.

The two original document bodies and their SHA-256 identifiers remain in
the preserved browser archive. A targeted independently checked source
manifest and reproducible replay script live outside this repository.

## DataDome presence versus enforced response (builtin-v6)

`X-DataDome: protected` is a presence/protection header, **not a CAPTCHA
action header**. It can accompany ordinary content, device verification,
or an interactive CAPTCHA. This is documented in DataDome's
[Protection API](https://docs.datadome.co/reference/validate-request),
[response-page taxonomy](https://docs.datadome.co/docs/response-pages)
and [Device Check](https://docs.datadome.co/docs/device-check) reference.

A source-backed complete first-party challenge document must have the
visible `Please enable JS and disable any ad blocker` message and a bounded
inline `dd` runtime object pointing at a `captcha-delivery.com` challenge
host. Its runtime type determines the actual response:

| Type | Observed action | Evidence |
| --- | --- | --- |
| `rt:'i'` | `challenge` (device/browser check) | `body:datadome-device-check` |
| `rt:'c'` | `captcha` | `body:datadome-captcha` |

The archived first-party body reduction contains **10 normal HTTP 200
responses** carrying the DataDome header, **44 denied device checks**
(401/403, `rt:'i'`), and **2 CAPTCHA responses** (403, `rt:'c'`).
Separate 200 responses served by `geo.captcha-delivery.com` as
challenge-service subdocuments do not automatically describe the outcome
of the first-party page. Header-only observations fall through to the
ordinary status-based classifier rather than fabricating an action.
Generic vendor script references, captions or `captcha-delivery.com`
mentions do not prove enforcement. Explicit AWS and Cloudflare action
headers still win.

The previous normalized header-only replay labeled **all 69**
`X-DataDome: protected` signatures as CAPTCHA, including **22 HTTP 200**
signatures. The revised independent replay instead treats these as
presence controls. Detailed source audit, SHA-bound cases and replay
oracle: separate Notion outcome-v6 study.

## Corpus replay

`wireprint classify BODY_FILE --status STATUS [--header NAME:VALUE ...]` performs one ad hoc classification. To replay thousands of **existing** observations, use:

```sh
wireprint classify --input response-rows.jsonl > response-classified.jsonl
```

Each input row must be a JSON object with `status` (integer HTTP status), `headers` (Wireprint header array), and optional `body_prefix` (captured text or null). Output retains all original fields and replaces or writes `outcome` with `kind`, `classifier`, and `evidence`. Invalid types are rejected; an omitted body is **not invented**. Unlike the path classifier, the outcome classifier version is `builtin-v6`.

The archived normalized response-header index has independently verified weighted counts of 749 `CF-Mitigated: challenge`, 21 `X-Amzn-Waf-Action: challenge`, 10 `X-Amzn-Waf-Action: captcha`, and 69 `X-DataDome: protected` **presence** signatures. These are weighted response-signature counts, **not** numbers of distinct hosts, enforced CAPTCHA actions or proven user sessions. Full methodology, positive and negative controls, and corpus-replay details live on the focused Notion research page, not in this durable high-level reference.
