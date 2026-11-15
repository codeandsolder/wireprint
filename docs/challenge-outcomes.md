# Response challenge outcomes (builtin-v3)

`classify_response(status, headers, body)` determines the **observed response action**, separately from the unordered network-path participant recognizer (`builtin-path-v14`). These are different questions: a Cloudflare, DataDome, AWS WAF, or Anubis cookie does not by itself prove a challenge was issued.

## Action-specific evidence

| Kind | Recognized evidence | Limits |
| --- | --- | --- |
| `challenge` | `CF-Mitigated: challenge` | [Cloudflare documents this specific response header on challenged HTML responses](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/). Ordinary `CF-Ray` and Turnstile widgets do not imply a challenge. |
| `challenge` | Both `_cf_chl_opt` and `/cdn-cgi/challenge-platform/` in a captured body | Strong paired Cloudflare interstitial shape. A lone script or documentation mention is insufficient. |
| `challenge` | `X-Amzn-Waf-Action: challenge` | [AWS WAF explicitly identifies challenge responses](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html), usually status 202. |
| `captcha` | `X-Amzn-Waf-Action: captcha` | [AWS WAF specifies this CAPTCHA response action](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html), usually status 405. |
| `challenge` | Both `<script id="anubis_version">` and `<script id="anubis_challenge">` in the captured body | Anubis-authored page structure; only actual script tags count. A cookie alone identifies participation, not an active challenge. |
| `captcha` | DataDome `X-DataDome: protected` or recognized captive CAPTCHA body | Existing v1 behavior preserved. |
| `challenge` | Paired Reddit JS challenge form markers or AWSWAF challenge body | Existing v1 behavior preserved. |

These checks run before generic HTTP status handling, so a 200 challenge page, 403 Cloudflare challenge, or 405 AWS WAF CAPTCHA is not misclassified as ordinary content, a generic block, or an application error. The remaining 429, 401/403, redirect, server error and content rules are unchanged.

## Additional reviewed first-party document gates (builtin-v3)

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

## Corpus replay

`wireprint classify BODY_FILE --status STATUS [--header NAME:VALUE ...]` performs one ad hoc classification. To replay thousands of **existing** observations, use:

```sh
wireprint classify --input response-rows.jsonl > response-classified.jsonl
```

Each input row must be a JSON object with `status` (integer HTTP status), `headers` (Wireprint header array), and optional `body_prefix` (captured text or null). Output retains all original fields and replaces or writes `outcome` with `kind`, `classifier`, and `evidence`. Invalid types are rejected; an omitted body is **not invented**. Unlike the path classifier, the outcome classifier version is `builtin-v3`.

The archived normalized response-header index has independently verified weighted counts of 749 `CF-Mitigated: challenge`, 21 `X-Amzn-Waf-Action: challenge`, 10 `X-Amzn-Waf-Action: captcha`, and 69 `X-DataDome: protected`. These are response signatures, **not** numbers of distinct hosts or proven user sessions. Full methodology, positive and negative controls, and corpus-replay details live on the focused Notion research page, not in this durable high-level reference.
