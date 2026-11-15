# Response challenge outcomes (builtin-v2)

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

## Corpus replay

`wireprint classify BODY_FILE --status STATUS [--header NAME:VALUE ...]` performs one ad hoc classification. To replay thousands of **existing** observations, use:

```sh
wireprint classify --input response-rows.jsonl > response-classified.jsonl
```

Each input row must be a JSON object with `status` (integer HTTP status), `headers` (Wireprint header array), and optional `body_prefix` (captured text or null). Output retains all original fields and replaces or writes `outcome` with `kind`, `classifier`, and `evidence`. Invalid types are rejected; an omitted body is **not invented**. Unlike the path classifier, the outcome classifier version is `builtin-v2`.

The archived normalized response-header index has independently verified weighted counts of 749 `CF-Mitigated: challenge`, 21 `X-Amzn-Waf-Action: challenge`, 10 `X-Amzn-Waf-Action: captcha`, and 69 `X-DataDome: protected`. These are response signatures, **not** numbers of distinct hosts or proven user sessions. Full methodology, positive and negative controls, and corpus-replay details live on the focused Notion research page, not in this durable high-level reference.
