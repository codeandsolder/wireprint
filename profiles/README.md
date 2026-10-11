# Request profiles

Profiles are inputs, not identities proven by the network.

- `ai-retrievers-observed.json` keeps the closest cheaply reproducible HTTP header shapes currently documented or independently observed in the research corpus.
- `ai-retrievers-normalized.json` keeps the same User-Agent/application-identity tokens but normalizes the rest of the request to `Accept: */*` for attribution experiments.

A named profile such as `ChatGPT-User` or `Claude-User` **does not authenticate the sender as that vendor**. Production systems may additionally validate source networks, authenticated-bot mechanisms, transport fingerprints, reputation, or session state.

Transport fidelity is intentionally separate. When a live fetcher capture becomes available, add or update a transport profile rather than silently editing the request profile to imply that the whole wire image is known.

## Schema note

`headers` is an **ordered array** of `{name, value}` objects rather than a JSON map. This is deliberate: ordering can itself be fingerprintable, and duplicate header fields must remain representable. Wireprint sends the entries in profile order and records the same ordered list in every observation.
