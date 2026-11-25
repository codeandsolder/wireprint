# Coordinated TLS and transport dependency updates

Wireprint uses one unprefixed BoringSSL provider for its direct TLS observer, Wreq browser emulations and quiche QUIC. The Cargo btls-sys package has native links = "btls", so different Git revisions of btls-sys cannot coexist. A mechanically independent digest update is therefore not a valid way to upgrade the TLS stack.

The Wreq fork pins btls, btls-sys and tokio-btls as a group. Wireprint's direct btls and btls-sys dependencies **must** use that same revision; its direct wreq and [patch.crates-io].wreq entries **must** use the same Wreq Git commit. The wreq-util publication from cargo-patches must internally pin that same Wreq commit. Renovate excludes those four dependency names in Wireprint, but continues to update other dependencies such as quiche normally. Match their Renovate depName (Cargo crate aliases), not packageName (the underlying Git repository URL).

To upgrade:

1. Choose and validate the upstream btls commit, and update all three Git revisions in codeandsolder/wreq-exp together. Regenerate its Cargo.lock and run its CI, including the full browser-profile compatibility test.
2. Merge the Wreq change, update the shared cargo-patches wreq-util publication to pin that commit, then update all five corresponding dependency entries in Wireprint: btls, btls-sys, wreq, wreq-util (the new publication tag), and the Wreq patch entry. Regenerate Wireprint's Cargo.lock.
3. Verify cargo metadata --locked --format-version 1, strict Rust/Clippy gates and the duplicate-code regression gate. Check that Cargo resolves exactly one btls-sys provider.
4. Run a real HTTPS TLS 1.3 observation and an HTTP/3 observation to confirm the handshake and ordered QUIC transport-parameter capture, then merge the Wireprint PR.

The explicit Git pins are part of the observed wire fingerprint. Do not silently advance them in a lockfile refresh or introduce a second native TLS provider. Changing a profile intentionally requires fingerprint-differential tests rather than assuming source/API compatibility is enough.
