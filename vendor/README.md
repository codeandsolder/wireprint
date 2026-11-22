# Temporary btls-sys Cargo patch

This directory contains only the upstream btls-sys crate at
3c1dd080ba617d78c63cd09285d2ce31abcdcbf9 (0.5.6, MIT).
BoringSSL is pinned to the same upstream submodule revision
427ec40cc8edc545253289232e885708c409e5ea. The upstream native patches and
FFI source are unchanged; workspace-inherited manifest fields use their
original explicit values. The only functional changes disable native
test/benchmark configuration and build the ssl target once (it depends on
crypto). The rest of btls remains sourced from its original Git revision.

Initialize the submodule after cloning (\`git submodule update --init\`).
Remove the Cargo patch and this directory after the upstream build
optimization is available at the chosen btls revision. See Wireprint #118.
