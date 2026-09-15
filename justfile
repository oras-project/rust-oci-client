build +FLAGS='':
    cargo build {{FLAGS}}

doc:
    RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --workspace --all-features --no-deps

test: && test-native-tls check-rustls-tls-no-provider
    cargo fmt --all -- --check
    cargo clippy --workspace
    cargo test --workspace --lib --tests
    cargo test --doc --all

# The full test suite under the OpenSSL (native-tls) backend.
test-native-tls:
    cargo test --workspace --lib --tests --no-default-features --features native-tls,test-registry

# rustls-tls-no-provider cannot run the test suite: it has no crypto provider
# until the embedding application installs one. A compile check is the
# strongest test available for this backend.
check-rustls-tls-no-provider:
    cargo check --no-default-features --features rustls-tls-no-provider,test-registry

check-deny:
    cargo deny  --all-features check bans licenses sources advisories
