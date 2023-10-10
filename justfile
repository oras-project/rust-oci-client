build +FLAGS='':
    cargo build {{FLAGS}}
    cargo build {{FLAGS}} --features=extension-rss

test:
    cargo fmt --all -- --check
    cargo clippy --workspace
    cargo test --workspace --lib
    cargo test --doc --all
    cargo test --workspace --lib --features=extension-rss
