build +FLAGS='':
    cargo build {{FLAGS}}

test:
    cargo fmt --all -- --check
    cargo clippy --workspace
    cargo test --workspace --lib --tests
    cargo test --doc --all
