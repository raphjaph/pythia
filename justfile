watch +args='test':
  cargo watch --clear --exec '{{args}}'

run: 
  RUST_LOG=info cargo run

fmt:
  cargo fmt --all

clippy:
  cargo clippy --all --all-targets -- --deny warnings

ci: clippy
  cargo fmt -- --check
  cargo test --all
  cargo test --all -- --ignored
