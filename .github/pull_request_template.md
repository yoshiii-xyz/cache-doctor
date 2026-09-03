## Scope

- [ ] The change stays within bounded, read-only Cargo cache evidence.
- [ ] No network access, installation, registry login, or secret values were
      added.
- [ ] No private paths or generated fuzz corpus files are included.

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo check --all-targets --locked`
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --all-targets --locked`
- [ ] `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked`
- [ ] `cargo package --locked`
- [ ] `cargo audit`
