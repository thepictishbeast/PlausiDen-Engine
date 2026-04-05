default: check-all

# Run all checks
check-all: fmt clippy test wasm-check

# Build all crates
build:
    cargo build --workspace

# Run all tests
test:
    cargo test --workspace

# Check formatting
fmt:
    cargo fmt --all -- --check

# Format all code
fmt-fix:
    cargo fmt --all

# Run clippy lints
clippy:
    cargo clippy --workspace -- -D warnings

# Verify engine-browser compiles to WASM
wasm-check:
    cargo check --target wasm32-unknown-unknown -p engine-browser

# Build WASM output for engine-browser
build-wasm:
    wasm-pack build engine-browser --target web

# Generate documentation
doc:
    cargo doc --workspace --no-deps --open

# Run cargo audit
audit:
    cargo audit

# Run benchmarks
bench:
    cargo bench --workspace
