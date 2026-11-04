# thine-probe

Not part of Thine. This is an ordinary near-sdk contract whose only job is to
put a sandbox account into one of the three states that `thine-bench`'s
`thine_migration_state` test migrates over:

1. an account with no contract at all (this contract is simply not deployed),
2. an account with a normal contract holding data under ordinary keys,
   near-sdk's own `b"STATE"` included,
3. an account whose contract has written the **empty** storage key `b""`, which
   is where the wallet contract keeps its own state.

Case 3 is the one that makes a migration impossible, and this contract exists to
produce it on demand.

## Rebuilding

The compiled artefact is committed at `res/thine-probe.wasm` so the test suite
runs with one command and no WASM toolchain. To rebuild it and confirm it
matches:

```bash
rustup target add wasm32-unknown-unknown
cd contracts/thine-probe
cargo build --release --target wasm32-unknown-unknown
shasum -a 256 target/wasm32-unknown-unknown/release/thine_probe.wasm
```

The flags that matter are set in `.cargo/config.toml`, so the command above is
all you need. `--cfg=near` is how NEAR's own contracts are built (`cargo near
build` sets it); without it, contracts in this family compile and deploy but
then trap at runtime. `--remap-path-prefix` keeps the digest independent of
where you checked the repository out. The toolchain is pinned by
`rust-toolchain.toml` at the repository root; the digest below was produced by
Rust 1.97.1 and is byte-identical across repeated builds.

Expected digest: `d3433dc1738d81a136811f8d153df61d944b5b377f2d456f7d989ff666771c42`
