# Thine: results of the three verification checks

Run 4 November 2026. All three checks completed. No mainnet transactions were sent, no keys were deleted anywhere, and no secrets are committed.

**Headline: all three checks pass. The check 1 gas estimate in the brief does not hold. The real cost is about three times lower than estimated. Check 3 passes, but its shape is not what the first version of this report claimed: the faucet grants 10 NEAR per request, not 10,000, and it is rate limited, so funding takes seven requests and consolidation rather than one request.**

---

## Environment

| Item | Value |
|---|---|
| Repository | `github.com/near/intents`, shallow clone of `main` |
| Rust toolchain | 1.97.1, pinned by `rust-toolchain` (confirmed) |
| Sandbox | `near-kit-sandbox` 0.20.1 → Docker image `nearprotocol/sandbox:2.14.0` |
| Sandbox protocol version | **88** |
| Testnet protocol version | **88** |
| Mainnet protocol version | **87** |

The repo's own sandbox tests (`cargo test -p defuse-wallet-sdk --test test`) pass: 5/5, `rotate` and `w_init` included. That is the baseline that validates everything below.

### Two environment facts the brief does not mention, both of which blocked progress

1. **The contracts must be built with `--cfg=near`.** A plain `cargo build --release --target wasm32-unknown-unknown` produces a WASM that compiles, deploys, and then **traps with `unreachable` inside `w_execute_signed`**. The canonical build is `cargo near build` (see the repo `Makefile`, which also sets `RUSTFLAGS='--cfg=near'` for clippy). `RUSTFLAGS='--cfg=near' cargo build --release …` is enough to get working artefacts. Without it, `defuse-crypto`'s `cfg_select!` picks a non-NEAR code path and the contract is broken in a way that does not look like a build problem.

2. **`near-kit-sandbox` 0.20.1 needs a Docker daemon.** It is testcontainers-based, not a downloaded `neard` binary. On this machine that meant starting `colima` and exporting `DOCKER_HOST=unix://$HOME/.colima/default/docker.sock`. Note that starting colima also resumed two pre-existing containers of yours (`splice`, `canton`); they were left untouched.

---

## Check 1: the P-256 execution hop, measured

### The brief's central premise about this check is wrong, in a helpful direction

> "There is no P-256 test fixture in the repository to copy, so the WebAuthn signing side of check 1 has to be written from scratch. That is the real work in this brief."

This is not the case. The repository already ships a complete P-256 WebAuthn signing path behind the `mock` cargo feature:

- `crates/signatures/webauthn/src/mock.rs`: `MockWebauthnSigner`, which builds real `authenticator_data` (rpIdHash, flags, signCount) and `client_data_json`, and signs the correct effective message.
- `contracts/wallet/signatures/webauthn/src/mock.rs`: `MockWalletWebauthnSigner`, which **implements `WalletSigner<WalletWebauthn<A, UV>>`** and emits the exact JSON proof the contract expects, using `msg.hash()` as the WebAuthn challenge.
- Two P-256 unit fixtures with real vectors in `crates/signatures/webauthn/src/p256.rs` and `contracts/wallet/signatures/webauthn/src/p256.rs`.

Wiring P-256 into the sandbox took **one dev-dependency line** (`defuse-wallet-webauthn` with features `["mock", "p256"]`) and a type alias, not a from-scratch WebAuthn implementation. The benchmark compiled on the first attempt. This should free up a meaningful amount of the remaining build window.

### Signature verification is a native host function, not WASM

`defuse_crypto::p256::P256::verify` calls `near_sdk::env::p256_verify`. P-256 verification is a **protocol host function**, so it costs a flat fee rather than scaling with WASM instructions. This is the single biggest reason the estimate in the brief was too high.

### Measured results

Benchmark: `crates/wallet/sdk/tests/thine_p256_gas.rs`. Both shapes were run three times; figures were stable to within 0.001 TGas.

| Case | Conversion | Receipts | Total gas | Total NEAR burnt |
|---|---|---|---|---|
| `UseGlobalContract(no-sign)` + `w_init` (migration step 1) | 0.4931 TGas | 2 | **2.3307 TGas** | 0.000211 |
| `DeterministicStateInit` + first `w_execute_signed` (empty request) | 0.8398 TGas | 2 | **12.5626 TGas** | 0.007514 |
| `AddExtension(passkey 0s)` (migration step 3) | 0.3084 TGas | 1 | **1.8404 TGas** | 0.000184 |
| **ONE HOP**, `w_execute_signed(0s)` → `FunctionCall` to a second account | 0.3438 TGas | 4 | **6.4881 TGas** | 0.000604 |
| **TWO HOP**, `w_execute_signed(0s)` → `w_execute_extension(user)` → `FunctionCall` | 0.3559 TGas | 6 | **8.6007 TGas** | 0.000793 |

Note the 0.0075 NEAR on the state-init row is overwhelmingly the new account's storage stake, not gas.

### Breakdown of the `w_execute_signed` receipt, the granularity the brief asked for

One-hop, the 0s wallet's own receipt (4.2767 TGas):

| Cost | Gas | What it is |
|---|---|---|
| `P256_VERIFY_BASE` | **1.3000 TGas** | passkey signature verification, flat host-function fee |
| `WASM_INSTRUCTION` | 1.0035 TGas | `clientDataJSON` parsing, borsh decode, contract logic |
| `CONTRACT_LOADING_BYTES` | 0.4588 TGas | loading the wallet WASM |
| `FUNCTION_CALL_BASE` | 0.2000 TGas | promise construction |
| `NEW_ACTION_RECEIPT` | 0.1081 TGas | promise construction |
| `STORAGE_WRITE_BASE` | 0.0642 TGas | nonce write |
| `STORAGE_READ_BASE` | 0.0564 TGas | state read |
| `UTF8_DECODING_BYTE` | 0.0525 TGas | JSON argument decoding |
| other memory/register costs | 0.0859 TGas | |
| profiled subtotal | 3.3870 TGas | remainder to 4.2767 is receipt-creation base cost |

Per-receipt, one hop: 4.2767 (0s wallet) + 1.4213 (target account) + 0.2232 + 0.2232 (two refunds).

Per-receipt, two hop: 4.3321 (0s wallet) + 1.8219 (user account, `w_execute_extension`) + 1.4213 (target) + three refunds at 0.2232 each.

Refund receipts are **0.2232 TGas each**, matching the brief's mainnet ed25519 figure of 0.223 exactly.

### Does the brief's working estimate hold? No.

> "Our working estimate for P-256 two-hop is 20 to 30 TGas and 0.002 to 0.003 NEAR. Report whether that holds."

| | Estimate | Measured | Ratio |
|---|---|---|---|
| Two-hop gas | 20–30 TGas | **8.60 TGas** | 2.3–3.5× lower |
| Two-hop NEAR | 0.002–0.003 | **0.000793** | 2.5–3.8× lower |

The measured P-256 two-hop (8.60 TGas) is also well below the mainnet **ed25519** figure quoted in the brief (17.7–19.2 TGas), though that ed25519 figure included a state init. The comparable Thine row including a state init is 12.56 TGas, still below it.

**Caveat on transferring these numbers to mainnet.** These were measured at protocol version 88 (sandbox), which matches testnet. Mainnet is at 87. Gas parameters are protocol-dependent, so re-confirm on mainnet before publishing a cost to a user. The figures are exact for testnet.

---

## Check 2: migrating an account that already has contract state. All three cases confirmed

Test: `crates/wallet/sdk/tests/thine_migration_state.rs`, plus a deliberately ordinary near-sdk probe contract at `contracts/thine-probe/`.

Every claim the brief listed as "established from source, to be confirmed empirically" is confirmed.

### Case 1, a plain account with no contract: SUCCEEDS

| | storage_usage | staked |
|---|---|---|
| before | 182 bytes | 0.00182 NEAR |
| after | 300 bytes | 0.00300 NEAR |
| delta | **+118 bytes** | +0.00118 NEAR |

Resulting state: one data key, the empty key `b""`, 46 value bytes. So a migrated wallet account costs **300 bytes / 0.003 NEAR** of storage stake, comfortably inside the NEP-448 zero-balance limit of 770 bytes.

### Case 2, an ordinary near-sdk contract holding data, `b"STATE"` included: SUCCEEDS

`w_init` succeeds. `UseGlobalContract` removed the code and **left every data key untouched**, exactly as the brief predicted. No collision, because the wallet's state key is `b""` and near-sdk's default is `b"STATE"`.

| | storage_usage | staked |
|---|---|---|
| empty account | 182 bytes | 0.00182 NEAR |
| with probe code + 4 data keys | 113,670 bytes | 1.13670 NEAR |
| after migration | 935 bytes | 0.00935 NEAR |
| **delta across step 1** | **−112,735 bytes** | **−1.12735 NEAR freed** |

Storage accounting:

| | bytes | NEAR |
|---|---|---|
| probe code + data added | 113,488 | 1.13488 |
| of which contract code (freed by `UseGlobalContract`) | 112,853 | 1.12853 |
| wallet-only baseline (from case 1) | 300 | 0.00300 |
| **orphaned, unreachable, still paid for** | **635** | **0.00635** |

The 635 orphaned bytes are the four surviving probe keys (`STATE` 8, `alpha` 64, `beta` 128, `gamma` 256 value bytes, plus key bytes and per-record overhead). They are unreachable, since the code that could read them is gone, but the account still stakes for them permanently.

### Case 3, a contract occupying the empty key `b""`: FAILS, cleanly, and reverts

`w_init` panics with exactly the expected message:

```
Smart contract panicked: The contract has already been initialized
```

It does **not** misparse the squatting value. Action index 1, i.e. the `FunctionCall`, not the `UseGlobalContract`.

### The open question in the brief: does a failed `w_init` revert the `UseGlobalContract` from the same receipt?

**Yes, it reverts.** This was the brief's "expected but unverified" item and it resolves in the safe direction.

| | |
|---|---|
| probe code hash before | `7e5pKnSGoTWWXh7xqz5BdmzjVqbmooFzPVbTQqr5RwW` |
| code hash after failed step 1 | `7e5pKnSGoTWWXh7xqz5BdmzjVqbmooFzPVbTQqr5RwW` |
| `wallet-no-sign` code hash | `C17Lfk3oa9ngVMWZnnbtmQNbMhqFFzTtu2SR3VD6qPRj` |
| storage_usage before / after | 113,161 / 113,161 bytes, unchanged |
| original contract still callable afterwards | **yes** |

A failed migration leaves the account exactly as it was. There is no state in which an account carries wallet code with no wallet state. That removes a whole class of recovery tooling from the build.

### The precondition the tool must check before sending anything

The only blocking precondition is whether the empty storage key `b""` is already occupied. Concretely:

```
POST https://rpc.mainnet.near.org
{"jsonrpc":"2.0","id":1,"method":"query","params":{
  "request_type":"view_state",
  "finality":"final",
  "account_id":"<target>",
  "prefix_base64":"",
  "limit":10}}
```

Then check whether any returned `values[].key` is the empty string `""` (base64 of zero bytes). If it is, refuse the migration. Verified against a real plain testnet account: returns `values: []`, so the check is unambiguous.

Two things worth surfacing to the user rather than blocking on, since the migration succeeds either way:

- **Orphaned storage.** If `view_state` returns keys other than `b""`, those bytes will be orphaned and paid for forever. Show the user the byte count and the NEAR figure before they commit.
- **Storage freed.** If the account currently has code (`code_hash` is not all-ones), migrating frees that code's storage stake, 1.13 NEAR in the case 2 example. That is a refund to the user and worth showing.

---

## Check 3: can we accumulate testnet NEAR? Yes, but not in one request

**This section was wrong in the first version of this report and has been corrected.** The original
claimed the faucet grants 10,000 NEAR per request with no rate limit. Both halves were wrong: the
grant is **10 NEAR**, and the faucet **is** rate limited. The error was a unit bug in the throwaway
script used to read balances, which divided yoctoNEAR by 1e21 instead of 1e24 and so reported every
balance 1,000x too high. The corrected figures below were measured with `thine fund` and confirmed
directly against `view_account`.

### What the faucet actually gives

The docs publish no figures at all; they say only "a small amount". Measured:

| | |
|---|---|
| Endpoint | `POST https://helper.testnet.near.org/account` |
| Body | `{"newAccountId": "<name>.testnet", "newAccountPublicKey": "ed25519:<base58>"}` |
| **Grant per request** | **10 NEAR** (`10000000000000000000000000` yocto, verified by `view_account`) |
| Creates the account? | Yes. It creates and funds a new named account |
| Latency | ~2.7–3.7 s per request |
| **Rate limit** | **Approximately 10 requests per day.** The 11th returned `429 Too Many Requests: Rate limit exceeded, retry in 11 hours.` |
| Consolidation | **Required.** Each grant lands in its own new account and must be swept. |

### What that means for the ~68 NEAR requirement

Publishing both contracts burns **67.882131 NEAR** (measured; see below). At 10 NEAR a request:

- **7 faucet requests** are needed: the first becomes the relayer, and six more are swept in at
  9.99 NEAR each after leaving dust for storage stake and transfer gas. 10 + 6 x 9.99 = 69.94 NEAR.
- 7 is comfortably inside the observed daily allowance of roughly 10, so **this is reachable within
  a single day's quota**.
- Sweeping is a plain transfer rather than `DeleteAccount` with a beneficiary, which leaves about
  0.01 NEAR per account behind. Recovering that dust is not worth performing an irreversible
  account deletion for.

### Where this actually stands right now

The relayer `thine-1a1a75385a8.testnet` holds **59.95 NEAR** and needs 68.38 including publishing
gas, so it is **8.43 NEAR short**. That is one more faucet request. The shortfall exists only
because four of today's ten requests were spent on the verification work in this report before the
grant size was known. The limit resets in about 11 hours.

**So check 3 passes, with a correction to its shape rather than its answer.** The original brief
asked whether 68 testnet NEAR is reachable and whether balances can be consolidated. They can, it
takes seven requests rather than one, and consolidation is required rather than unnecessary. This
does not force the fallback to a mainnet-only demo: nothing about the plan changes except that
funding the relayer is a scripted step (`thine fund`) rather than a single call, and that the
testnet publish waits for the next faucet window.

Everything else can be built and proven in the meantime without the faucet, because
`near-kit-sandbox` is a complete local network and all three measurements already run against it.

### The publish cost, measured rather than assumed

I fetched the **exact bytes deployed on mainnet** via `view_global_contract_code_by_account_id` and
published them into the sandbox to measure the real burn. Test:
`crates/thine-bench/tests/thine_publish_cost.rs`; artefacts committed under `res/`.

| Variant | Size | Gas | **Balance spent** | Predicted 10x burn | Multiplier |
|---|---|---|---|---|---|
| `wallet-no-sign` | 308,482 B | 24.50 TGas | **30.850628 NEAR** | 30.848200 | 10.001x |
| `wallet-webauthn-p256` | 370,286 B | 29.25 TGas | **37.031503 NEAR** | 37.028600 | 10.001x |
| **Total** | 678,768 B | | **67.882131 NEAR** | | |

This confirms the brief's 30.85 / 37.03 / ~68 NEAR figures to six decimal places, and confirms the
10x rate (size x 1e20 yoctoNEAR per byte).

One mechanical detail worth knowing: the burn is levied inside `tokens_burnt`, **not** as refundable
storage stake. The publisher's own `storage_usage` stays at 182 bytes. The NEAR is genuinely gone,
which matches the brief's "not refundable".

## Things that contradict the handover file

Listed because the brief asked for them explicitly.

1. **"No P-256 test fixture in the repository … has to be written from scratch. That is the real work in this brief."** Wrong. A complete mock P-256 WebAuthn signer implementing `WalletSigner` ships behind the `mock` feature. This was the single largest item in the brief and it is already done upstream.

2. **The build needs `--cfg=near`.** Not mentioned. Plain `cargo build` yields a contract that traps at runtime rather than failing to build, which is a nasty failure mode.

3. **`near-kit-sandbox` requires Docker.** Not mentioned; it is testcontainers-based.

4. **Mainnet is at protocol version 87, not 86.** The brief states 86 in three places. This matters for one of its own claims: "From protocol version 87 a gas key cannot sign the inner delegate action of a meta transaction; mainnet is at 86 today." Mainnet is at 87, so **that restriction is already live on mainnet**. The universal-accounts conclusion is unchanged, since 88 is still ahead of mainnet, but the stated numbers are stale. Testnet and the sandbox are both at 88.

5. **The mainnet table's sizes and sha256 hashes are exactly right**, verified byte-for-byte. But the labelling needs one refinement: `0sfa7a4d20…` and `0saf343be2…` are *global-deployer instances* that publish the wallet WASM as a **global contract by account id**. They are not themselves wallet contracts (their own `contract_source_metadata` reports `standard: "global-deployer"`), and their own code resolves through `0s7876eb5ba4f1d97eb53a53903a86bd211c71b3b1` to global contract hash `37osLHRQ8KsJx1YwXJbPcd2wfKHP5KjtKawnrfjjaD3J`.

6. **Those two sha256 hashes are not published by code hash on mainnet.** Querying `view_global_contract_code` for either returns `NO_GLOBAL_CONTRACT_CODE`. So the brief's "Publish by code hash rather than by account id" is the right instruction for *our own* testnet deploy, but on mainnet today the only way to reference the existing deployments is **by account id**. This is directly relevant to open question 5 (whether to publish your own immutable mainnet copies at ~68 NEAR), because referencing the existing ones by code hash is not currently an option.

7. **The deployed artefacts are from commit `32a7836f825e8c984c26149f4456793ec7e3d49a`**, not `main` HEAD. Building `main` with `--cfg=near` produces different sizes (349,875 B for no-sign vs 308,482 deployed; 421,163 B for p256 vs 370,286 deployed). That is partly the commit difference and partly because `cargo near build` post-processes while plain cargo does not. Build from that commit with `cargo near build` if you need byte-identical artefacts.

8. The brief says `res` must be created manually and that `read_wasm` resolves `CARGO_MANIFEST_DIR/../../../` plus `DEFUSE_USE_OUT_DIR` defaulting to `./res`. Both confirmed exactly. Worth adding that `.cargo/config.toml` already sets `DEFUSE_USE_OUT_DIR=res` relative to the workspace root, and that filenames must use **hyphens** (`defuse-wallet-no-sign.wasm`), not the underscored cargo output names.

9. The existing harness also needs `defuse-wallet-ed25519.wasm` in `res`, a third artefact the brief does not list.

---

## What was committed

Inside the `intents` clone:

- `crates/wallet/sdk/tests/thine_p256_gas.rs`: check 1 benchmark, full per-receipt and per-cost-category gas reporting, machine-readable JSON per measurement.
- `crates/wallet/sdk/tests/thine_migration_state.rs`: check 2, all three cases plus the revert question and storage accounting.
- `crates/wallet/sdk/tests/thine_publish_cost.rs`: check 3 publish-cost measurement against the real mainnet bytes.
- `contracts/thine-probe/`: the ordinary near-sdk contract used to set up check 2's three starting states.
- `res/mainnet/*.wasm`: the exact mainnet-deployed artefacts, for reproducible cost measurement.
- One line added to `crates/wallet/sdk/Cargo.toml` dev-dependencies, and one workspace member.

All three are written as committed, repeatable benchmarks rather than one-off scripts, so they can move into the Thine repository as the reproducible measurements the submission ships.

Reproduce with:

```bash
RUSTFLAGS='--cfg=near' cargo build --release --target wasm32-unknown-unknown \
  -p defuse-wallet-webauthn-p256 -p thine-probe
RUSTFLAGS='--cfg=near' cargo build --release --target wasm32-unknown-unknown \
  -p defuse-wallet-no-sign -p defuse-wallet-ed25519 --no-default-features --features=contract
mkdir -p res   # then copy artefacts in, renaming underscores to hyphens
export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
cargo test -p defuse-wallet-sdk --test thine_p256_gas        -- --nocapture --test-threads=1
cargo test -p defuse-wallet-sdk --test thine_migration_state -- --nocapture --test-threads=1
cargo test -p defuse-wallet-sdk --test thine_publish_cost    -- --nocapture --test-threads=1
```

---

## Not done

As instructed, I stopped at verification and did not begin building the migration flow. Steps 2, 4 and 5 of the five-step architecture were exercised only as far as checks 1 and 2 required. Step 4 (proving a passkey works via `w_execute_signed` with a promise to `w_execute_extension`) is fully demonstrated by the two-hop benchmark, but step 5 (`RemoveExtension` then `DeleteKey` on every full access key) was deliberately not run anywhere, per the brief.
