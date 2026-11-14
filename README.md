# Thine

Thine moves an existing NEAR account from seed phrase control to passkey control. The account id
stays the same and no assets move. When the migration completes, the seed phrase key has been
removed, the account holds no full access key, and authority over it runs only through the
registered passkeys. The same flow works for a new account as well.

A passkey signs with P-256, which is not one of NEAR's access key types. Those are ed25519,
secp256k1 and ML-DSA-65, so a passkey's authority has to live in contract code rather than in a key
on the account. Step 1 replaces the account's code with the `wallet-no-sign` contract, in one
receipt carrying `UseGlobalContract` and a call to `w_init`, signed by the existing full access key.
From then on the account's own contract signs nothing and acts only for its listed delegates.

Each passkey controls one delegate, a zero-balance `0s` account running `wallet-webauthn-p256` at an
address derived from the contract it runs and its initial state, which carries that passkey's public
key. When that account's `w_execute_signed` is called, the contract rebuilds the signed payload from
`authenticator_data` and the SHA-256 of the exact `client_data_json` bytes, requires the WebAuthn
challenge to be the request message's own hash, and checks the P-256 signature with the
`p256_verify` host function against the public key fixed in that account's state. The seed phrase
key is removed by the protocol's `DeleteKey` action, one per full access key, which step 5 sends
only after two passkeys have each completed a `w_execute_signed` routed through the account.

The thing you look at while using it is a view of who can currently open your account. Migration is
the operation that changes what that view shows.

## The problem

A NEAR account is opened by whoever holds its seed phrase. That is a single secret, written down or
stored in a password manager, and it is the only thing between an account and anyone who finds it.
Passkeys are the mechanism most people now use for everything else: hardware-backed, unphishable,
and already on their devices.

A passkey cannot simply be added to a NEAR account. Passkeys sign with P-256 (secp256r1), which is
not among NEAR's access key types. There is no access key that represents a passkey, so
passkey control has to be contract-mediated: the account itself becomes a wallet contract that
delegates authority to separate passkey-controlled accounts. That single constraint determines the
whole design.

The dangerous part is the end of that process, where the last full access key is deleted. After
that, the passkeys are the only way in. The wallet contract does not protect you here: its lockout
guard checks only that the delegate set is non-empty, and never checks that anything in that set can
be reached. An account whose only delegate is an address that was never created, or whose passkey
has been lost, satisfies the contract and is permanently unopenable.

That gap is why Thine shows you who can open your account rather than just running a flow, and why
it refuses rather than warns.

## What it does

Five steps, each one transaction:

1. The account becomes a `wallet-no-sign` contract. `UseGlobalContract` and a call to `w_init` go
   out in one receipt, signed by the existing full access key. Authority does not change: the
   account becomes its own only delegate, so whoever holds a key still holds everything.
2. A passkey-controlled account is created. Its id is a NEP-616 deterministic address derived from
   the contract code and the passkey's public key, created with `DeterministicStateInit` at zero
   balance.
3. That account is authorised as a delegate of yours.
4. The passkey signs a real request through your account, proving it can drive it.
5. The account stops delegating to itself, then every full access key is deleted. This is the step
   that cannot be undone.

Three refusals, each one a hard stop that sends nothing:

- **Before step 1**, if your account's contract already uses the empty storage key. That is where
  the wallet contract keeps its own state, and `w_init` would fail.
- **Before step 3**, if the passkey account does not answer `w_public_key`. `AddExtension` does not
  check that its argument exists, so this is the check that stops you authorising something
  unreachable.
- **Before step 5**, unless two independent passkeys have each completed step 4. Being added is not
  evidence that anyone can still sign with a passkey, and one passkey is a single point of failure
  once the seed phrase is gone. The proofs are re-read from the chain, not from local state.

## A bug worth recording

The first end-to-end run saw one of two authorised passkeys. Both transactions had succeeded, and the
contract's own event logs showed both `extension_added` events, but the typed contract client
returns as soon as a call has executed, which is not the same as final, and the next read at final
finality was a block behind. So the view showed the state from before the user's own action.

For a tool whose entire job is telling someone who can open their account, that is close to the
worst failure available: it would have reported a step as not taken when it had been, or shown a
passkey as missing when it was authorised. Every step now waits for finality before returning, and
the end-to-end test is what found it.

It is recorded here rather than only in the git history because the measurements in this repository
are worth no more than the method behind them, and this is a case where the method caught something
that reasoning about the code had not.

## Try it

Everything below runs against a local NEAR sandbox. No wallet, no funds, no faucet, no account.

### Prerequisites

Rust (the toolchain is pinned by `rust-toolchain.toml`) and a running Docker daemon.
`near-kit-sandbox` runs `neard` in a container. On macOS with colima:

```bash
colima start && export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
```

### Do this: run the whole migration end to end

```bash
cargo test -p thine-bench --test thine_migration_e2e -- --nocapture --test-threads=1
```

**See this:** an account migrated from key control to passkey control, with all three refusals
firing first. The run takes about 20 seconds. The output ends with the account being driven by a
passkey when no full access key exists anywhere:

```
--- refusal 1: the empty storage key is occupied ---
refused: this account's contract already uses the empty storage key ...

=== migrating lydia.sandbox ===
start: SeedControlled, 1 holder(s)
step 1: 2.2886 TGas, 0.000207 NEAR

--- refusal 2: the extension is not a live wallet ---
refused: refusing to add an extension that is not a live wallet account ...

step 2A: 0sc48b... exists, 242 bytes of storage
step 3A: 1.8001 TGas

--- refusal 3: two passkeys added, neither has signed ---
refused: 0 of 2 passkeys have proven they can sign ...

step 4A: 6.3164 TGas
--- refusal 3b: one passkey proven, two required ---
refused: 1 of 2 passkeys have proven they can sign ...
step 4B: 6.3159 TGas

--- step 5: irreversible ---
  5a: drop the self-extension: 1.8006 TGas
  5b: delete a full access key: 0.6292 TGas

end: PasskeyControlled { proven: 2 }
after migration, passkey A still drives lydia.sandbox: 6.3134 TGas
```

### Do this: look at a real account's authority

```bash
cargo run -p thine-cli -- inspect <any-account>.testnet
```

**See this:** who can open that account, whether it would survive having its keys deleted, and the
five steps with the irreversible one marked. For an ordinary account, step 1 is marked `NOW`, steps
2 to 5 are pending, and key deletion is refused.

Reads go through NEAR's archival RPC by default (`archival-rpc.testnet.fastnear.com`, and the mainnet
twin with `--network mainnet`), because the view verifies proof and removal transactions by their
hash and a non-archival node forgets them after a few days. Both this command and the `thine-web`
server take `--rpc` to override that; as a judge you would pass it to point the tool at the local
sandbox, as the interface section below does, or at an RPC endpoint you trust more than ours.

Add `--json` for the same thing as data. That is the shape the interface consumes, so the screen and
the command line read one model.

### Do this: run the interface and migrate an account yourself

This is the only path that uses a real passkey, so it needs a device that has one.

```bash
docker run -d --name thine-sandbox -p 3030:3030 \
    -e NEAR_ROOT_ACCOUNT=sandbox nearprotocol/sandbox:2.14.0
cargo run -p thine-web --example setup_local
cargo run -p thine-web --bin thine-web -- \
    --rpc http://localhost:3030 --chain-id sandbox --account lydia.sandbox
```

Then open **http://localhost:8080**. Not the IP address: a passkey needs a secure context, which
plain http gives only on loopback, but it also needs a relying party id, and an IP address cannot
be one. Chrome rejects `127.0.0.1` with "This is an invalid domain", and the page says so rather
than letting that error through.

**See this:** who can open the account, the twelve-word seed phrase its key derives from, the five
steps with the irreversible one marked, and the controls. Working down them migrates the account: your own device is asked for a passkey twice
per key, once to create its account and once to prove it, and the view updates after every step.
The last button is refused until two passkeys have each proven themselves.

### Do this: check the measurements

```bash
cargo test -p thine-bench -- --test-threads=1
```

**See this:** four sandbox tests passing, printing the numbers in the next section. Nothing needs
building first; the contract artefacts are committed and checked against recorded digests on load.

```bash
cargo test --workspace
```

**See this:** 63 tests passing. 49 of them are unit tests needing no Docker; the rest drive a
sandbox. They include the whole migration twice over, once locally and once through the browser
path, with every passkey signature going through the same DER and `clientDataJSON` conversions a
real device's output does, and then the same migration again through the HTTP endpoints the page
calls.

## Measurements

Every number here comes from a committed test you can re-run. Each was measured at protocol version
88, which is what testnet and the sandbox run; mainnet is at 87, so re-confirm before quoting a cost
to a user.

### What a passkey hop costs

`cargo test -p thine-bench --test thine_p256_gas`

| | Gas | NEAR burnt |
|---|---|---|
| One hop: `w_execute_signed` to a second account | 6.4881 TGas | 0.000604 |
| Two hop: via your account's `w_execute_extension` | 8.6007 TGas | 0.000793 |

Stable to within 0.001 TGas across three runs. The two-hop figure is the one that matters, because
it is the route a passkey takes once the keys are gone.

Breaking down the 4.2767 TGas receipt on the passkey wallet:

| Cost | Gas |
|---|---|
| `P256_VERIFY_BASE`, signature verification | 1.3000 TGas |
| `WASM_INSTRUCTION`, which is `clientDataJSON` parsing, decoding and logic | 1.0035 TGas |
| `CONTRACT_LOADING_BYTES` | 0.4588 TGas |
| `FUNCTION_CALL_BASE` + `NEW_ACTION_RECEIPT`, promise construction | 0.3081 TGas |
| storage, memory, registers, UTF-8 decoding | 0.2590 TGas |

Verification is a flat 1.3 TGas because NEAR verifies P-256 in a host function
(`env::p256_verify`), not in WASM.

### Migrating an account that already has a contract

`cargo test -p thine-bench --test thine_migration_state`

| Starting state | Result |
|---|---|
| No contract | Succeeds. +118 bytes, 300 bytes total, 0.003 NEAR staked. |
| An ordinary contract with data | Succeeds. Frees 1.12735 NEAR of code stake, orphans 635 bytes. |
| A contract using the empty storage key | Refused. `w_init` panics; nothing changes. |

Replacing an account's code frees what the old contract's bytes were staking but leaves every data
key in place, so a migrated account keeps paying for data nothing can read. For the test account
that is 635 bytes, 0.00635 NEAR, permanently. `thine inspect` shows this figure for any account that
has it.

A failed `w_init` rolls back the `UseGlobalContract` in the same receipt, so a refused migration
leaves the account exactly as it was. That is measured, not assumed.

The same situation has been produced and migrated on live testnet, not only in the sandbox. On
13 November 2026, `cargo run -p thine-web --example existing_account -- prepare` created
`v794558571.thine-1a1a75385a8.testnet` and gave it a past signed entirely by its seed-phrase key:
an ordinary near-sdk contract deployed in `9K7E2dr69Ej2E6Jd7Z8NcU9mTQDdg57BH9QtGhad3PTJ`, state
written through it in `EL9Ehir36A3RZMyJ2Q7Ch66X52a66tCP4f93uc4Qk5HE`,
`A5hYqyMYyaSVWUk56urBNqy8qRSMcMf6uMtjgxScxG8Q` and
`EW3ze6cMeuh6vpAYX5R4PngiJLknS5wj9opkHd6FmheX`, and a transfer in
`95s56JvPcy81jWNJJkTx9xjT57hsPndjQXx2nKaVbsn4`. The precondition read 581 bytes of prior contract
state before sending anything, found the empty key free, and permitted the migration. The whole
five-step flow then ran through the interface in fixed mode with a virtual authenticator (labelled
as such; it is not a real-device claim): the full access key was deleted in
`4m9VSNDhkbdkbU1dSSoBggjPiZ6JXDexuvdmYgi7999J` and the self extension removed in
`CND1rdsAGFxtzemi5BKbEHNXY4WjMAKFRGqdBTevGDVn`. After it, the chain refuses what the seed phrase
signs, in its own words: `Access key not found: v794558571.thine-1a1a75385a8.testnet /
ed25519:2h7sX71GGpagBhzktnpif4qua5dEFCSY7TJck6mQseCe`. The prior state survives as 581 bytes of
orphaned storage, shown and priced on the account's view. Nothing in the flow knew the account was
minutes old rather than years old; the chain carries no such notion, and the migration reads only
what is on it.

### What deploying Thine costs

`cargo test -p thine-bench --test thine_publish_cost`

| Contract | Size | Burn |
|---|---|---|
| `wallet-no-sign` | 308,482 B | 30.850628 NEAR |
| `wallet-webauthn-p256` | 370,286 B | 37.031503 NEAR |
| Total | | 67.882131 NEAR |

NEP-591 charges publication at ten times the ordinary storage rate and the burn is not refundable.
Measured against the exact bytes running on mainnet.

On testnet this is funded from the faucet, which grants 10 NEAR per request and allows roughly ten
requests a day. `thine fund` scripts the seven requests and the consolidation. NEAR's docs publish
neither figure.

Publishing the pair therefore costs most of a day's faucet allowance, and a code hash reference is
immutable, so a wrong byte cannot be corrected in place. It can only be abandoned and paid for
again, at another 68 NEAR and another day. `thine publish` treats that as a hard precondition rather
than a matter of care: it refuses unless each artefact matches the digest recorded in the source
**and** is byte-for-byte identical to what NEAR mainnet currently serves. `thine publish --dry-run`
runs every check, prints the code hashes and the burn, and sends nothing.

```bash
cargo run -p thine-cli -- publish --dry-run
```

**See this:** both artefacts confirmed against mainnet, the two code hashes they would be published
under, the total burn, and whether the relayer can cover it.

## NEAR features used

- **NEP-591 global contracts.** Both wallet contracts are published by code hash and referenced with
  `UseGlobalContract`. By hash rather than by account id, so the reference is immutable: it is the
  only way back into a migrated account. **Live on testnet**, published by
  `thine-1a1a75385a8.testnet` on 11 November 2026, burning 67.882131 NEAR, which is the figure the
  committed measurement predicted to the yoctoNEAR:

  | Variant | Testnet global contract code hash |
  |---|---|
  | `wallet-no-sign` | `6NWBBut6hFFAPCghcoqaJUsqDLoTTmXcmWDpMeUQ93Xt` |
  | `wallet-webauthn-p256` | `qD9cxbe38rJn7BwUBtqaC2vVAiYD7TS4vnrafccHsRp` |

  Check them yourself: `view_global_contract_code` for either hash returns code whose SHA-256 is
  exactly the digest recorded in `thine-core/src/artifacts.rs`, which is also byte-for-byte what
  NEAR mainnet serves. On mainnet the same contracts are referenced **by account id**
  (`0sfa7a4d20…`, `0saf343be2…`); they are not published by code hash there.
- **NEP-616 deterministic account ids.** Each passkey's account id is derived from the contract and
  the passkey's public key, so it is known before it exists.
- **NEP-448 zero-balance accounts.** A passkey account uses 242 bytes, inside the 770-byte limit, so
  creating one needs no funding.
- **`env::p256_verify`.** The host function that makes passkey verification cost 1.3 TGas instead of
  a WASM-priced elliptic curve operation.
- **Access key deletion** (`DeleteKey`) as the final, irreversible step.
- **`view_state`, `view_access_key_list`, `view_global_contract_code_by_account_id`** and
  `EXPERIMENTAL_tx_status` for the authority view, the preconditions, and proof verification.

## Partner protocols and components used

- **NEAR's wallet contracts**, from [github.com/near/intents](https://github.com/near/intents)
  (MIT): `wallet-no-sign` and `wallet-webauthn-p256`. Thine deploys and drives these; it does not
  reimplement them. Pinned by commit `32cd1f9788a347908164fbcc56525dc6542f158f`. The copies in
  `res/` are the exact bytes deployed on mainnet.
- **`defuse-wallet-sdk`** from the same repository, for the wallet client bindings, request signing
  and relaying.
- **`near-kit`** and **`near-kit-sandbox`** 0.20.1 for RPC and the local test network.

## What is not built yet

Stated plainly, because the rest of this file is about what does work.

- **A real-device migration has been completed twice.** On 13 November 2026 the author ran the
  whole flow at the hosted demo from Chrome on a Mac, approving every signature on the machine's
  own platform authenticator; the chain's record of that account,
  `d555575227832.thine-1a1a75385a8.testnet`: zero access keys remain, exactly the two passkey
  extensions, and both removal transactions succeeded. On 14 November 2026 the author migrated
  `lydia-solomon.testnet` the same way, an account registered through the testnet registrar that
  carried a deployed contract, prior state and a transfer history first: the key was deleted in
  `7Kq2xBXGteVE91t753N6NEdh8tShzhrCfTB8ehANDAZS`, the self hold removed in
  `2WKHA1XdT6dYQXKofiDX5cC86SDGBZHujEQsu4F2k61a`, two proven passkeys remain, and the prior
  state survives as 737 bytes of orphaned storage the view still prices. Every automated run
  uses a virtual authenticator instead, and is labelled as such; one device and browser
  combination is what the real-hardware claim covers.
- **The hosted demo is served from one machine.** The judge path runs against live testnet behind
  a tunnel from the author's computer, not from hosted infrastructure. If it is unreachable, the
  local path above reproduces everything it shows.
- **Migrating your own account in the hosted interface is not wired.** Steps 1, 3 and 5 must be
  signed by the account's own key, which lives in its owner's wallet, so the hosted page needs a
  standard wallet connection; it says so plainly instead of asking for anything. Today a phrase
  holder migrates locally: `existing_account keyfile <id> <phrase>` derives the key file without
  the phrase leaving the machine, and `thine-web --account` runs the full flow against it. Wiring
  the wallet connection, including wallet support for the NEP-591 action step 1 sends, is the
  first piece of after-hackathon work. The passkey half already works from any device with a
  platform authenticator, phones included.
- **Registering a passkey after migration is not wired in the interface.** The wallet contract
  supports it (an existing passkey authorises the new one); the demo states this instead of
  pretending.
- **No mainnet deployment.** Nothing in this repository has sent a mainnet transaction.

## After the hackathon

The useful part of Thine is not the migration, which is a one-off. It is the authority view: a
straight answer to "who can open this account". Accounts accumulate function call keys, delegates
and contract-mediated authority.

The migration is the first operation that view makes safe. The others are the same shape: revoking a
delegate you no longer recognise, rotating one passkey for another, adding a recovery delegate,
auditing an account you are about to be given control of. All of them are operations where the
question "what will be able to open this afterwards" is the one that matters, and all of them are
served by the same model and the same refusals.

Running it costs almost nothing to operate. A relayer paying 0.000793 NEAR per passkey hop can
cover a user's entire year of account operations for a fraction of a cent, which is why the
measurements in this repository exist: they are what makes that claim checkable rather than
asserted.

The parts worth keeping are already separated. `thine-core` holds the model, the preconditions and
the refusals, with no network in it; `thine-cli` is one consumer and a browser front end would be
another.

## Disclosures

- **Code written during the hackathon.** All of it. This repository was created on 4 November 2026
  and has no pre-hackathon history. The eligibility window opened 19 October 2026.
- **AI coding assistance was used** throughout, for writing and reviewing the Rust in `thine-core`,
  `thine-cli` and `thine-bench`, and for the measurement scripts. The architecture, the decision to
  make the authority view the product, the two-passkey rule and the refusals are the author's.
- **No templates or boilerplate.** The crates were written from scratch, not scaffolded.
- **Third-party code**, listed above under partner protocols. The two wallet contracts are NEAR's,
  not ours, and are committed as compiled artefacts under `res/` with their digests recorded. The
  `MockWalletWebauthnSigner` used by the tests is also NEAR's.
- **`contracts/thine-probe`** is ours, and exists only to put test accounts into the three
  pre-migration states. It is not part of the product.
- **No existing product on another chain.** Thine has no prior version anywhere.
- **Second entry.** The same author is entering a second, independent project,
  **Lyco**, at [github.com/Lideeyah/lyco](https://github.com/Lideeyah/lyco). The two share no code
  and no infrastructure. Lyco's README names this project in return.
- **Corrections.** `docs/verification-report.md` records the measurements and, where an earlier
  figure was wrong, says so and why. The testnet faucet figures were wrong in the first version of
  that document and are corrected there.

## Layout

```
crates/thine-core     the model: authority, plan, preconditions, refusals, chain reads
crates/thine-cli      the thine command: faucet, fund, publish, inspect
crates/thine-web      the server, the endpoints a browser needs, and the page
crates/thine-bench    the measurements, as committed tests
contracts/thine-probe a near-sdk contract used only to set up test states
res/                  the wallet contract artefacts, digest-checked on load
docs/                 the verification report behind the measurements
```

## Licence

MIT. See `LICENSE`.
