# The real-device run

Everything else is done; this is the only thing left that needs a person at
the machine, because it needs a finger on a real authenticator. About five
minutes. Every virtual-authenticator run so far exercised everything between
the authenticator and the chain; this run replaces only the authenticator.

## The strongest take: an account that already exists

The demo-mode take below migrates an account created seconds earlier. This
take migrates one that already has a past, which is the product's actual
claim. It mixes a terminal with the browser, and that is fine on camera: the
terminal is where the chain speaks in its own words.

Prepare once, off camera:

```bash
cargo run -p thine-web --release --example existing_account -- prepare
```

This prints an account id and a seed phrase, gives the account a history
signed by that phrase (a deployed contract, state, a transfer), and writes
the key where the server expects it. Keep the output. Then:

```bash
cargo run -p thine-web --release --bin thine-web --     --account <the printed account id>     --send-rpc https://rpc.testnet.fastnear.com --listen 127.0.0.1:8081
```

On camera, in order:

1. Show the account's past: open
   `https://testnet.nearblocks.io/address/<account id>` in a tab. A deployed
   contract and a history of transactions, none of them made by Thine.
2. In the terminal, show the phrase opening the account:

   ```bash
   cargo run -p thine-web --release --example existing_account --        try-seed <account id> <the twelve words>
   ```

   The chain accepts a transaction and prints its hash.
3. Open **http://localhost:8081**. The authority view loads straight onto
   the account: one full access key, and the prior contract's storage
   already surfaced as bytes nothing will be able to read.
4. Migrate exactly as in the demo-mode steps 3 to 8 below: two passkeys
   created, registered and proven with a finger on the real authenticator,
   then the self hold, then the typed confirmation and the last key.
5. Run the same try-seed command again. The chain refuses it: the key the
   phrase derives no longer exists. This is the whole product in one line.
6. End on the final authority view: the account opened by the passkeys, the
   removed key and self hold struck through with their transaction hashes,
   and the storage line still telling the truth about the past. Paste a
   removal hash into `https://testnet.nearblocks.io/txns/<hash>`.

## If the hosted demo is up

The stable address is `https://lideeyah.github.io/redirect/`, which forwards
to the live demo.

1. Open the demo URL in Safari or Chrome on any device with a platform
   authenticator (a Mac with Touch ID, an iPhone, an Android phone).
2. Press **Create a practice account**. A fresh testnet account
   appears as the authority view, opened by one full access key.
3. Press **Change the lock**. Step 1 runs; the create screen appears.
4. Type a name for the device, press **Create passkey**, and approve the
   system sheet with your fingerprint or face. The derived `0s` address
   appears. Press **Continue**, then **Register** on the row, approving the
   sheet again when asked.
5. Press **Register another passkey** and repeat step 4. A second real device
   is better; a second passkey on the same device also works.
6. Press **Continue**, then **Prove this one** on each row, approving the
   sheet each time. This is the two-hop proof, on chain, from your device.
7. Press **Continue**, then **Remove the self hold**.
8. When the second part appears, read the four lines, type the account id
   into the confirmation, and press **Remove last key**.
9. Press **Try the seed phrase** before step 3 and once more at the end: the
   first answer is the chain accepting a transaction signed with the phrase,
   the second is the chain refusing it because the key no longer exists.
10. The final authority view shows the account opened by your passkeys, the
   removed key and the removed self hold struck through, each with the
   transaction hash that removed it. Copy either hash into
   `https://testnet.nearblocks.io/txns/<hash>` to check it on an explorer.

## If running locally instead

```bash
cd Thine
cargo run -p thine-web --bin thine-web -- --demo \
    --send-rpc https://rpc.testnet.fastnear.com
```

Then open **http://localhost:8080** (localhost, not the IP: an IP address
cannot be a WebAuthn relying party) and follow the same clicks from step 2.

## What to capture for the demo video

The existing-account take above is the complete story: an account with a
past, a real device, and an irreversible change a viewer can verify on an
explorer. The demo-mode take is the fallback if the terminal feels like too
much; its account is created on camera, so say so rather than implying it
was old.
