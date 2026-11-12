# The real-device run

Everything else is done; this is the only thing left that needs a person at
the machine, because it needs a finger on a real authenticator. About five
minutes. Every virtual-authenticator run so far exercised everything between
the authenticator and the chain; this run replaces only the authenticator.

## If the hosted demo is up

1. Open the demo URL in Safari or Chrome on any device with a platform
   authenticator (a Mac with Touch ID, an iPhone, an Android phone).
2. Press **Create a demo account to migrate**. A fresh testnet account
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
9. The final authority view shows the account opened by your passkeys, the
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

One take of steps 2 through 9 is the complete story: a real account, a real
device, and an irreversible change a viewer can verify on an explorer.
