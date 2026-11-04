//! A deliberately ordinary near-sdk contract, used by Thine check 2 to put an
//! account into each of the three pre-migration states we need to test.
use near_sdk::{env, near};

#[near(contract_state)]
#[derive(Default)]
pub struct Probe {
    counter: u64,
}

#[near]
impl Probe {
    /// Mutates contract state, which makes near-sdk persist it under its
    /// default state key `b"STATE"` when the call returns.
    pub fn bump(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    /// Write an arbitrary storage key.
    pub fn put(&mut self, key: String, value: String) {
        env::storage_write(key.as_bytes(), value.as_bytes());
    }

    /// Write the *empty* storage key `b""`, which is the key the wallet
    /// contract uses for its own state.
    pub fn put_empty_key(&mut self, value: String) {
        env::storage_write(b"", value.as_bytes());
    }

    pub fn has(&self, key: String) -> bool {
        env::storage_has_key(key.as_bytes())
    }

    pub fn has_empty_key(&self) -> bool {
        env::storage_has_key(b"")
    }
}
