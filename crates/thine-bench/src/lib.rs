//! Thine's measurements live in `tests/`, where `cargo test` runs them. This
//! crate exists only to host them.
//!
//! - `thine_p256_gas` — what a passkey execution hop costs.
//! - `thine_migration_state` — migrating an account that already has state.
//! - `thine_publish_cost` — what publishing the contracts burns.
//!
//! Each needs a Docker daemon, because `near-kit-sandbox` runs `neard` in a
//! container. See the README.
