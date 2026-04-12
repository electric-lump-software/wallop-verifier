//! Tamper scenario catalog, loader, and runner for `wallop-verify selftest`.
//!
//! All items in this module are `pub(crate)` — internal to the wallop_verifier
//! crate. The only public surface from this work is `StepName` (always public,
//! in verify_steps) and the `wallop-verify selftest` CLI subcommand.

pub(crate) mod keypairs;
pub(crate) mod loader;
pub(crate) mod mutations;
pub(crate) mod runner;
pub(crate) mod schema;
