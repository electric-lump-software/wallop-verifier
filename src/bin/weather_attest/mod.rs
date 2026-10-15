//! `wallop-verify weather-attest`: compare a bundle's signed weather
//! observation with public records. Informational only: nothing here
//! feeds `VerificationReport::passed()`.

pub(crate) mod http;
pub(crate) mod landobs;
pub(crate) mod synop;

/// Sent with every request this subcommand makes.
pub(crate) const USER_AGENT: &str = concat!(
    "wallop-verify/",
    env!("CARGO_PKG_VERSION"),
    " weather-attest"
);

/// The result of one comparison or lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Match(String),
    Mismatch(String),
    Unavailable(String),
    Present(String),
    Absent(String),
}
