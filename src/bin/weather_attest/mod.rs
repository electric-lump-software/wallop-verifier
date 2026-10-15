//! `wallop-verify weather-attest`: compare a bundle's signed weather
//! observation with public records. Informational only: nothing here
//! feeds `VerificationReport::passed()`.

pub(crate) mod landobs;
pub(crate) mod synop;

/// The result of one comparison or lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Match(String),
    Mismatch(String),
    Unavailable(String),
    Present(String),
    Absent(String),
}
