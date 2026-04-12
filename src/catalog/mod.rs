//! Tamper scenario catalog, loader, and runner for `wallop-verify selftest`.
//!
//! All items in this module are `pub(crate)` — internal to the wallop_verifier
//! crate. The only public surface from this work is `StepName` (always public,
//! in verify_steps) and the `wallop-verify selftest` CLI subcommand.

pub(crate) mod keypairs;
pub(crate) mod loader;
pub(crate) mod mutations;
pub mod runner;
pub(crate) mod schema;

/// The shipping tamper scenario catalog, baked into the binary at compile time.
const SHIPPING_CATALOG_JSON: &str = include_str!("scenarios.json");

/// Load and run the shipping catalog.
pub fn run_shipping_catalog() -> Result<runner::CatalogReport, runner::RunError> {
    runner::run_catalog_from_str(SHIPPING_CATALOG_JSON)
}

/// Load and run the shipping catalog, returning per-scenario `VerificationReport`s
/// alongside the overall `CatalogReport`. Used by the TUI to display step-by-step
/// results when the user switches between scenarios.
pub fn run_shipping_catalog_with_reports() -> Result<
    (
        runner::CatalogReport,
        Vec<Option<crate::verify_steps::VerificationReport>>,
    ),
    runner::RunError,
> {
    runner::run_catalog_from_str_with_reports(SHIPPING_CATALOG_JSON)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipping_catalog_parses_and_validates() {
        let _catalog = loader::load_catalog_from_str(SHIPPING_CATALOG_JSON)
            .expect("shipping catalog must parse and validate");
    }

    #[test]
    fn shipping_catalog_runs_without_errors() {
        let report = run_shipping_catalog().expect("shipping catalog must run");
        assert!(report.total_scenarios > 0, "catalog should have scenarios");
        // We don't assert zero failures here — that's the selftest command's
        // responsibility. This test only verifies the catalog is structurally
        // valid and runnable.
    }

    #[test]
    fn shipping_catalog_scenarios_that_run_all_pass() {
        let report = run_shipping_catalog().expect("shipping catalog must run");
        assert_eq!(
            report.failed_p0, 0,
            "no scenario should pass when it should fail (P0)"
        );
        assert_eq!(
            report.caught_by_wrong_step, 0,
            "no scenario should be caught by an unexpected step"
        );
        // Coverage completeness is NOT asserted here — the initial catalog
        // may not cover all StepName variants. That's intentional — more
        // scenarios are added iteratively.
    }
}
