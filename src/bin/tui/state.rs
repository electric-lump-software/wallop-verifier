use std::time::Instant;

use wallop_verifier::verify_steps::{StepResult, StepStatus, VerificationReport};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Interactive,
    Demo,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum View {
    BundleVerify,
    Selftest,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PinState {
    /// Selftest mode -- dim grey "test ·"
    Test,
    /// Green "a1b2 pinned ✓"
    Pinned { key_id: String },
    /// Red "a1b2 MISMATCH ✗"
    Mismatch { key_id: String },
    /// Yellow "unpinned ⚠"
    Unpinned,
}

#[derive(Debug, Clone)]
pub enum AnimationPhase {
    Idle,
    Spinning {
        step: usize,
        started_at: Instant,
    },
    #[allow(dead_code)]
    Scrambling {
        step: usize,
        started_at: Instant,
        target_hex: String,
    },
    Settled {
        step: usize,
        started_at: Instant,
    },
    VictoryRipple {
        started_at: Instant,
    },
    /// Demo finished — show summary screen.
    DemoComplete,
}

#[derive(Debug, Clone)]
pub struct ScenarioEntry {
    pub name: String,
    #[allow(dead_code)]
    pub description: String,
    pub tamper_summary: String,
    pub passed: Option<bool>,
    /// Per-step statuses for the heatmap display. Empty until the scenario has run.
    pub step_statuses: Vec<StepStatus>,
}

pub struct VerificationSession {
    pub mode: Mode,
    pub view: View,
    pub steps: Vec<StepResult>,
    /// How many steps have been revealed to the user (0..=total).
    pub revealed_count: usize,
    /// Cursor position in the step list.
    pub selected_step: usize,
    /// Whether the detail panel for the selected step is expanded.
    pub detail_expanded: bool,
    pub operator_pin: PinState,
    pub infra_pin: PinState,
    pub animation: AnimationPhase,
    pub scenarios: Vec<ScenarioEntry>,
    pub selected_scenario: usize,
    pub scenarios_passed: usize,
    pub scenarios_total: usize,
}

impl VerificationSession {
    /// Create a session for verifying a single proof bundle.
    /// Starts with zero steps revealed -- the user advances through them.
    pub fn new_bundle_verify(
        report: VerificationReport,
        op_pin: PinState,
        infra_pin: PinState,
    ) -> Self {
        Self {
            mode: Mode::Interactive,
            view: View::BundleVerify,
            steps: report.steps,
            revealed_count: 0,
            selected_step: 0,
            detail_expanded: false,
            animation: AnimationPhase::Idle,
            operator_pin: op_pin,
            infra_pin,
            scenarios: Vec::new(),
            selected_scenario: 0,
            scenarios_passed: 0,
            scenarios_total: 0,
        }
    }

    /// Create a session for running the selftest catalog.
    /// Pins are set to `Test` since selftest uses generated bundles.
    pub fn new_selftest(report: VerificationReport, scenarios: Vec<ScenarioEntry>) -> Self {
        let scenarios_total = scenarios.len();
        Self {
            mode: Mode::Interactive,
            view: View::Selftest,
            steps: report.steps,
            revealed_count: 0,
            selected_step: 0,
            detail_expanded: false,
            animation: AnimationPhase::Idle,
            operator_pin: PinState::Test,
            infra_pin: PinState::Test,
            scenarios,
            selected_scenario: 0,
            scenarios_passed: 0,
            scenarios_total,
        }
    }

    pub fn total_steps(&self) -> usize {
        self.steps.len()
    }

    pub fn all_revealed(&self) -> bool {
        self.revealed_count >= self.steps.len()
    }

    #[allow(dead_code)]
    pub fn visible_steps(&self) -> &[StepResult] {
        &self.steps[..self.revealed_count]
    }

    /// Reveal the next step, select it, and auto-expand detail if it failed.
    /// Returns `false` if all steps are already revealed.
    pub fn advance(&mut self) -> bool {
        if self.all_revealed() {
            return false;
        }
        self.revealed_count += 1;
        self.selected_step = self.revealed_count - 1;
        self.detail_expanded = matches!(self.steps[self.selected_step].status, StepStatus::Fail(_));
        true
    }

    /// Reveal all remaining steps at once, select the last one, and
    /// auto-expand detail if the last step failed.
    pub fn continue_all(&mut self) {
        self.revealed_count = self.steps.len();
        if !self.steps.is_empty() {
            self.selected_step = self.steps.len() - 1;
            self.detail_expanded =
                matches!(self.steps[self.selected_step].status, StepStatus::Fail(_));
        }
    }

    /// Move the step cursor up (towards index 0) within revealed steps.
    pub fn move_step_up(&mut self) {
        if self.selected_step > 0 {
            self.selected_step -= 1;
            self.detail_expanded =
                matches!(self.steps[self.selected_step].status, StepStatus::Fail(_));
        }
    }

    /// Move the step cursor down within revealed steps.
    pub fn move_step_down(&mut self) {
        if self.revealed_count > 0 && self.selected_step < self.revealed_count - 1 {
            self.selected_step += 1;
            self.detail_expanded =
                matches!(self.steps[self.selected_step].status, StepStatus::Fail(_));
        }
    }

    /// Toggle detail expansion for the currently selected step.
    pub fn toggle_detail(&mut self) {
        self.detail_expanded = !self.detail_expanded;
    }

    /// Move to the next scenario. Resets step state. Returns `false` at the end.
    pub fn next_scenario(&mut self) -> bool {
        if self.selected_scenario + 1 >= self.scenarios.len() {
            return false;
        }
        self.selected_scenario += 1;
        self.reset_step_state();
        true
    }

    /// Move to the previous scenario. Resets step state. Returns `false` at zero.
    pub fn prev_scenario(&mut self) -> bool {
        if self.selected_scenario == 0 {
            return false;
        }
        self.selected_scenario -= 1;
        self.reset_step_state();
        true
    }

    /// Swap in a new verification report, resetting step presentation state.
    pub fn replace_report(&mut self, report: VerificationReport) {
        self.steps = report.steps;
        self.reset_step_state();
    }

    /// Summary string once all steps are revealed.
    /// Returns `None` if not all steps have been revealed yet.
    pub fn result_summary(&self) -> Option<String> {
        if !self.all_revealed() {
            return None;
        }
        let fail_count = self
            .steps
            .iter()
            .filter(|s| matches!(s.status, StepStatus::Fail(_)))
            .count();
        if fail_count == 0 {
            Some("RESULT: PASS".to_string())
        } else {
            Some(format!("RESULT: FAIL ({fail_count} errors)"))
        }
    }

    fn reset_step_state(&mut self) {
        self.revealed_count = 0;
        self.selected_step = 0;
        self.detail_expanded = false;
        self.animation = AnimationPhase::Idle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallop_verifier::verify_steps::StepName;

    fn make_report(statuses: Vec<StepStatus>) -> VerificationReport {
        let names = StepName::all();
        let steps = statuses
            .into_iter()
            .enumerate()
            .map(|(i, status)| StepResult {
                name: names[i],
                status,
                detail: None,
            })
            .collect();
        VerificationReport {
            steps,
            operator_key_id: None,
            infra_key_id: None,
        }
    }

    fn all_pass_report() -> VerificationReport {
        make_report(vec![StepStatus::Pass; 9])
    }

    fn mixed_report() -> VerificationReport {
        make_report(vec![
            StepStatus::Pass,
            StepStatus::Pass,
            StepStatus::Pass,
            StepStatus::Pass,
            StepStatus::Fail("bad sig".into()),
            StepStatus::Fail("mismatch".into()),
            StepStatus::Skip("upstream failed".into()),
            StepStatus::Skip("upstream failed".into()),
            StepStatus::Pass,
        ])
    }

    fn sample_scenarios() -> Vec<ScenarioEntry> {
        vec![
            ScenarioEntry {
                name: "Tampered entries".into(),
                description: "Modify entry weights".into(),
                tamper_summary: "weight 1 -> 99".into(),
                passed: None,
                step_statuses: vec![],
            },
            ScenarioEntry {
                name: "Bad lock sig".into(),
                description: "Corrupt lock signature".into(),
                tamper_summary: "flip sig bytes".into(),
                passed: None,
                step_statuses: vec![],
            },
            ScenarioEntry {
                name: "Wrong seed".into(),
                description: "Alter the seed value".into(),
                tamper_summary: "seed -> ff..ff".into(),
                passed: None,
                step_statuses: vec![],
            },
        ]
    }

    #[test]
    fn new_session_starts_with_zero_revealed() {
        let session = VerificationSession::new_bundle_verify(
            all_pass_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        assert_eq!(session.revealed_count, 0);
        assert_eq!(session.selected_step, 0);
        assert!(!session.detail_expanded);
        assert_eq!(session.total_steps(), 9);
        assert!(!session.all_revealed());
        assert!(session.visible_steps().is_empty());
    }

    #[test]
    fn advance_reveals_one_step() {
        let mut session = VerificationSession::new_bundle_verify(
            all_pass_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        let advanced = session.advance();
        assert!(advanced);
        assert_eq!(session.revealed_count, 1);
        assert_eq!(session.selected_step, 0);
        assert_eq!(session.visible_steps().len(), 1);
    }

    #[test]
    fn advance_past_end_returns_false() {
        let mut session = VerificationSession::new_bundle_verify(
            all_pass_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        for _ in 0..9 {
            assert!(session.advance());
        }
        assert!(session.all_revealed());
        assert!(!session.advance());
        assert_eq!(session.revealed_count, 9);
    }

    #[test]
    fn continue_all_reveals_everything() {
        let mut session = VerificationSession::new_bundle_verify(
            all_pass_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        session.continue_all();
        assert!(session.all_revealed());
        assert_eq!(session.revealed_count, 9);
        assert_eq!(session.selected_step, 8);
        assert_eq!(session.visible_steps().len(), 9);
    }

    #[test]
    fn advance_auto_expands_detail_on_fail() {
        let mut session = VerificationSession::new_bundle_verify(
            mixed_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        // Steps 0-3 are Pass -- detail should not expand
        for _ in 0..4 {
            session.advance();
            assert!(!session.detail_expanded);
        }
        // Step 4 is Fail -- detail should expand
        session.advance();
        assert!(session.detail_expanded);
        assert_eq!(session.selected_step, 4);
    }

    #[test]
    fn move_step_cursor_stays_in_bounds() {
        let mut session = VerificationSession::new_bundle_verify(
            mixed_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        // Reveal 3 steps
        session.advance();
        session.advance();
        session.advance();
        assert_eq!(session.selected_step, 2);

        // Try to move past the end
        session.move_step_down();
        assert_eq!(session.selected_step, 2); // stays at last revealed

        // Move up to 0
        session.move_step_up();
        assert_eq!(session.selected_step, 1);
        session.move_step_up();
        assert_eq!(session.selected_step, 0);

        // Try to move before start
        session.move_step_up();
        assert_eq!(session.selected_step, 0); // stays at 0
    }

    #[test]
    fn result_summary_none_until_all_revealed() {
        let mut session = VerificationSession::new_bundle_verify(
            all_pass_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        assert!(session.result_summary().is_none());
        session.advance();
        assert!(session.result_summary().is_none());
    }

    #[test]
    fn result_summary_pass_when_all_pass() {
        let mut session = VerificationSession::new_bundle_verify(
            all_pass_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        session.continue_all();
        assert_eq!(session.result_summary(), Some("RESULT: PASS".to_string()));
    }

    #[test]
    fn result_summary_fail_with_count() {
        let mut session = VerificationSession::new_bundle_verify(
            mixed_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        session.continue_all();
        assert_eq!(
            session.result_summary(),
            Some("RESULT: FAIL (2 errors)".to_string())
        );
    }

    #[test]
    fn toggle_detail_flips_state() {
        let mut session = VerificationSession::new_bundle_verify(
            all_pass_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        session.advance();
        assert!(!session.detail_expanded);
        session.toggle_detail();
        assert!(session.detail_expanded);
        session.toggle_detail();
        assert!(!session.detail_expanded);
    }

    #[test]
    fn selftest_session_starts_at_first_scenario() {
        let scenarios = sample_scenarios();
        let session = VerificationSession::new_selftest(all_pass_report(), scenarios);
        assert_eq!(session.view, View::Selftest);
        assert_eq!(session.operator_pin, PinState::Test);
        assert_eq!(session.infra_pin, PinState::Test);
        assert_eq!(session.selected_scenario, 0);
        assert_eq!(session.scenarios_total, 3);
        assert_eq!(session.scenarios.len(), 3);
    }

    #[test]
    fn next_scenario_stops_at_end() {
        let scenarios = sample_scenarios();
        let mut session = VerificationSession::new_selftest(all_pass_report(), scenarios);
        assert!(session.next_scenario()); // 0 -> 1
        assert!(session.next_scenario()); // 1 -> 2
        assert!(!session.next_scenario()); // 2 -> can't go further
        assert_eq!(session.selected_scenario, 2);
    }

    #[test]
    fn prev_scenario_stops_at_zero() {
        let scenarios = sample_scenarios();
        let mut session = VerificationSession::new_selftest(all_pass_report(), scenarios);
        session.next_scenario(); // move to 1
        assert!(session.prev_scenario()); // 1 -> 0
        assert!(!session.prev_scenario()); // 0 -> can't go further
        assert_eq!(session.selected_scenario, 0);
    }

    #[test]
    fn scenario_switch_resets_revealed_steps() {
        let scenarios = sample_scenarios();
        let mut session = VerificationSession::new_selftest(all_pass_report(), scenarios);
        // Reveal some steps
        session.advance();
        session.advance();
        session.advance();
        assert_eq!(session.revealed_count, 3);
        assert_eq!(session.selected_step, 2);

        // Switch scenario
        session.next_scenario();
        assert_eq!(session.revealed_count, 0);
        assert_eq!(session.selected_step, 0);
        assert!(!session.detail_expanded);
    }

    #[test]
    fn replace_report_resets_step_state() {
        let mut session = VerificationSession::new_bundle_verify(
            mixed_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        // Reveal several steps and move the cursor
        session.continue_all();
        assert_eq!(session.revealed_count, 9);
        assert_eq!(session.selected_step, 8);

        // Replace with a fresh all-pass report
        session.replace_report(all_pass_report());

        assert_eq!(session.steps.len(), 9);
        assert!(session.steps.iter().all(|s| s.status == StepStatus::Pass));
        assert_eq!(session.revealed_count, 0);
        assert_eq!(session.selected_step, 0);
        assert!(!session.detail_expanded);
    }

    #[test]
    fn animation_phase_starts_idle() {
        let session = VerificationSession::new_bundle_verify(
            all_pass_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        assert!(matches!(session.animation, AnimationPhase::Idle));
    }

    #[test]
    fn scenario_switch_resets_animation() {
        let scenarios = vec![
            ScenarioEntry {
                name: "a".into(),
                description: "".into(),
                tamper_summary: "".into(),
                passed: None,
                step_statuses: vec![],
            },
            ScenarioEntry {
                name: "b".into(),
                description: "".into(),
                tamper_summary: "".into(),
                passed: None,
                step_statuses: vec![],
            },
        ];
        let mut session = VerificationSession::new_selftest(all_pass_report(), scenarios);
        session.animation = AnimationPhase::Spinning {
            step: 0,
            started_at: std::time::Instant::now(),
        };
        session.next_scenario();
        assert!(matches!(session.animation, AnimationPhase::Idle));
    }

    #[test]
    fn move_step_cursor_sets_detail_expanded() {
        let mut session = VerificationSession::new_bundle_verify(
            mixed_report(),
            PinState::Unpinned,
            PinState::Unpinned,
        );
        // Reveal all steps so we can navigate freely
        session.continue_all();

        // Move cursor to index 4 (Fail "bad sig")
        // continue_all leaves selected_step at 8; move up to 4
        for _ in 0..4 {
            session.move_step_up();
        }
        assert_eq!(session.selected_step, 4);
        assert!(session.detail_expanded, "FAIL step should expand detail");

        // Move up to index 3 (Pass) -- detail should collapse
        session.move_step_up();
        assert_eq!(session.selected_step, 3);
        assert!(!session.detail_expanded, "PASS step should collapse detail");

        // Move back down to index 4 (Fail) -- detail should re-expand
        session.move_step_down();
        assert_eq!(session.selected_step, 4);
        assert!(
            session.detail_expanded,
            "FAIL step should expand detail on move_down"
        );

        // Move down to index 5 (Fail "mismatch") -- detail stays expanded
        session.move_step_down();
        assert_eq!(session.selected_step, 5);
        assert!(session.detail_expanded, "FAIL step 5 should expand detail");
    }
}
