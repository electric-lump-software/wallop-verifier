use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use wallop_verifier::verify_steps::VerificationReport;

use super::input::{Action, map_key};
use super::render;
use super::state::{Mode, VerificationSession};

/// Run the TUI with pre-computed per-scenario reports for selftest mode.
pub fn run_with_reports(
    session: VerificationSession,
    scenario_reports: Vec<Option<VerificationReport>>,
) -> io::Result<()> {
    run_inner(session, Some(scenario_reports))
}

pub fn run(session: VerificationSession) -> io::Result<()> {
    run_inner(session, None)
}

fn run_inner(
    mut session: VerificationSession,
    scenario_reports: Option<Vec<Option<VerificationReport>>>,
) -> io::Result<()> {
    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = run_loop(&mut terminal, &mut session, scenario_reports);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    session: &mut VerificationSession,
    scenario_reports: Option<Vec<Option<VerificationReport>>>,
) -> io::Result<()> {
    if session.mode == Mode::Demo {
        run_demo_loop(terminal, session, scenario_reports.as_deref())
    } else {
        run_interactive_loop(terminal, session, scenario_reports.as_deref())
    }
}

fn run_interactive_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    session: &mut VerificationSession,
    scenario_reports: Option<&[Option<VerificationReport>]>,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| render::render(session, frame))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key_event) = event::read()?
            && let Some(action) = map_key(key_event, session.view)
        {
            match action {
                Action::Quit => break,
                Action::Advance => {
                    if session.all_revealed() {
                        session.toggle_detail();
                    } else {
                        session.advance();
                    }
                }
                Action::ContinueAll => session.continue_all(),
                Action::StepUp => session.move_step_up(),
                Action::StepDown => session.move_step_down(),
                Action::NextScenario => {
                    let old = session.selected_scenario;
                    session.next_scenario();
                    apply_scenario_report(session, old, scenario_reports);
                }
                Action::PrevScenario => {
                    let old = session.selected_scenario;
                    session.prev_scenario();
                    apply_scenario_report(session, old, scenario_reports);
                }
            }
        }
    }
    Ok(())
}

/// Replace the session's verification report with the pre-computed one for the
/// newly selected scenario, if available and the scenario actually changed.
fn apply_scenario_report(
    session: &mut VerificationSession,
    old_index: usize,
    scenario_reports: Option<&[Option<VerificationReport>]>,
) {
    let new_index = session.selected_scenario;
    if new_index == old_index {
        return;
    }
    if let Some(reports) = scenario_reports
        && let Some(Some(report)) = reports.get(new_index)
    {
        session.replace_report(report.clone());
    }
}

fn run_demo_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    session: &mut VerificationSession,
    scenario_reports: Option<&[Option<VerificationReport>]>,
) -> io::Result<()> {
    let step_delay_pass = Duration::from_millis(800);
    let step_delay_fail = Duration::from_millis(1500);
    let scenario_pause = Duration::from_millis(2000);

    let total_scenarios = session.scenarios_total;
    let mut scenario_idx = 0;

    loop {
        // Animate step reveals for the current scenario
        while !session.all_revealed() {
            terminal.draw(|frame| render::render(session, frame))?;

            // Determine delay based on what the next step's status will be
            let next_step_idx = session.revealed_count;
            let delay = if next_step_idx < session.steps.len() {
                match &session.steps[next_step_idx].status {
                    wallop_verifier::verify_steps::StepStatus::Fail(_) => step_delay_fail,
                    _ => step_delay_pass,
                }
            } else {
                step_delay_pass
            };

            // Wait, but check for quit
            if wait_or_quit(delay)? {
                return Ok(());
            }

            session.advance();
        }

        // Draw the final state with all steps revealed
        terminal.draw(|frame| render::render(session, frame))?;

        // Mark current scenario result
        if scenario_idx < session.scenarios.len() {
            let has_fail = session
                .steps
                .iter()
                .any(|s| matches!(s.status, wallop_verifier::verify_steps::StepStatus::Fail(_)));
            session.scenarios[scenario_idx].passed = Some(!has_fail);
            if !has_fail {
                session.scenarios_passed += 1;
            }
        }

        // Redraw with updated scenario status
        terminal.draw(|frame| render::render(session, frame))?;

        // Check if this was the last scenario
        scenario_idx += 1;
        if scenario_idx >= total_scenarios {
            // Hold on summary -- wait for quit
            loop {
                terminal.draw(|frame| render::render(session, frame))?;
                if event::poll(Duration::from_millis(100))?
                    && let Event::Key(key_event) = event::read()?
                    && (key_event.code == KeyCode::Char('q')
                        || (key_event.modifiers.contains(KeyModifiers::CONTROL)
                            && key_event.code == KeyCode::Char('c')))
                {
                    return Ok(());
                }
            }
        }

        // Pause between scenarios
        if wait_or_quit(scenario_pause)? {
            return Ok(());
        }

        // Advance to next scenario
        let old = session.selected_scenario;
        session.next_scenario();
        apply_scenario_report(session, old, scenario_reports);
    }
}

/// Wait for `duration`, returning `true` if the user pressed 'q' or Ctrl-C.
fn wait_or_quit(duration: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let remaining = deadline - Instant::now();
        let poll_time = remaining.min(Duration::from_millis(50));
        if event::poll(poll_time)?
            && let Event::Key(key_event) = event::read()?
            && (key_event.code == KeyCode::Char('q')
                || (key_event.modifiers.contains(KeyModifiers::CONTROL)
                    && key_event.code == KeyCode::Char('c')))
        {
            return Ok(true);
        }
    }
    Ok(false)
}
