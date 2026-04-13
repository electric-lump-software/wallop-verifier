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
use super::state::{AnimationPhase, Mode, VerificationSession};

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

const DEMO_SPINNER_DURATION: Duration = Duration::from_millis(400);
const DEMO_SCRAMBLE_DURATION: Duration = Duration::from_millis(300);
const DEMO_SETTLE_PAUSE: Duration = Duration::from_millis(100);
const DEMO_FAIL_EXTRA: Duration = Duration::from_millis(700);
const DEMO_SCENARIO_DELAY: Duration = Duration::from_millis(2000);

fn run_demo_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    session: &mut VerificationSession,
    scenario_reports: Option<&[Option<VerificationReport>]>,
) -> io::Result<()> {
    let total_scenarios = session.scenarios_total;
    let mut scenario_idx = 0;

    loop {
        // Draw frame
        terminal.draw(|frame| render::render(session, frame))?;

        match session.animation.clone() {
            AnimationPhase::Idle => {
                if !session.all_revealed() {
                    // Start spinning on next step
                    let step = session.revealed_count;
                    session.animation = AnimationPhase::Spinning {
                        step,
                        started_at: Instant::now(),
                    };
                } else {
                    // All steps revealed for this scenario
                    // Mark current scenario result
                    if scenario_idx < session.scenarios.len()
                        && session.scenarios[scenario_idx].passed.is_none()
                    {
                        let has_fail = session.steps.iter().any(|s| {
                            matches!(
                                s.status,
                                wallop_verifier::verify_steps::StepStatus::Fail(_)
                            )
                        });
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
                    if wait_or_quit(DEMO_SCENARIO_DELAY)? {
                        return Ok(());
                    }

                    // Advance to next scenario
                    let old = session.selected_scenario;
                    session.next_scenario();
                    apply_scenario_report(session, old, scenario_reports);
                }
            }
            AnimationPhase::Spinning { step, started_at } => {
                if started_at.elapsed() > DEMO_SPINNER_DURATION {
                    let target = get_target_hex_for_step(session, step);
                    if target.is_empty() {
                        // No hex for this step (winners, BLS) -- skip scramble
                        session.advance();
                        session.animation = AnimationPhase::Settled {
                            step,
                            started_at: Instant::now(),
                        };
                    } else {
                        session.animation = AnimationPhase::Scrambling {
                            step,
                            started_at: Instant::now(),
                            target_hex: target,
                        };
                    }
                }
            }
            AnimationPhase::Scrambling { step, started_at, .. } => {
                if started_at.elapsed() > DEMO_SCRAMBLE_DURATION {
                    session.advance();
                    session.animation = AnimationPhase::Settled {
                        step,
                        started_at: Instant::now(),
                    };
                }
            }
            AnimationPhase::Settled { step, started_at } => {
                let step_failed = matches!(
                    session.steps.get(step).map(|s| &s.status),
                    Some(wallop_verifier::verify_steps::StepStatus::Fail(_))
                );
                let pause = if step_failed {
                    DEMO_SETTLE_PAUSE + DEMO_FAIL_EXTRA
                } else {
                    DEMO_SETTLE_PAUSE
                };
                if started_at.elapsed() > pause {
                    session.animation = AnimationPhase::Idle;
                }
            }
        }

        // Poll for quit (50ms timeout)
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key_event) = event::read()?
            && (key_event.code == KeyCode::Char('q')
                || (key_event.modifiers.contains(KeyModifiers::CONTROL)
                    && key_event.code == KeyCode::Char('c')))
        {
            return Ok(());
        }
    }
}

fn get_target_hex_for_step(session: &VerificationSession, step_idx: usize) -> String {
    use wallop_verifier::verify_steps::{StepDetail, StepName};
    if step_idx >= session.steps.len() {
        return String::new();
    }
    let step = &session.steps[step_idx];

    // Steps with no meaningful hex to show
    match step.name {
        StepName::WinnerSelection | StepName::DrandBlsSignature => String::new(),
        _ => {
            // Try to get hex from StepDetail
            match &step.detail {
                Some(StepDetail::HexMismatch { expected, .. }) => {
                    // Show expected (the correct value) truncated to 32 chars
                    expected.chars().take(32).collect()
                }
                None => {
                    // For passing steps, generate a plausible-looking hex string
                    // Use a deterministic approach based on step index
                    let fake: String = (0..32)
                        .map(|j| {
                            let byte = ((step_idx * 17 + j * 31) % 16) as u8;
                            char::from(if byte < 10 {
                                b'0' + byte
                            } else {
                                b'a' + byte - 10
                            })
                        })
                        .collect();
                    fake
                }
            }
        }
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
