use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use wallop_verifier::verify_steps::{StepDetail, StepStatus};

use super::state::{AnimationPhase, Mode, PinState, VerificationSession, View};

const SPINNER_CHARS: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Top-level render entry point.
pub fn render(session: &VerificationSession, frame: &mut Frame) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(frame.area());

    let main_area = outer[0];
    let footer_area = outer[1];

    match session.view {
        View::Selftest => {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
                .split(main_area);
            render_scenario_list(session, frame, cols[0]);
            render_step_panel(session, frame, cols[1]);
        }
        View::BundleVerify => {
            render_step_panel(session, frame, main_area);
        }
    }

    render_footer(session, frame, footer_area);
}

// ── Scenario list (selftest only) ──────────────────────────────────────────

fn render_scenario_list(session: &VerificationSession, frame: &mut Frame, area: Rect) {
    let running = session
        .scenarios
        .iter()
        .filter(|s| s.passed.is_none())
        .count();

    let title = format!(
        " SCENARIOS ({}/{} passed) ",
        session.scenarios_passed, session.scenarios_total
    );

    let items: Vec<ListItem> = session
        .scenarios
        .iter()
        .enumerate()
        .map(|(i, sc)| {
            let is_selected = i == session.selected_scenario;
            let marker = if is_selected { "▶ " } else { "  " };

            let (prefix, color) = match sc.passed {
                Some(true) => ("✓ ", Color::Green),
                Some(false) => ("✗ ", Color::Red),
                None => ("  ", Color::DarkGray),
            };
            let row_color = if is_selected { Color::Yellow } else { color };
            let text = format!("{marker}{prefix}{}", sc.name);
            let name_line = Line::from(Span::from(text).style(Style::default().fg(row_color)));
            let mut item_lines = vec![name_line];
            if is_selected && !sc.step_statuses.is_empty() {
                let mut hm_spans: Vec<Span> = vec![Span::from("      ").style(Style::default())];
                for status in &sc.step_statuses {
                    let (ch, color) = match status {
                        StepStatus::Pass => ("▓", Color::Green),
                        StepStatus::Fail(_) => ("▓", Color::Red),
                        StepStatus::Skip(_) => ("░", Color::DarkGray),
                    };
                    hm_spans.push(Span::from(ch).style(Style::default().fg(color)));
                }
                item_lines.push(Line::from(hm_spans));
            }
            ListItem::new(item_lines)
        })
        .collect();

    let bottom_line = format!(
        " {}/{} passed \u{00b7} {} running",
        session.scenarios_passed, session.scenarios_total, running
    );

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    // Split area: list above, counter line below
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let list = List::new(items);
    frame.render_widget(list, chunks[0]);

    let counter = Paragraph::new(Line::from(
        Span::from(bottom_line).style(Style::default().fg(Color::DarkGray)),
    ));
    frame.render_widget(counter, chunks[1]);
}

// ── Step panel ─────────────────────────────────────────────────────────────

fn render_step_panel(session: &VerificationSession, frame: &mut Frame, area: Rect) {
    if matches!(session.animation, AnimationPhase::DemoComplete) {
        render_demo_complete(session, frame, area);
        return;
    }

    let title = build_step_panel_title(session);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Build line items
    let mut lines: Vec<Line> = Vec::new();
    let total = session.total_steps();

    for i in 0..total {
        // Check if this step is the one being animated
        let anim_step = match &session.animation {
            AnimationPhase::Spinning { step, .. } => Some(*step),
            AnimationPhase::Scrambling { step, .. } => Some(*step),
            _ => None,
        };

        if i < session.revealed_count {
            // Revealed step
            let step = &session.steps[i];
            let is_selected = i == session.selected_step;

            let gutter = if is_selected { " \u{25b6} " } else { "   " };

            let name_str = format!("{}", step.name);
            let (status_label, status_color) = match &step.status {
                StepStatus::Pass => ("PASS", Color::Green),
                StepStatus::Fail(_) => ("FAIL", Color::Red),
                StepStatus::Skip(_) => ("SKIP", Color::DarkGray),
            };

            // Calculate dots to fill between name and status.
            // Total line: gutter(3) + name + ' ' + dots + ' ' + status
            let available = inner.width as usize;
            let gutter_len = 3;
            let name_len = name_str.len();
            let status_len = status_label.len();
            let min_dots = 2;
            let fixed_width = gutter_len + name_len + 2 + status_len; // 2 = spaces around dots
            let dots_count = available.saturating_sub(fixed_width).max(min_dots);
            let dots: String = " ".to_string() + &".".repeat(dots_count) + " ";

            let bg = if is_selected {
                Color::Rgb(30, 30, 50)
            } else {
                Color::Reset
            };

            let line = Line::from(vec![
                Span::from(gutter.to_string()).style(Style::default().fg(Color::White).bg(bg)),
                Span::from(name_str).style(Style::default().fg(Color::White).bg(bg)),
                Span::from(dots).style(Style::default().fg(Color::DarkGray).bg(bg)),
                Span::from(status_label.to_string())
                    .style(Style::default().fg(status_color).bg(bg)),
            ]);
            lines.push(line);

            // Inline detail expansion
            if is_selected && session.detail_expanded {
                render_detail_lines(&step.status, &step.detail, &mut lines);
            }
        } else if anim_step == Some(i) {
            // This step is being animated
            let step = &session.steps[i];
            let name_str = format!("{}", step.name);

            match &session.animation {
                AnimationPhase::Spinning { started_at, .. } => {
                    let elapsed_ms = started_at.elapsed().as_millis() as usize;
                    let spinner_idx = (elapsed_ms / 80) % SPINNER_CHARS.len();
                    let spinner = SPINNER_CHARS[spinner_idx];

                    // Calculate wave area width (same formula as dots)
                    let available = inner.width as usize;
                    let gutter_len = 3;
                    let name_len = name_str.len();
                    let status_len = 4;
                    let min_dots = 2;
                    let fixed_width = gutter_len + name_len + 2 + status_len;
                    let wave_count = available.saturating_sub(fixed_width).max(min_dots);

                    // Small travelling wave: mostly flat dots with a gentle
                    // 3-4 char ripple moving across. Subtle, like a pulse.
                    //
                    // Most chars are '·' (flat). The wave is a small bump
                    // that travels left-to-right across the dot area.
                    const RIPPLE: &[char] = &['·', '⠒', '⠊', '⠉', '⠊', '⠒', '·'];
                    let ripple_len = RIPPLE.len();

                    // Wave position moves across the dot area
                    let wave_speed = 40.0_f64; // ms per column
                    let wave_pos = (elapsed_ms as f64 / wave_speed) as isize;

                    let mut wave_spans: Vec<Span> = vec![
                        Span::from(format!(" {spinner} "))
                            .style(Style::default().fg(Color::Yellow)),
                        Span::from(name_str).style(Style::default().fg(Color::White)),
                        Span::from(" ").style(Style::default()),
                    ];

                    let dot_color = Color::Rgb(70, 70, 70);
                    for ci in 0..wave_count {
                        // Distance from wave centre
                        let dist =
                            ci as isize - (wave_pos % (wave_count as isize + ripple_len as isize));
                        if dist >= 0 && (dist as usize) < ripple_len {
                            let ch = RIPPLE[dist as usize];
                            let brightness: u8 = if dist == 3 {
                                120
                            } else if dist == 2 || dist == 4 {
                                100
                            } else {
                                80
                            };
                            wave_spans.push(Span::from(ch.to_string()).style(
                                Style::default().fg(Color::Rgb(brightness, brightness, brightness)),
                            ));
                        } else {
                            wave_spans.push(Span::from("·").style(Style::default().fg(dot_color)));
                        }
                    }

                    wave_spans.push(Span::from(" ").style(Style::default()));
                    wave_spans.push(Span::from("    ").style(Style::default()));

                    lines.push(Line::from(wave_spans));
                }
                AnimationPhase::Scrambling { started_at, .. } => {
                    // Status slot (4 chars) scrambles left-to-right to the real value
                    let elapsed_ms = started_at.elapsed().as_millis() as usize;
                    let step = &session.steps[i];

                    let (status_label, status_color) = match &step.status {
                        StepStatus::Pass => ("PASS", Color::Green),
                        StepStatus::Fail(_) => ("FAIL", Color::Red),
                        StepStatus::Skip(_) => ("SKIP", Color::DarkGray),
                    };
                    let status_chars: Vec<char> = status_label.chars().collect();
                    let total = status_chars.len(); // always 4
                    let elapsed_frac = (elapsed_ms as f64) / 300.0;
                    let settled_count = ((elapsed_frac * total as f64) as usize).min(total);

                    // Normal dots (no pulse)
                    let available = inner.width as usize;
                    let gutter_len = 3;
                    let name_len = name_str.len();
                    let min_dots = 2;
                    let fixed_width = gutter_len + name_len + 2 + total;
                    let dots_count = available.saturating_sub(fixed_width).max(min_dots);
                    let dots: String = " ".to_string() + &".".repeat(dots_count) + " ";

                    let mut spans: Vec<Span> = vec![
                        Span::from("   ").style(Style::default().fg(Color::White)),
                        Span::from(name_str).style(Style::default().fg(Color::White)),
                        Span::from(dots).style(Style::default().fg(Color::DarkGray)),
                    ];

                    // Build the 4-char status with settled/scrambling chars
                    for (ci, &real_ch) in status_chars.iter().enumerate() {
                        if ci < settled_count {
                            spans.push(
                                Span::from(real_ch.to_string())
                                    .style(Style::default().fg(status_color)),
                            );
                        } else {
                            let pseudo = ((elapsed_ms / 30 + ci * 7) % 36) as u8;
                            let ch = char::from(if pseudo < 10 {
                                b'0' + pseudo
                            } else {
                                b'a' + pseudo - 10
                            });
                            spans.push(
                                Span::from(ch.to_string())
                                    .style(Style::default().fg(Color::Yellow)),
                            );
                        }
                    }

                    lines.push(Line::from(spans));
                }
                _ => {}
            }
        } else {
            // Unrevealed step
            let step = &session.steps[i];
            let name_str = format!("{}", step.name);
            let dim = Style::default().fg(Color::Rgb(60, 60, 60));
            let line = Line::from(vec![
                Span::from("   ").style(dim),
                Span::from(name_str).style(dim),
                Span::from(" \u{00b7}\u{00b7}\u{00b7}").style(dim),
            ]);
            lines.push(line);
        }
    }

    // Result summary at the bottom once all revealed
    if let Some(summary) = session.result_summary() {
        lines.push(Line::from(""));
        let color = if summary.contains("PASS") {
            // During victory ripple, pulse the green brightness
            if let AnimationPhase::VictoryRipple { started_at } = &session.animation {
                let elapsed_ms = started_at.elapsed().as_millis() as f64;
                // Pulse: 180 -> 255 -> 180 over 800ms (sine wave)
                let t = (elapsed_ms / 800.0) * std::f64::consts::PI;
                let bright = 180.0 + 75.0 * t.sin();
                Color::Rgb(0, bright.clamp(0.0, 255.0) as u8, 0)
            } else {
                Color::Green
            }
        } else {
            Color::Red
        };
        lines
            .push(Line::from(Span::from(format!("   {summary}")).style(
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            )));
    }

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

fn render_demo_complete(session: &VerificationSession, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" SELFTEST COMPLETE ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    let version = env!("CARGO_PKG_VERSION");
    lines.push(Line::from(
        Span::from(format!("   wallop-verify {version} selftest")).style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ));
    lines.push(Line::from(""));

    // Per-scenario results with heatmaps
    for sc in &session.scenarios {
        let (status_ch, color) = match sc.passed {
            Some(true) => ("CAUGHT", Color::Green),
            Some(false) => ("MISSED", Color::Red),
            None => ("SKIP  ", Color::DarkGray),
        };

        let mut spans: Vec<Span> = vec![
            Span::from("   ").style(Style::default()),
            Span::from(status_ch).style(Style::default().fg(color)),
            Span::from("  ").style(Style::default()),
        ];

        // Mini heatmap
        for status in &sc.step_statuses {
            let (ch, c) = match status {
                StepStatus::Pass => ("▓", Color::Green),
                StepStatus::Fail(_) => ("▓", Color::Red),
                StepStatus::Skip(_) => ("░", Color::DarkGray),
            };
            spans.push(Span::from(ch).style(Style::default().fg(c)));
        }

        spans.push(Span::from(format!("  {}", sc.name)).style(Style::default().fg(Color::White)));
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(""));

    // Summary
    let passed = session
        .scenarios
        .iter()
        .filter(|s| s.passed == Some(true))
        .count();
    let total = session.scenarios_total;
    let all_passed = passed == total;

    let summary_color = if all_passed { Color::Green } else { Color::Red };
    let summary_text = if all_passed {
        format!("   All {total} scenarios caught — verifier integrity confirmed")
    } else {
        let missed = total - passed;
        format!("   {missed}/{total} tampered bundles were not rejected")
    };
    lines.push(Line::from(
        Span::from(summary_text).style(
            Style::default()
                .fg(summary_color)
                .add_modifier(Modifier::BOLD),
        ),
    ));

    lines.push(Line::from(""));
    lines.push(Line::from(
        Span::from("   Press q to exit").style(Style::default().fg(Color::DarkGray)),
    ));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

fn build_step_panel_title(session: &VerificationSession) -> String {
    match session.view {
        View::Selftest => {
            if let Some(sc) = session.scenarios.get(session.selected_scenario) {
                if sc.tamper_summary.is_empty() {
                    format!(" {} ", sc.name)
                } else {
                    format!(" {} \u{2014} {} ", sc.name, sc.tamper_summary)
                }
            } else {
                " STEPS ".to_string()
            }
        }
        View::BundleVerify => " VERIFICATION STEPS ".to_string(),
    }
}

fn render_detail_lines(status: &StepStatus, detail: &Option<StepDetail>, lines: &mut Vec<Line>) {
    let indent = "      ";
    match detail {
        Some(StepDetail::HexMismatch { expected, computed }) => {
            lines.push(Line::from(
                Span::from(format!("{indent}exp: {expected}"))
                    .style(Style::default().fg(Color::Green)),
            ));
            lines.push(Line::from(
                Span::from(format!("{indent}got: {computed}"))
                    .style(Style::default().fg(Color::Red)),
            ));
        }
        None => {
            // Show the reason from Fail status in dim
            if let StepStatus::Fail(reason) = status {
                lines.push(Line::from(
                    Span::from(format!("{indent}{reason}"))
                        .style(Style::default().fg(Color::DarkGray)),
                ));
            }
        }
    }
}

// ── Footer ─────────────────────────────────────────────────────────────────

fn render_footer(session: &VerificationSession, frame: &mut Frame, area: Rect) {
    let bg = Color::Rgb(17, 17, 34);

    let mut spans: Vec<Span> = vec![
        Span::from(" ").style(Style::default().bg(bg)),
        pin_span("operator", &session.operator_pin, bg),
        Span::from("  ").style(Style::default().bg(bg)),
        pin_span("infra", &session.infra_pin, bg),
    ];

    if session.mode != Mode::Demo {
        // Right-align keyboard hints by padding
        let hint_text = " [Space] next  [c] continue  [q] quit ";
        // Push a flexible spacer -- we'll let the spans handle it
        spans.push(Span::from("  ").style(Style::default().bg(bg)));
        spans.push(
            Span::from(hint_text.to_string()).style(Style::default().fg(Color::DarkGray).bg(bg)),
        );
    }

    let line = Line::from(spans);
    let footer = Paragraph::new(line).style(Style::default().bg(bg));
    frame.render_widget(footer, area);
}

fn pin_span(label: &str, state: &PinState, bg: Color) -> Span<'static> {
    match state {
        PinState::Test => Span::from(format!("{label}: test \u{00b7}"))
            .style(Style::default().fg(Color::DarkGray).bg(bg)),
        PinState::Pinned { key_id } => Span::from(format!("{label}: {key_id} pinned \u{2713}"))
            .style(Style::default().fg(Color::Green).bg(bg)),
        PinState::Mismatch { key_id } => Span::from(format!("{label}: {key_id} MISMATCH \u{2717}"))
            .style(
                Style::default()
                    .fg(Color::Red)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            ),
        PinState::Unpinned => Span::from(format!("{label}: unpinned \u{26a0}"))
            .style(Style::default().fg(Color::Yellow).bg(bg)),
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use wallop_verifier::verify_steps::{StepName, StepResult, StepStatus, VerificationReport};

    use super::super::state::{Mode, PinState, ScenarioEntry, VerificationSession};

    fn make_test_report(statuses: Vec<StepStatus>) -> VerificationReport {
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

    fn render_to_string(session: &VerificationSession, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| super::render(session, frame))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut output = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                let cell = buffer.cell((x, y)).unwrap();
                output.push_str(cell.symbol());
            }
            output.push('\n');
        }
        output
    }

    #[test]
    fn bundle_verify_shows_pending_steps() {
        // New session with 0 revealed — all steps should show the "···" pending marker.
        let report = make_test_report(vec![StepStatus::Pass; 9]);
        let session =
            VerificationSession::new_bundle_verify(report, PinState::Unpinned, PinState::Unpinned);
        let output = render_to_string(&session, 80, 15);
        assert!(
            output.contains('\u{00b7}'),
            "Expected middle-dot pending marker in output; got:\n{output}"
        );
    }

    #[test]
    fn bundle_verify_shows_pass_after_advance() {
        // After advancing once, the revealed step should show "PASS" and the cursor "▶".
        let report = make_test_report(vec![StepStatus::Pass; 9]);
        let mut session =
            VerificationSession::new_bundle_verify(report, PinState::Unpinned, PinState::Unpinned);
        session.advance();
        let output = render_to_string(&session, 80, 15);
        assert!(
            output.contains("PASS"),
            "Expected 'PASS' status label in output after advancing; got:\n{output}"
        );
        assert!(
            output.contains('\u{25b6}'),
            "Expected cursor '▶' in output after advancing; got:\n{output}"
        );
    }

    #[test]
    fn footer_shows_pin_states() {
        // Pinned operator + Unpinned infra should show both "pinned" and "unpinned".
        let report = make_test_report(vec![StepStatus::Pass; 9]);
        let session = VerificationSession::new_bundle_verify(
            report,
            PinState::Pinned {
                key_id: "a1b2".to_string(),
            },
            PinState::Unpinned,
        );
        let output = render_to_string(&session, 80, 15);
        assert!(
            output.contains("pinned"),
            "Expected 'pinned' in footer output; got:\n{output}"
        );
        assert!(
            output.contains("unpinned"),
            "Expected 'unpinned' in footer output; got:\n{output}"
        );
    }

    #[test]
    fn selftest_footer_shows_test_pins() {
        // Selftest sessions use PinState::Test — footer should show "test ·".
        let report = make_test_report(vec![StepStatus::Pass; 9]);
        let scenarios = vec![ScenarioEntry {
            name: "Scenario A".to_string(),
            description: "A test scenario".to_string(),
            tamper_summary: String::new(),
            passed: None,
            step_statuses: vec![],
        }];
        let session = VerificationSession::new_selftest(report, scenarios);
        let output = render_to_string(&session, 80, 15);
        assert!(
            output.contains("test"),
            "Expected 'test' pin label in selftest footer; got:\n{output}"
        );
        // Middle-dot U+00B7 is used in the Test pin span
        assert!(
            output.contains('\u{00b7}'),
            "Expected middle-dot after 'test' in selftest footer; got:\n{output}"
        );
    }

    #[test]
    fn demo_mode_hides_keyboard_hints() {
        // In Demo mode the keyboard hint line ("[space]", "[c]", "[q]") must not appear.
        let report = make_test_report(vec![StepStatus::Pass; 9]);
        let mut session =
            VerificationSession::new_bundle_verify(report, PinState::Unpinned, PinState::Unpinned);
        session.mode = Mode::Demo;
        let output = render_to_string(&session, 80, 15);
        assert!(
            !output.contains("[space]"),
            "Demo mode should not show keyboard hints, but found '[space]' in output:\n{output}"
        );
    }
}
