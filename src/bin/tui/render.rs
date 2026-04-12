use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use wallop_verifier::verify_steps::{StepDetail, StepStatus};

use super::state::{Mode, PinState, VerificationSession, View};

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
            let marker = if i == session.selected_scenario {
                "▶ "
            } else {
                "  "
            };
            let (prefix, color) = match sc.passed {
                Some(true) => ("✓ ", Color::Green),
                Some(false) => ("✗ ", Color::Red),
                None => ("  ", Color::DarkGray),
            };
            let row_color = if i == session.selected_scenario {
                Color::Yellow
            } else {
                color
            };
            let text = format!("{marker}{prefix}{}", sc.name);
            ListItem::new(Line::from(Span::from(text).style(Style::default().fg(row_color))))
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

            // Calculate dots to fill between name and status
            let available = inner.width as usize;
            let gutter_len = 3;
            let name_len = name_str.len();
            let status_len = status_label.len();
            let min_dots = 2;
            let dots_count = available
                .saturating_sub(gutter_len + name_len + 1 + status_len)
                .max(min_dots);
            let dots: String = " ".to_string() + &".".repeat(dots_count) + " ";

            let bg = if is_selected {
                Color::Rgb(30, 30, 50)
            } else {
                Color::Reset
            };

            let line = Line::from(vec![
                Span::from(gutter.to_string())
                    .style(Style::default().fg(Color::White).bg(bg)),
                Span::from(name_str).style(Style::default().fg(Color::White).bg(bg)),
                Span::from(dots).style(Style::default().fg(Color::DarkGray).bg(bg)),
                Span::from(status_label.to_string()).style(
                    Style::default().fg(status_color).bg(bg),
                ),
            ]);
            lines.push(line);

            // Inline detail expansion
            if is_selected && session.detail_expanded {
                render_detail_lines(&step.status, &step.detail, &mut lines);
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
            Color::Green
        } else {
            Color::Red
        };
        lines.push(Line::from(
            Span::from(format!("   {summary}")).style(
                Style::default()
                    .fg(color)
                    .add_modifier(Modifier::BOLD),
            ),
        ));
    }

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

fn render_detail_lines(
    status: &StepStatus,
    detail: &Option<StepDetail>,
    lines: &mut Vec<Line>,
) {
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
            Span::from(hint_text.to_string())
                .style(Style::default().fg(Color::DarkGray).bg(bg)),
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
        PinState::Mismatch { key_id } => {
            Span::from(format!("{label}: {key_id} MISMATCH \u{2717}")).style(
                Style::default()
                    .fg(Color::Red)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            )
        }
        PinState::Unpinned => Span::from(format!("{label}: unpinned \u{26a0}"))
            .style(Style::default().fg(Color::Yellow).bg(bg)),
    }
}
