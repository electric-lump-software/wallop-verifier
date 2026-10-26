//! `weather-attest` for grid-frequency bundles: re-fetch the 8 Elexon FREQ
//! readings and compare them with the signed `freq_value`. Informational
//! only; nothing here feeds `VerificationReport::passed()`.

use std::process::ExitCode;

use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::protocol::freq_v1;
use wallop_verifier::protocol::receipts::{
    ParsedExecutionReceipt, ParsedLockReceipt, parse_execution_receipt, parse_lock_receipt,
    validate_execution_receipt_tags_v5_freq, validate_lock_receipt_tags_v6_freq,
};

use super::{Line, Outcome, has_mismatch, http, render_line};

/// What `weather-attest` needs from a grid-frequency bundle.
#[derive(Debug)]
pub(crate) struct FreqAttestInput {
    pub draw_id: String,
    pub freq_start: String,
    pub freq_start_unix: i64,
    pub value: Option<String>,
    pub fallback_reason: Option<String>,
}

/// True when the lock receipt is a schema 6 receipt under the
/// grid-frequency tag.
pub(crate) fn is_freq_bundle(bundle: &ProofBundle) -> bool {
    matches!(
        parse_lock_receipt(&bundle.lock_receipt.payload_jcs),
        Ok(ParsedLockReceipt::V6Freq(_))
    )
}

impl FreqAttestInput {
    pub(crate) fn from_bundle(bundle: &ProofBundle) -> Result<Self, String> {
        let lock = match parse_lock_receipt(&bundle.lock_receipt.payload_jcs)
            .map_err(|e| e.to_string())?
        {
            ParsedLockReceipt::V6Freq(p) => p,
            _ => return Err(format!("not a {} bundle", freq_v1::ENTROPY_COMPOSITION)),
        };
        // First, before anything slices `freq_start` by byte index.
        let freq_start_unix = freq_v1::parse_freq_start(&lock.freq_start)?;
        validate_lock_receipt_tags_v6_freq(&lock)?;
        let exec = match parse_execution_receipt(&bundle.execution_receipt.payload_jcs)
            .map_err(|e| format!("the execution receipt is unusable: {e}"))?
        {
            ParsedExecutionReceipt::V5Freq(p) => p,
            _ => {
                return Err(format!(
                    "the execution receipt is unusable: it is not a schema \"5\" {} receipt",
                    freq_v1::ENTROPY_COMPOSITION
                ));
            }
        };
        validate_execution_receipt_tags_v5_freq(&exec)?;
        if exec.draw_id != lock.draw_id {
            return Err("the lock and execution receipts name different draws".into());
        }
        // Exactly one of the value and the reason, as the verifier requires.
        if exec.freq_value.is_some() == exec.freq_fallback_reason.is_some() {
            let shown = |set: bool| if set { "set" } else { "null" };
            return Err(format!(
                "the execution receipt is unusable: it must carry freq_value or \
                 freq_fallback_reason, not both or neither; it has freq_value {}, \
                 freq_fallback_reason {}",
                shown(exec.freq_value.is_some()),
                shown(exec.freq_fallback_reason.is_some())
            ));
        }
        Ok(Self {
            draw_id: lock.draw_id,
            freq_start: lock.freq_start,
            freq_start_unix,
            value: exec.freq_value,
            fallback_reason: exec.freq_fallback_reason,
        })
    }
}

/// Compare the signed window with Elexon's public FREQ record.
///
/// - value signed, Elexon's window equal: `MATCH`;
/// - value signed, Elexon's window valid but different: `MISMATCH`;
/// - value signed, Elexon has a row at all 8 reading times but the window
///   is invalid (a 0, out of bounds, a duplicate, malformed or stuck):
///   `MISMATCH`. Elexon does not revise readings, so this contradicts the
///   receipt; it is not missing data;
/// - value signed, a reading time with no row, or any fetch or parse
///   error: `UNAVAILABLE`;
/// - fallback signed: `PRESENT` if Elexon now holds a valid window,
///   `ABSENT` if it does not, `UNAVAILABLE` on a fetch error.
///
/// A response that can't be read, or lacks a reading time, is never a
/// mismatch.
pub(crate) fn attest(input: &FreqAttestInput, client: &http::ElexonClient) -> Vec<Line> {
    let label = format!("Elexon FREQ from {} UTC", &input.freq_start[11..19]);
    let outcome = match client.fetch(
        input.freq_start_unix,
        input.freq_start_unix + freq_v1::SPAN_SECS,
    ) {
        Err(e) => Outcome::Unavailable(e),
        Ok(rows) => match (
            freq_v1::window_from_rows(&rows, input.freq_start_unix),
            &input.value,
        ) {
            (Ok(now), Some(signed)) if &now == signed => {
                Outcome::Match(format!("8 readings {now}"))
            }
            (Ok(now), Some(signed)) => {
                Outcome::Mismatch(format!("Elexon has {now}, the receipt has {signed}"))
            }
            (Err(e), Some(signed))
                if freq_v1::rows_at_every_reading_time(&rows, input.freq_start_unix) =>
            {
                Outcome::Mismatch(format!(
                    "Elexon has all 8 reading times but no valid window ({e}), the receipt has {signed}"
                ))
            }
            (Err(e), Some(_)) => {
                Outcome::Unavailable(format!("Elexon has no valid window now: {e}"))
            }
            (Ok(now), None) => Outcome::Present(format!("Elexon now holds a valid window ({now})")),
            (Err(e), None) => Outcome::Absent(format!("Elexon has no valid window either: {e}")),
        },
    };
    vec![Line { label, outcome }]
}

/// The report `run` prints, as text.
pub(crate) fn report(input: &FreqAttestInput, lines: &[Line]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "wallop-verify {} weather-attest",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "  Draw ................ {}", input.draw_id);
    let _ = writeln!(out, "  Readings from ....... {}", input.freq_start);
    match &input.value {
        Some(v) => {
            let _ = writeln!(out, "  Grid frequency ...... {v} (mHz)");
        }
        None => {
            let _ = writeln!(
                out,
                "  Grid frequency ...... none, drand only (receipt reason: {})",
                input
                    .fallback_reason
                    .as_deref()
                    .unwrap_or("no reason given")
            );
        }
    }
    let _ = writeln!(out);
    for line in lines {
        let _ = writeln!(out, "  {}", render_line(line));
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  This checks the grid frequency in this bundle's execution receipt against"
    );
    let _ = writeln!(
        out,
        "  Elexon's public record. It does not check signatures; run"
    );
    let _ = writeln!(out, "  `wallop-verify <BUNDLE>` for that.");
    if lines
        .iter()
        .any(|l| matches!(l.outcome, Outcome::Present(_)))
    {
        let _ = writeln!(
            out,
            "  PRESENT means Elexon holds a valid window now. It may have arrived after the"
        );
        let _ = writeln!(
            out,
            "  fetch deadline, so on its own it does not show the readings were withheld."
        );
    }
    let _ = writeln!(
        out,
        "  Contains BMRS data © Elexon Limited copyright and database right {}.",
        &input.freq_start[0..4]
    );
    out
}

/// The exit status for `lines`: 1 on a mismatch (Elexon's record
/// contradicts the signed window), else 0 (no mismatch was found, which is not a
/// confirmation). Unusable input exits 2 before any lookup.
pub(crate) fn exit_status(lines: &[Line]) -> u8 {
    if has_mismatch(lines) { 1 } else { 0 }
}

pub(crate) fn run(bundle: &ProofBundle) -> ExitCode {
    let input = match FreqAttestInput::from_bundle(bundle) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let lines = attest(&input, &http::ElexonClient::new(http::ELEXON_BASE_URL));
    print!("{}", report(&input, &lines));
    ExitCode::from(exit_status(&lines))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use wallop_verifier::_test_support::{FreqParams, build_freq_bundle, resign_exec};

    pub(crate) const REAL: &str = "50012;50018;50012;49983;49980;49953;49912;49883";
    pub(crate) const REAL_TEXT: [&str; 8] = [
        "50.012", "50.018", "50.012", "49.983", "49.98", "49.953", "49.912", "49.883",
    ];

    /// The frequency fixture's window start, 2026-10-14T19:54:00Z.
    const START: i64 = 1_792_007_640;

    /// Elexon's stamp for `secs`: whole seconds, `Z`.
    fn stamp(secs: i64) -> String {
        let canonical = freq_v1::format_freq_start(secs);
        format!("{}Z", canonical.strip_suffix(".000000Z").unwrap())
    }

    /// An Elexon FREQ body holding `texts` at the reading times from
    /// `start`, 15 s apart, newest first as Elexon sends them.
    pub(crate) fn body_at(start: i64, texts: &[&str]) -> String {
        let rows: Vec<String> = texts
            .iter()
            .enumerate()
            .rev()
            .map(|(i, f)| {
                let t = stamp(start + freq_v1::SPACING_SECS * i as i64);
                format!(r#"{{"dataset":"FREQ","measurementTime":"{t}","frequency":{f}}}"#)
            })
            .collect();
        format!(r#"{{"data":[{}]}}"#, rows.join(","))
    }

    fn body(texts: &[&str]) -> String {
        body_at(START, texts)
    }

    /// Serve `body` for exactly the window request from `start`.
    pub(crate) fn serve_at(
        server: &mut mockito::Server,
        start: i64,
        status: usize,
        body: &str,
    ) -> mockito::Mock {
        server
            .mock("GET", "/")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("measurementDateTimeFrom".into(), stamp(start)),
                mockito::Matcher::UrlEncoded(
                    "measurementDateTimeTo".into(),
                    stamp(start + freq_v1::SPAN_SECS),
                ),
            ]))
            .with_status(status)
            .with_body(body)
            .create()
    }

    fn input(value: Option<&str>) -> FreqAttestInput {
        let p = if value.is_some() {
            FreqParams::value()
        } else {
            FreqParams::fallback()
        };
        let (json, _, _) = build_freq_bundle(&p);
        FreqAttestInput::from_bundle(&ProofBundle::from_json(&json).unwrap()).unwrap()
    }

    fn serve(server: &mut mockito::Server, status: usize, body: &str) -> mockito::Mock {
        serve_at(server, START, status, body)
    }

    fn outcome(value: Option<&str>, status: usize, body: &str) -> Outcome {
        let mut server = mockito::Server::new();
        let mock = serve(&mut server, status, body);
        let lines = attest(&input(value), &http::ElexonClient::new(&server.url()));
        mock.assert();
        assert_eq!(lines.len(), 1);
        lines.into_iter().next().unwrap().outcome
    }

    #[test]
    fn the_helpers_serve_the_fixture_window() {
        assert_eq!(stamp(START), "2026-10-14T19:54:00Z");
        assert_eq!(stamp(START + freq_v1::SPAN_SECS), "2026-10-14T19:55:45Z");
        let b = body(&REAL_TEXT);
        assert!(b.starts_with(r#"{"data":[{"dataset":"FREQ","measurementTime":"2026-10-14T19:55:45Z","frequency":49.883}"#), "{b}");
    }

    #[test]
    fn from_bundle_reads_a_frequency_bundle() {
        let i = input(Some(REAL));
        assert_eq!(i.freq_start, "2026-10-14T19:54:00.000000Z");
        assert_eq!(i.freq_start_unix, 1_792_007_640);
        assert_eq!(i.value.as_deref(), Some(REAL));
        assert_eq!(i.fallback_reason, None);
        let f = input(None);
        assert_eq!(f.value, None);
        assert_eq!(
            f.fallback_reason.as_deref(),
            Some(freq_v1::FALLBACK_NO_FREQUENCY)
        );
    }

    #[test]
    fn from_bundle_refuses_other_bundles_and_invalid_frequency_receipts() {
        let (landobs, _, _) = wallop_verifier::_test_support::build_v6_bundle(
            &wallop_verifier::_test_support::V6Params::weather(),
        );
        let b = ProofBundle::from_json(&landobs).unwrap();
        assert!(!is_freq_bundle(&b));
        assert!(FreqAttestInput::from_bundle(&b).is_err());

        let (json, _, _) = build_freq_bundle(&FreqParams::value());
        assert!(is_freq_bundle(&ProofBundle::from_json(&json).unwrap()));
        // A bad signed value, a weather field, or another draw's exec is refused.
        for edit in [
            |e: &mut serde_json::Value| e["freq_value"] = serde_json::json!("1;2"),
            |e: &mut serde_json::Value| e["weather_value"] = serde_json::json!("141;1025;85;2432"),
            |e: &mut serde_json::Value| {
                e["draw_id"] = serde_json::json!("33333333-3333-3333-3333-333333333333")
            },
            |e: &mut serde_json::Value| {
                e["entropy_composition"] =
                    serde_json::json!(wallop_verifier::protocol::landobs_v1::ENTROPY_COMPOSITION)
            },
        ] {
            let v = resign_exec(&json, edit);
            let b = ProofBundle::from_json(&v.to_string()).unwrap();
            assert!(FreqAttestInput::from_bundle(&b).is_err());
        }
        // A freq_start off the grid.
        let p = FreqParams {
            freq_start: "2026-10-14T19:54:01.000000Z".into(),
            ..FreqParams::value()
        };
        let (json, _, _) = build_freq_bundle(&p);
        assert!(FreqAttestInput::from_bundle(&ProofBundle::from_json(&json).unwrap()).is_err());
    }

    #[test]
    fn from_bundle_refuses_a_value_with_a_reason_or_neither() {
        let both = FreqParams {
            freq_fallback_reason: Some(freq_v1::FALLBACK_NO_FREQUENCY.into()),
            ..FreqParams::value()
        };
        let neither = FreqParams {
            freq_fallback_reason: None,
            ..FreqParams::fallback()
        };
        for (p, shown) in [
            (both, "freq_value set, freq_fallback_reason set"),
            (neither, "freq_value null, freq_fallback_reason null"),
        ] {
            let (json, _, _) = build_freq_bundle(&p);
            let b = ProofBundle::from_json(&json).unwrap();
            let err = FreqAttestInput::from_bundle(&b).unwrap_err();
            assert!(err.contains(shown), "{err}");
            assert_eq!(run(&b), ExitCode::from(2));
        }
    }

    #[test]
    fn signed_value_matches_elexon() {
        assert_eq!(
            outcome(Some(REAL), 200, &body(&REAL_TEXT)),
            Outcome::Match(format!("8 readings {REAL}"))
        );
    }

    #[test]
    fn a_different_window_is_a_mismatch() {
        let mut other = REAL_TEXT;
        other[7] = "49.884";
        let o = outcome(Some(REAL), 200, &body(&other));
        assert!(
            matches!(&o, Outcome::Mismatch(d) if d.contains("49884")),
            "{o:?}"
        );
        let lines = vec![Line {
            label: "x".into(),
            outcome: o,
        }];
        assert!(has_mismatch(&lines));
    }

    #[test]
    fn an_invalid_window_with_all_8_times_is_a_mismatch() {
        let mut zero = REAL_TEXT;
        zero[2] = "0";
        let mut high = REAL_TEXT;
        high[4] = "53.000";
        let mut low = REAL_TEXT;
        low[4] = "46.999";
        let mut quoted = REAL_TEXT;
        quoted[2] = "\"50.012\"";
        let stuck = ["50.001"; 8];
        let no_reading = body(&REAL_TEXT).replace(r#""frequency":49.983"#, r#""x":1"#);
        let duplicate = body(&REAL_TEXT).replace(
            r#"{"data":["#,
            r#"{"data":[{"measurementTime":"2026-10-14T19:54:45Z","frequency":49.983},"#,
        );
        for b in [
            body(&zero),
            body(&high),
            body(&low),
            body(&quoted),
            body(&stuck),
            no_reading,
            duplicate,
        ] {
            let o = outcome(Some(REAL), 200, &b);
            assert!(
                matches!(&o, Outcome::Mismatch(d) if d.contains("all 8") && d.contains(REAL)),
                "{b}: {o:?}"
            );
            let lines = vec![Line {
                label: "x".into(),
                outcome: o,
            }];
            assert_eq!(exit_status(&lines), 1);
        }
    }

    #[test]
    fn a_missing_reading_time_is_unavailable_never_a_match_or_mismatch() {
        // A row at another time does not stand in for the missing one.
        let off_window = body(&REAL_TEXT[..7]).replace(
            r#"{"data":["#,
            r#"{"data":[{"measurementTime":"2026-10-14T19:56:00Z","frequency":50.5},"#,
        );
        let mut zero = REAL_TEXT;
        zero[2] = "0";
        for b in [
            body(&REAL_TEXT[..7]),
            body(&zero[..7]),
            off_window,
            r#"{"data":[]}"#.to_string(),
        ] {
            let o = outcome(Some(REAL), 200, &b);
            assert!(matches!(o, Outcome::Unavailable(_)), "{b}: {o:?}");
        }
    }

    #[test]
    fn a_body_with_a_repeated_key_is_unavailable() {
        let b = body(&REAL_TEXT).replacen(
            r#""frequency":49.883"#,
            r#""frequency":50.999,"frequency":49.883"#,
            1,
        );
        for value in [Some(REAL), None] {
            let o = outcome(value, 200, &b);
            assert!(
                matches!(&o, Outcome::Unavailable(d) if d.contains("duplicate key")),
                "{o:?}"
            );
        }
    }

    #[test]
    fn a_fetch_error_or_unreadable_body_is_unavailable_never_a_mismatch() {
        for (status, b) in [
            (500, body(&REAL_TEXT)),
            (200, "<html>maintenance</html>".to_string()),
            (200, r#"{"data":{}}"#.to_string()),
            (302, String::new()),
        ] {
            for value in [Some(REAL), None] {
                let o = outcome(value, status, &b);
                assert!(matches!(o, Outcome::Unavailable(_)), "{status} {b}: {o:?}");
            }
        }
    }

    #[test]
    fn non_objects_and_other_rows_in_the_body_are_ignored() {
        let b = body(&REAL_TEXT).replace(
            r#"{"data":["#,
            r#"{"data":[1,"x",null,{"measurementTime":"2026-10-14T19:53:45Z","frequency":50.5},"#,
        );
        assert_eq!(
            outcome(Some(REAL), 200, &b),
            Outcome::Match(format!("8 readings {REAL}"))
        );
    }

    #[test]
    fn only_a_mismatch_exits_1() {
        let line = |outcome| Line {
            label: "x".into(),
            outcome,
        };
        assert_eq!(exit_status(&[line(Outcome::Mismatch("m".into()))]), 1);
        for o in [
            Outcome::Match("m".into()),
            Outcome::Unavailable("u".into()),
            Outcome::Present("p".into()),
            Outcome::Absent("a".into()),
        ] {
            assert_eq!(exit_status(&[line(o)]), 0);
        }
    }

    #[test]
    fn on_a_fallback_reports_present_or_absent() {
        assert!(matches!(
            outcome(None, 200, &body(&REAL_TEXT)),
            Outcome::Present(d) if d.contains(REAL)
        ));
        let mut zero = REAL_TEXT;
        zero[2] = "0";
        assert!(matches!(
            outcome(None, 200, &body(&zero)),
            Outcome::Absent(_)
        ));
    }

    #[test]
    fn the_report_names_the_window_and_carries_the_attribution() {
        let i = input(Some(REAL));
        let lines = vec![Line {
            label: "Elexon FREQ from 19:54:00 UTC".into(),
            outcome: Outcome::Match(format!("8 readings {REAL}")),
        }];
        let r = report(&i, &lines);
        assert!(
            r.contains("Readings from ....... 2026-10-14T19:54:00.000000Z"),
            "{r}"
        );
        assert!(
            r.contains(&format!("Grid frequency ...... {REAL} (mHz)")),
            "{r}"
        );
        assert!(r.contains("MATCH (8 readings"), "{r}");
        assert!(
            r.contains("Contains BMRS data © Elexon Limited copyright and database right 2026.")
        );
        assert!(!r.contains("PRESENT means"));
        let f = input(None);
        let lines = vec![Line {
            label: "x".into(),
            outcome: Outcome::Present("y".into()),
        }];
        let r = report(&f, &lines);
        assert!(
            r.contains("none, drand only (receipt reason: no_frequency_by_deadline)"),
            "{r}"
        );
        assert!(r.contains("PRESENT means"));
    }
}
