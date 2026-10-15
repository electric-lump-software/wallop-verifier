//! `wallop-verify weather-attest`: compare a bundle's signed weather
//! observation with public records. Informational only: nothing here
//! feeds `VerificationReport::passed()`.

use std::io::Read;
use std::process::ExitCode;

use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::protocol::landobs_v1::{self, PRIMARY_STATION, STATIONS};
use wallop_verifier::protocol::receipts::{
    ParsedExecutionReceipt, ParsedLockReceipt, parse_execution_receipt, parse_lock_receipt,
    validate_execution_receipt_tags_v5, validate_lock_receipt_tags_v6,
};

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

/// Land Observations keeps roughly 48 hours of rows. Look no further back
/// than 46, so an hour on the edge of rolling off is reported unavailable
/// rather than missing.
const LANDOBS_RETENTION_SECS: i64 = 46 * 3600;

/// One labelled result in the report.
#[derive(Debug)]
pub(crate) struct Line {
    pub label: String,
    pub outcome: Outcome,
}

/// What `weather-attest` needs from a schema 6 / 5 bundle.
#[derive(Debug)]
pub(crate) struct AttestInput {
    pub draw_id: String,
    pub weather_time: String,
    pub weather_time_unix: i64,
    pub station: String,
    pub value: Option<String>,
    pub fallback_reason: Option<String>,
}

impl AttestInput {
    pub(crate) fn from_bundle(bundle: &ProofBundle) -> Result<Self, String> {
        let wrong_schema = || {
            format!(
                "weather-attest needs a lock receipt with schema_version \"6\" and an execution \
                 receipt with schema_version \"5\" ({})",
                landobs_v1::ENTROPY_COMPOSITION
            )
        };
        let lock = match parse_lock_receipt(&bundle.lock_receipt.payload_jcs)
            .map_err(|e| e.to_string())?
        {
            ParsedLockReceipt::V6(p) => p,
            _ => return Err(wrong_schema()),
        };
        // First, before anything slices `weather_time` by byte index.
        let weather_time_unix = landobs_v1::parse_weather_time(&lock.weather_time)?;
        validate_lock_receipt_tags_v6(&lock)?;
        let exec = match parse_execution_receipt(&bundle.execution_receipt.payload_jcs)
            .map_err(|e| e.to_string())?
        {
            ParsedExecutionReceipt::V5(p) => p,
            _ => return Err(wrong_schema()),
        };
        validate_execution_receipt_tags_v5(&exec)?;
        let station = exec
            .weather_station
            .ok_or("execution receipt has no weather_station")?;
        Ok(Self {
            draw_id: lock.draw_id,
            weather_time: lock.weather_time,
            weather_time_unix,
            station,
            value: exec.weather_value,
            fallback_reason: exec.weather_fallback_reason,
        })
    }
}

pub(crate) fn station_name(station: &str) -> &'static str {
    match station {
        "wmo-03749" => "Middle Wallop",
        "wmo-03462" => "Wittering",
        _ => "unknown station",
    }
}

/// Compare the signed observation with Land Observations (first), then
/// the WMO SYNOP via Ogimet. When the backup station was used, also report
/// whether the primary station's records hold that hour; on a fallback,
/// report that for both stations.
///
/// Takes the run's one `OgimetClient` so every SYNOP request shares its
/// pacing. `input.weather_time` has passed `parse_weather_time`.
pub(crate) fn attest(
    input: &AttestInput,
    landobs: Option<&http::LandObsClient>,
    ogimet: &http::OgimetClient,
    now_unix: i64,
) -> Vec<Line> {
    let rows_for = |station: &str| -> Result<Vec<landobs::Row>, String> {
        let client = landobs.ok_or_else(|| {
            "no Met Office key: pass --metoffice-key or set WALLOP_METOFFICE_KEY".to_string()
        })?;
        if now_unix - input.weather_time_unix > LANDOBS_RETENTION_SECS {
            return Err(
                "Land Observations only keeps about 48 hours, and this hour is older".into(),
            );
        }
        let geohash = landobs::geohash_for(station)
            .ok_or_else(|| format!("no Land Observations location for {station}"))?;
        client.fetch(geohash)
    };
    let synop_for = |station: &str| -> Result<Option<String>, String> {
        ogimet.fetch(
            synop::block_for(station)?,
            &synop::ogimet_hour(&input.weather_time),
        )
    };
    let presence_lines = |station: &str, lines: &mut Vec<Line>| {
        lines.push(Line {
            label: format!("Land Observations, {station}"),
            outcome: match rows_for(station) {
                Ok(rows) => landobs::presence(&rows, &input.weather_time),
                Err(e) => Outcome::Unavailable(e),
            },
        });
        lines.push(Line {
            label: format!("SYNOP via Ogimet, {station}"),
            outcome: match synop_for(station) {
                Ok(body) => synop::presence(body.as_deref(), station, &input.weather_time),
                Err(e) => Outcome::Unavailable(e),
            },
        });
    };

    let mut lines = Vec::new();
    match &input.value {
        Some(value) => {
            lines.push(Line {
                label: format!("Land Observations, {}", input.station),
                outcome: match rows_for(&input.station) {
                    Ok(rows) => landobs::check(&rows, &input.weather_time, value),
                    Err(e) => Outcome::Unavailable(e),
                },
            });
            lines.push(Line {
                label: format!("SYNOP via Ogimet, {}", input.station),
                outcome: match synop_for(&input.station) {
                    Ok(body) => {
                        synop::check(body.as_deref(), &input.station, &input.weather_time, value)
                    }
                    Err(e) => Outcome::Unavailable(e),
                },
            });
            if input.station != PRIMARY_STATION {
                presence_lines(PRIMARY_STATION, &mut lines);
            }
        }
        None => {
            for station in STATIONS {
                presence_lines(station, &mut lines);
            }
        }
    }
    lines
}

pub(crate) fn render_line(line: &Line) -> String {
    let (word, detail) = match &line.outcome {
        Outcome::Match(d) => ("MATCH", d),
        Outcome::Mismatch(d) => ("MISMATCH", d),
        Outcome::Unavailable(d) => ("UNAVAILABLE", d),
        Outcome::Present(d) => ("PRESENT", d),
        Outcome::Absent(d) => ("ABSENT", d),
    };
    let dots = ".".repeat(40usize.saturating_sub(line.label.len()));
    format!("{} {dots} {word} ({detail})", line.label)
}

pub(crate) fn has_mismatch(lines: &[Line]) -> bool {
    lines
        .iter()
        .any(|l| matches!(l.outcome, Outcome::Mismatch(_)))
}

fn read_input(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("error reading stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("error reading {path}: {e}"))
    }
}

/// The `weather-attest` entry point. Builds the run's only HTTP clients.
/// Exit codes: 0 no MISMATCH, 1 at least one MISMATCH, 2 unusable input.
pub(crate) fn run(path: &str, metoffice_key: Option<&str>) -> ExitCode {
    let input = match read_input(path)
        .and_then(|json| ProofBundle::from_json(&json).map_err(|e| e.to_string()))
        .and_then(|bundle| AttestInput::from_bundle(&bundle))
    {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let landobs = metoffice_key
        .filter(|k| !k.is_empty())
        .map(|k| http::LandObsClient::new(http::LANDOBS_BASE_URL, k));
    let ogimet = http::OgimetClient::new(http::OGIMET_BASE_URL);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let lines = attest(&input, landobs.as_ref(), &ogimet, now_unix);
    print!("{}", report(&input, &lines));
    if has_mismatch(&lines) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// The report `run` prints, as text.
fn report(input: &AttestInput, lines: &[Line]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "wallop-verify {} weather-attest",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "  Draw ................ {}", input.draw_id);
    let _ = writeln!(out, "  Observation hour .... {}", input.weather_time);
    match &input.value {
        Some(value) => {
            let _ = writeln!(
                out,
                "  Station used ........ {} ({})",
                input.station,
                station_name(&input.station)
            );
            let _ = writeln!(out, "  Weather value ....... {value}");
        }
        None => {
            let _ = writeln!(
                out,
                "  Station used ........ none, drand only (receipt reason: {})",
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
        "  These lines check the weather details in this bundle's execution receipt"
    );
    let _ = writeln!(
        out,
        "  against public records. This command does not check signatures; run"
    );
    let _ = writeln!(out, "  `wallop-verify <BUNDLE>` for that.");
    if lines
        .iter()
        .any(|l| matches!(l.outcome, Outcome::Present(_)))
    {
        let _ = writeln!(
            out,
            "  PRESENT means the record holds that hour now. It may have arrived after the"
        );
        let _ = writeln!(
            out,
            "  fetch deadline, so on its own it does not show an observation was withheld."
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;
    use wallop_verifier::_test_support::{
        V6Params, build_v6_bundle, build_valid_v5_bundle, v6_entries,
    };

    const WT: &str = "2026-10-01T19:00:00.000000Z";
    const WT_UNIX: i64 = 1_790_881_200;
    const ROW_03749: &str = r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":18.38,"mslp":1021,"humidity":51,"visibility":41140.0}]"#;
    const SYNOP_03749: &str =
        "03749,2026,10,01,19,00,AAXX 01194 03749 25481 82109 10184 20156 30096 40210 52001==\n";

    fn input(station: &str, value: Option<&str>) -> AttestInput {
        AttestInput {
            draw_id: "22222222-2222-2222-2222-222222222222".into(),
            weather_time: WT.into(),
            weather_time_unix: WT_UNIX,
            station: station.into(),
            value: value.map(str::to_owned),
            fallback_reason: value
                .is_none()
                .then(|| "no_observation_by_deadline".to_string()),
        }
    }

    fn ogimet(server: &mockito::Server) -> http::OgimetClient {
        http::OgimetClient::with_pacing(&server.url(), Duration::ZERO, Box::new(|_| {}))
    }

    fn mock_synop(server: &mut mockito::Server, block: &str, body: &str) -> mockito::Mock {
        server
            .mock("GET", "/cgi-bin/getsynop")
            .match_query(mockito::Matcher::UrlEncoded("block".into(), block.into()))
            .with_body(body)
            .create()
    }

    #[test]
    fn from_bundle_reads_a_v6_bundle() {
        let (json, _, _) = build_v6_bundle(&V6Params::backup());
        let i = AttestInput::from_bundle(&ProofBundle::from_json(&json).unwrap()).unwrap();
        assert_eq!(i.station, "wmo-03462");
        assert_eq!(i.value.as_deref(), Some("184;1021;51;4114"));
    }

    #[test]
    fn from_bundle_refuses_older_schemas() {
        let (json, _, _) = build_valid_v5_bundle(&v6_entries(), Some("1013"), 2);
        let err = AttestInput::from_bundle(&ProofBundle::from_json(&json).unwrap()).unwrap_err();
        assert!(err.contains("schema_version \"6\""), "{err}");
    }

    #[test]
    fn from_bundle_refuses_a_malformed_weather_time_without_panicking() {
        for bad in [
            "2026",
            "2026-10-01T19:00:00Z",
            "2026-10-01T19:30:00.000000Z",
            "ééééééééééééééééé",
        ] {
            let (json, _, _) = build_v6_bundle(&V6Params {
                weather_time: bad.into(),
                ..V6Params::weather()
            });
            let bundle = ProofBundle::from_json(&json).unwrap();
            assert!(
                AttestInput::from_bundle(&bundle).is_err(),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn primary_station_matches_both_sources() {
        let mut server = mockito::Server::new();
        server.mock("GET", "/gcnfur").with_body(ROW_03749).create();
        mock_synop(&mut server, "03749", SYNOP_03749);
        let landobs = http::LandObsClient::new(&server.url(), "k");
        let lines = attest(
            &input("wmo-03749", Some("184;1021;51;4114")),
            Some(&landobs),
            &ogimet(&server),
            WT_UNIX + 3600,
        );
        assert_eq!(lines.len(), 2);
        assert!(
            lines.iter().all(|l| matches!(l.outcome, Outcome::Match(_))),
            "{lines:?}"
        );
        assert!(!has_mismatch(&lines));
    }

    #[test]
    fn a_different_value_is_a_mismatch() {
        let mut server = mockito::Server::new();
        server.mock("GET", "/gcnfur").with_body(ROW_03749).create();
        mock_synop(&mut server, "03749", SYNOP_03749);
        let landobs = http::LandObsClient::new(&server.url(), "k");
        let lines = attest(
            &input("wmo-03749", Some("185;1021;51;4114")),
            Some(&landobs),
            &ogimet(&server),
            WT_UNIX + 3600,
        );
        assert!(has_mismatch(&lines));
    }

    #[test]
    fn land_observations_is_unavailable_without_a_key_or_after_48_hours() {
        let mut server = mockito::Server::new();
        mock_synop(&mut server, "03749", SYNOP_03749);
        let no_key = attest(
            &input("wmo-03749", Some("184;1021;51;4114")),
            None,
            &ogimet(&server),
            WT_UNIX + 3600,
        );
        assert!(
            matches!(&no_key[0].outcome, Outcome::Unavailable(r) if r == "no Met Office key: pass --metoffice-key or set WALLOP_METOFFICE_KEY")
        );
        let landobs = http::LandObsClient::new(&server.url(), "k");
        let old = attest(
            &input("wmo-03749", Some("184;1021;51;4114")),
            Some(&landobs),
            &ogimet(&server),
            WT_UNIX + 46 * 3600 + 1,
        );
        assert!(
            matches!(&old[0].outcome, Outcome::Unavailable(r) if r == "Land Observations only keeps about 48 hours, and this hour is older")
        );
        assert!(matches!(old[1].outcome, Outcome::Match(_)));
        server.mock("GET", "/gcnfur").with_body(ROW_03749).create();
        let edge = attest(
            &input("wmo-03749", Some("184;1021;51;4114")),
            Some(&landobs),
            &ogimet(&server),
            WT_UNIX + 46 * 3600,
        );
        assert!(matches!(edge[0].outcome, Outcome::Match(_)), "{edge:?}");
    }

    #[test]
    fn backup_station_reports_the_primary() {
        let mut server = mockito::Server::new();
        server.mock("GET", "/gcrem9").with_body(ROW_03749).create();
        server.mock("GET", "/gcnfur").with_body(ROW_03749).create();
        mock_synop(&mut server, "03462", &SYNOP_03749.replace("03749", "03462"));
        mock_synop(&mut server, "03749", SYNOP_03749);
        let landobs = http::LandObsClient::new(&server.url(), "k");
        let lines = attest(
            &input("wmo-03462", Some("184;1021;51;4114")),
            Some(&landobs),
            &ogimet(&server),
            WT_UNIX + 3600,
        );
        assert_eq!(lines.len(), 4);
        assert!(
            lines[2].label.contains("wmo-03749") && matches!(lines[2].outcome, Outcome::Present(_)),
            "{lines:?}"
        );
        assert!(matches!(lines[3].outcome, Outcome::Present(_)));
    }

    #[test]
    fn two_stations_share_one_ogimet_client_and_its_pacing() {
        let mut server = mockito::Server::new();
        let backup = mock_synop(&mut server, "03462", &SYNOP_03749.replace("03749", "03462"));
        let primary = mock_synop(&mut server, "03749", SYNOP_03749);
        let slept = Rc::new(RefCell::new(Vec::new()));
        let record = Rc::clone(&slept);
        let client = http::OgimetClient::with_pacing(
            &server.url(),
            Duration::from_secs(3600),
            Box::new(move |d| record.borrow_mut().push(d)),
        );
        let lines = attest(
            &input("wmo-03462", Some("184;1021;51;4114")),
            None,
            &client,
            WT_UNIX + 3600,
        );
        backup.assert();
        primary.assert();
        assert_eq!(lines.len(), 4, "{lines:?}");
        let slept = slept.borrow();
        assert_eq!(
            slept.len(),
            1,
            "one gap between the two SYNOP requests: {slept:?}"
        );
        assert!(slept[0] > Duration::from_secs(3500), "{slept:?}");
    }

    #[test]
    fn fallback_reports_both_stations() {
        let mut server = mockito::Server::new();
        let earlier = ROW_03749.replace("19:00:00Z", "18:00:00Z");
        server.mock("GET", "/gcnfur").with_body(&earlier).create();
        server.mock("GET", "/gcrem9").with_body(&earlier).create();
        mock_synop(&mut server, "03749", "");
        mock_synop(&mut server, "03462", "");
        let landobs = http::LandObsClient::new(&server.url(), "k");
        let lines = attest(
            &input("wmo-03749", None),
            Some(&landobs),
            &ogimet(&server),
            WT_UNIX + 3600,
        );
        assert_eq!(lines.len(), 4);
        assert!(
            lines
                .iter()
                .all(|l| matches!(l.outcome, Outcome::Absent(_))),
            "{lines:?}"
        );
    }

    #[test]
    fn ogimet_error_page_is_unavailable_not_absent() {
        let mut server = mockito::Server::new();
        mock_synop(
            &mut server,
            "03749",
            "Sorry, too many requests. Try later.\n",
        );
        mock_synop(
            &mut server,
            "03462",
            "Sorry, too many requests. Try later.\n",
        );
        let lines = attest(
            &input("wmo-03749", None),
            None,
            &ogimet(&server),
            WT_UNIX + 3600,
        );
        let synop: Vec<_> = lines.iter().filter(|l| l.label.contains("SYNOP")).collect();
        assert_eq!(synop.len(), 2);
        assert!(
            synop
                .iter()
                .all(|l| matches!(l.outcome, Outcome::Unavailable(_))),
            "{lines:?}"
        );
    }

    #[test]
    fn render_line_aligns_and_names_the_outcome() {
        let line = Line {
            label: "SYNOP via Ogimet, wmo-03749".into(),
            outcome: Outcome::Match("t 184, mslp 1021".into()),
        };
        let s = render_line(&line);
        assert!(s.starts_with("SYNOP via Ogimet, wmo-03749 ."), "{s}");
        assert!(s.ends_with(" MATCH (t 184, mslp 1021)"), "{s}");
    }
    #[test]
    fn fallback_with_records_that_no_longer_reach_back_is_unavailable() {
        let mut server = mockito::Server::new();
        server.mock("GET", "/gcnfur").with_body("[]").create();
        server.mock("GET", "/gcrem9").with_body("[]").create();
        mock_synop(&mut server, "03749", "");
        mock_synop(&mut server, "03462", "");
        let landobs = http::LandObsClient::new(&server.url(), "k");
        let lines = attest(
            &input("wmo-03749", None),
            Some(&landobs),
            &ogimet(&server),
            WT_UNIX + 3600,
        );
        let land: Vec<_> = lines
            .iter()
            .filter(|l| l.label.starts_with("Land"))
            .collect();
        assert_eq!(land.len(), 2);
        assert!(
            land.iter()
                .all(|l| matches!(l.outcome, Outcome::Unavailable(_))),
            "{lines:?}"
        );
    }

    #[test]
    fn report_names_the_receipt_and_never_claims_a_signature_check() {
        let lines = vec![Line {
            label: "SYNOP via Ogimet, wmo-03749".into(),
            outcome: Outcome::Absent("no SYNOP for this hour".into()),
        }];
        let fallback = report(&input("wmo-03749", None), &lines);
        assert!(
            fallback.contains("Station used ........ none, drand only (receipt reason: no_observation_by_deadline)"),
            "{fallback}"
        );
        assert!(!fallback.contains("signed weather value"), "{fallback}");
        let footer = "These lines check the weather details in this bundle's execution receipt against public records. This command does not check signatures; run `wallop-verify <BUNDLE>` for that.";
        let flat = fallback.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains(footer), "{fallback}");
        let used = report(&input("wmo-03749", Some("184;1021;51;4114")), &lines);
        assert!(
            used.contains("Station used ........ wmo-03749 (Middle Wallop)"),
            "{used}"
        );
        assert!(
            used.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains(footer),
            "{used}"
        );
    }
}
