//! `wallop-verify weather-attest`: compare a bundle's signed weather
//! observation with public records. Informational only: nothing here
//! feeds `VerificationReport::passed()`.

use std::io::Read;
use std::process::ExitCode;

use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::protocol::freq_v1;
use wallop_verifier::protocol::landobs_v1::{self, ExecState, PRIMARY_STATION};
use wallop_verifier::protocol::receipts::{
    ParsedExecutionReceipt, ParsedLockReceipt, parse_execution_receipt, parse_lock_receipt,
    validate_execution_receipt_tags_v5, validate_lock_receipt_tags_v6,
};

pub(crate) mod freq;
pub(crate) mod http;
pub(crate) mod landobs;
pub(crate) mod synop;

/// Sent with every request this subcommand makes.
pub(crate) const USER_AGENT: &str = concat!(
    "wallop-verify/",
    env!("CARGO_PKG_VERSION"),
    " weather-attest"
);

/// What a PRESENT reading on a fallback means: the record holds the hour
/// now, but not when it was published.
pub(crate) const PRESENT_CAVEAT: &str =
    "publication time unknown; a late reading can't be told from a withheld one";

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

/// Which source fed the seed, by the signed execution receipt's state
/// under the three-state table (`landobs_v1::exec_state`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SeedSource {
    /// (a) Middle Wallop's reading: the signed `weather_value`.
    Weather(String),
    /// (b) The round's grid-frequency window.
    Freq,
    /// (c) drand alone.
    DrandOnly,
}

/// What `weather-attest` needs from a schema 6 / 5 bundle.
#[derive(Debug)]
pub(crate) struct AttestInput {
    pub draw_id: String,
    pub weather_time: String,
    pub weather_time_unix: i64,
    pub station: String,
    pub source: SeedSource,
    pub fallback_reason: Option<String>,
    pub freq_start: String,
    pub freq_start_unix: i64,
    pub freq_value: Option<String>,
    pub freq_fallback_reason: Option<String>,
}

impl AttestInput {
    pub(crate) fn from_bundle(bundle: &ProofBundle) -> Result<Self, String> {
        let wrong_schema = || {
            format!(
                "weather-attest needs a lock receipt with schema_version \"6\" and an execution \
                 receipt with schema_version \"5\" ({} or {})",
                landobs_v1::ENTROPY_COMPOSITION,
                wallop_verifier::protocol::freq_v1::ENTROPY_COMPOSITION
            )
        };
        let lock = match parse_lock_receipt(&bundle.lock_receipt.payload_jcs)
            .map_err(|e| e.to_string())?
        {
            ParsedLockReceipt::V6(p) => p,
            _ => return Err(wrong_schema()),
        };
        // First, before anything slices `weather_time` or `freq_start` by
        // byte index.
        let weather_time_unix = landobs_v1::parse_weather_time(&lock.weather_time)?;
        let freq_start_unix = freq_v1::parse_freq_start(&lock.freq_start)?;
        validate_lock_receipt_tags_v6(&lock)?;
        let exec = match parse_execution_receipt(&bundle.execution_receipt.payload_jcs)
            .map_err(|e| e.to_string())?
        {
            ParsedExecutionReceipt::V5(p) => p,
            _ => return Err(wrong_schema()),
        };
        validate_execution_receipt_tags_v5(&exec)?;
        // The state comes from the signed payload by the three-state table,
        // never from whichever field happens to be set.
        let payload: serde_json::Value =
            serde_json::from_str(&bundle.execution_receipt.payload_jcs)
                .map_err(|e| format!("the execution receipt is unusable: {e}"))?;
        let source = match landobs_v1::exec_state(&payload)? {
            ExecState::Weather(value) => SeedSource::Weather(value.to_string()),
            ExecState::Freq(_) => SeedSource::Freq,
            ExecState::DrandOnly => SeedSource::DrandOnly,
        };
        let station = exec
            .weather_station
            .ok_or("execution receipt has no weather_station")?;
        Ok(Self {
            draw_id: lock.draw_id,
            weather_time: lock.weather_time,
            weather_time_unix,
            station,
            source,
            fallback_reason: exec.weather_fallback_reason,
            freq_start: lock.freq_start,
            freq_start_unix,
            freq_value: exec.freq_value,
            freq_fallback_reason: exec.freq_fallback_reason,
        })
    }

    /// The grid-frequency window this draw falls back to, as the
    /// frequency check reads it.
    pub(crate) fn freq_input(&self) -> freq::FreqAttestInput {
        freq::FreqAttestInput {
            draw_id: self.draw_id.clone(),
            freq_start: self.freq_start.clone(),
            freq_start_unix: self.freq_start_unix,
            value: self.freq_value.clone(),
            fallback_reason: self.freq_fallback_reason.clone(),
        }
    }
}

pub(crate) fn station_name(station: &str) -> &'static str {
    match station {
        "wmo-03749" => "Middle Wallop",
        _ => "unknown station",
    }
}

/// Compare the signed observation with Land Observations (first), then
/// the WMO SYNOP via Ogimet. On a fallback, report whether Middle Wallop's
/// records hold that hour, then check the grid-frequency window against
/// Elexon: its signed readings in state (b), whether Elexon holds a valid
/// window in state (c).
///
/// Takes the run's one `OgimetClient` so every SYNOP request shares its
/// pacing. `input.weather_time` has passed `parse_weather_time` and
/// `input.freq_start` has passed `parse_freq_start`.
pub(crate) fn attest(
    input: &AttestInput,
    landobs: Option<&http::LandObsClient>,
    ogimet: &http::OgimetClient,
    elexon: &http::ElexonClient,
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
    let (begin, end) = synop::ogimet_window(input.weather_time_unix);
    let synop_for = |station: &str| -> Result<Option<String>, String> {
        ogimet.fetch(synop::block_for(station)?, &begin, &end)
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
    match &input.source {
        SeedSource::Weather(value) => {
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
        }
        SeedSource::Freq | SeedSource::DrandOnly => {
            presence_lines(PRIMARY_STATION, &mut lines);
            // A window Elexon holds now says no more than a reading the
            // Met Office holds now: its publication time is unknown.
            lines.extend(
                freq::attest(&input.freq_input(), elexon)
                    .into_iter()
                    .map(|line| match line.outcome {
                        Outcome::Present(d) => Line {
                            outcome: Outcome::Present(format!("{d}; {PRESENT_CAVEAT}")),
                            ..line
                        },
                        _ => line,
                    }),
            );
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
    let bundle = match read_input(path)
        .and_then(|json| ProofBundle::from_json(&json).map_err(|e| e.to_string()))
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    // The frequency tag is chosen by the signed lock receipt; it needs no key.
    if freq::is_freq_bundle(&bundle) {
        return freq::run(&bundle);
    }
    let input = match AttestInput::from_bundle(&bundle) {
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
    let elexon = http::ElexonClient::new(http::ELEXON_BASE_URL);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let lines = attest(&input, landobs.as_ref(), &ogimet, &elexon, now_unix);
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
    let reason = |r: &Option<String>| r.as_deref().unwrap_or("no reason given").to_string();
    match &input.source {
        SeedSource::Weather(value) => {
            let _ = writeln!(out, "  Seed source ......... Middle Wallop's reading");
            let _ = writeln!(
                out,
                "  Station used ........ {} ({})",
                input.station,
                station_name(&input.station)
            );
            let _ = writeln!(out, "  Weather value ....... {value}");
        }
        SeedSource::Freq => {
            let _ = writeln!(
                out,
                "  Seed source ......... grid frequency (Middle Wallop's reading was not stored by the deadline)"
            );
            let _ = writeln!(
                out,
                "  Station used ........ none (receipt reason: {})",
                reason(&input.fallback_reason)
            );
            let _ = writeln!(out, "  Readings from ....... {}", input.freq_start);
            if let Some(v) = &input.freq_value {
                let _ = writeln!(out, "  Grid frequency ...... {v} (mHz)");
            }
        }
        SeedSource::DrandOnly => {
            let _ = writeln!(
                out,
                "  Seed source ......... drand only (no reading and no grid window by the deadline)"
            );
            let _ = writeln!(
                out,
                "  Station used ........ none (receipt reason: {})",
                reason(&input.fallback_reason)
            );
            let _ = writeln!(out, "  Readings from ....... {}", input.freq_start);
            let _ = writeln!(
                out,
                "  Grid frequency ...... none (receipt reason: {})",
                reason(&input.freq_fallback_reason)
            );
        }
    }
    let _ = writeln!(out);
    for line in lines {
        let _ = writeln!(out, "  {}", render_line(line));
    }
    let _ = writeln!(out);
    let details = match input.source {
        SeedSource::Weather(_) => "weather details",
        SeedSource::Freq | SeedSource::DrandOnly => "weather and grid-frequency details",
    };
    let _ = writeln!(
        out,
        "  These lines check the {details} in this bundle's execution receipt"
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
            "  PRESENT means the record holds that hour, or that grid window, now. Its"
        );
        let _ = writeln!(
            out,
            "  publication time is unknown, so a late reading can't be told from a withheld one."
        );
    }
    if !matches!(input.source, SeedSource::Weather(_)) {
        let _ = writeln!(
            out,
            "  Contains BMRS data © Elexon Limited copyright and database right {}.",
            &input.freq_start[0..4]
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wallop_verifier::_test_support::{
        V6_FREQ_VALUE, V6_WEATHER_VALUE, V6Params, build_v6_bundle, build_valid_v5_bundle,
        v6_entries, v6_negative_bundle,
    };

    const WT: &str = "2026-10-01T19:00:00.000000Z";
    const WT_UNIX: i64 = 1_790_881_200;
    const ROW_03749: &str = r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":18.38,"mslp":1021,"humidity":51,"visibility":41140.0}]"#;
    const SYNOP_03749: &str =
        "03749,2026,10,01,19,00,AAXX 01194 03749 25481 82109 10184 20156 30096 40210 52001==\n";

    /// The round's window start for `WT` at the earliest publish time.
    const FREQ_START: &str = "2026-10-01T19:25:00.000000Z";
    const FREQ_START_UNIX: i64 = WT_UNIX + 1500;
    use freq::tests::{REAL as FREQ, REAL_TEXT as FREQ_TEXT, body_at, serve_at};
    const NOW: i64 = WT_UNIX + 3600;

    /// State (a) with a value, otherwise state (c).
    fn input(station: &str, value: Option<&str>) -> AttestInput {
        AttestInput {
            draw_id: "22222222-2222-2222-2222-222222222222".into(),
            weather_time: WT.into(),
            weather_time_unix: WT_UNIX,
            station: station.into(),
            source: match value {
                Some(v) => SeedSource::Weather(v.into()),
                None => SeedSource::DrandOnly,
            },
            fallback_reason: value
                .is_none()
                .then(|| landobs_v1::FALLBACK_NO_OBSERVATION.to_string()),
            freq_start: FREQ_START.into(),
            freq_start_unix: FREQ_START_UNIX,
            freq_value: None,
            freq_fallback_reason: value
                .is_none()
                .then(|| freq_v1::FALLBACK_NO_FREQUENCY.to_string()),
        }
    }

    fn input_fallback() -> AttestInput {
        input("wmo-03749", None)
    }

    /// State (b): no reading by the deadline, the grid window `value`.
    fn input_freq_fallback(value: &str) -> AttestInput {
        AttestInput {
            source: SeedSource::Freq,
            freq_value: Some(value.into()),
            freq_fallback_reason: None,
            ..input_fallback()
        }
    }

    fn ogimet(server: &mockito::Server) -> http::OgimetClient {
        http::OgimetClient::with_pacing(&server.url(), Duration::ZERO, Box::new(|_| {}))
    }

    fn elexon(server: &mockito::Server) -> http::ElexonClient {
        http::ElexonClient::new(&server.url())
    }

    fn serve_elexon(server: &mut mockito::Server, body: &str) -> mockito::Mock {
        serve_at(server, FREQ_START_UNIX, 200, body)
    }

    fn elexon_body(texts: &[&str]) -> String {
        body_at(FREQ_START_UNIX, texts)
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
        let (json, _, _) = build_v6_bundle(&V6Params::weather());
        let i = AttestInput::from_bundle(&ProofBundle::from_json(&json).unwrap()).unwrap();
        assert_eq!(i.station, "wmo-03749");
        assert_eq!(i.source, SeedSource::Weather("184;1021;51;4114".into()));
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
            &elexon(&server),
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
            &elexon(&server),
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
            &elexon(&server),
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
            &elexon(&server),
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
            &elexon(&server),
            WT_UNIX + 46 * 3600,
        );
        assert!(matches!(edge[0].outcome, Outcome::Match(_)), "{edge:?}");
    }

    #[test]
    fn fallback_reports_both_stations() {
        let mut server = mockito::Server::new();
        let earlier = ROW_03749.replace("19:00:00Z", "18:00:00Z");
        server.mock("GET", "/gcnfur").with_body(&earlier).create();
        mock_synop(
            &mut server,
            "03749",
            &SYNOP_03749.replace(",19,00,", ",18,00,"),
        );
        let landobs = http::LandObsClient::new(&server.url(), "k");
        let lines = attest(
            &input("wmo-03749", None),
            Some(&landobs),
            &ogimet(&server),
            &elexon(&server),
            WT_UNIX + 3600,
        );
        let labels: Vec<&str> = lines.iter().map(|l| l.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Land Observations, wmo-03749",
                "SYNOP via Ogimet, wmo-03749",
                "Elexon FREQ from 19:25:00 UTC"
            ]
        );
        assert!(
            lines[..2]
                .iter()
                .all(|l| matches!(l.outcome, Outcome::Absent(_))),
            "{lines:?}"
        );
    }

    #[test]
    fn an_unparseable_land_observations_body_is_unavailable_not_a_mismatch() {
        for body in [
            r#"{"error":"x"}"#,
            "<html>busy</html>",
            "",
            "[{\"datetime\":",
        ] {
            let mut server = mockito::Server::new();
            server.mock("GET", "/gcnfur").with_body(body).create();
            mock_synop(&mut server, "03749", SYNOP_03749);
            let landobs = http::LandObsClient::new(&server.url(), "k");
            let checked = attest(
                &input("wmo-03749", Some("184;1021;51;4114")),
                Some(&landobs),
                &ogimet(&server),
                &elexon(&server),
                WT_UNIX + 3600,
            );
            assert!(
                matches!(&checked[0].outcome, Outcome::Unavailable(r) if r.contains("not a list of rows")),
                "{body:?}: {checked:?}"
            );
            assert!(!has_mismatch(&checked), "{body:?}: {checked:?}");
            let fallback = attest(
                &input("wmo-03749", None),
                Some(&landobs),
                &ogimet(&server),
                &elexon(&server),
                WT_UNIX + 3600,
            );
            for line in fallback
                .iter()
                .filter(|l| l.label.starts_with("Land Observations"))
            {
                assert!(
                    matches!(&line.outcome, Outcome::Unavailable(r) if r.contains("not a list of rows")),
                    "{body:?}: {fallback:?}"
                );
            }
        }
    }

    #[test]
    fn ogimet_error_page_is_unavailable_not_absent() {
        let mut server = mockito::Server::new();
        mock_synop(
            &mut server,
            "03749",
            "Sorry, too many requests. Try later.\n",
        );
        let lines = attest(
            &input("wmo-03749", None),
            None,
            &ogimet(&server),
            &elexon(&server),
            WT_UNIX + 3600,
        );
        let synop: Vec<_> = lines.iter().filter(|l| l.label.contains("SYNOP")).collect();
        assert_eq!(synop.len(), 1);
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
        mock_synop(&mut server, "03749", "");
        let landobs = http::LandObsClient::new(&server.url(), "k");
        let lines = attest(
            &input("wmo-03749", None),
            Some(&landobs),
            &ogimet(&server),
            &elexon(&server),
            WT_UNIX + 3600,
        );
        let land: Vec<_> = lines
            .iter()
            .filter(|l| l.label.starts_with("Land"))
            .collect();
        assert_eq!(land.len(), 1);
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
            fallback.contains(
                "Station used ........ none (receipt reason: no_observation_by_deadline)"
            ),
            "{fallback}"
        );
        assert!(!fallback.contains("signed weather value"), "{fallback}");
        let flat = fallback.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains("These lines check the weather and grid-frequency details in this bundle's execution receipt against public records. This command does not check signatures; run `wallop-verify <BUNDLE>` for that."),
            "{fallback}"
        );
        let footer = "These lines check the weather details in this bundle's execution receipt against public records. This command does not check signatures; run `wallop-verify <BUNDLE>` for that.";
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

    #[test]
    fn ogimet_is_asked_for_three_hours_either_side() {
        let mut server = mockito::Server::new();
        let window = server
            .mock("GET", "/cgi-bin/getsynop")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("block".into(), "03749".into()),
                mockito::Matcher::UrlEncoded("begin".into(), "202610011600".into()),
                mockito::Matcher::UrlEncoded("end".into(), "202610012200".into()),
            ]))
            .with_body(SYNOP_03749)
            .expect(1)
            .create();
        let lines = attest(
            &input("wmo-03749", Some("184;1021;51;4114")),
            None,
            &ogimet(&server),
            &elexon(&server),
            WT_UNIX + 3600,
        );
        window.assert();
        assert!(matches!(lines[1].outcome, Outcome::Match(_)), "{lines:?}");
    }

    #[test]
    fn fallback_with_no_ogimet_reports_around_the_hour_is_unavailable() {
        let mut server = mockito::Server::new();
        mock_synop(&mut server, "03749", "");
        let lines = attest(
            &input("wmo-03749", None),
            None,
            &ogimet(&server),
            &elexon(&server),
            WT_UNIX + 3600,
        );
        let synop: Vec<_> = lines.iter().filter(|l| l.label.contains("SYNOP")).collect();
        assert_eq!(synop.len(), 1);
        assert!(
            synop
                .iter()
                .all(|l| matches!(l.outcome, Outcome::Unavailable(_))),
            "{lines:?}"
        );
    }

    #[test]
    fn from_bundle_reads_the_state_and_the_frequency_fields() {
        let read = |p: &V6Params| {
            let (json, _, _) = build_v6_bundle(p);
            AttestInput::from_bundle(&ProofBundle::from_json(&json).unwrap()).unwrap()
        };
        let a = read(&V6Params::weather());
        assert_eq!(a.source, SeedSource::Weather(V6_WEATHER_VALUE.into()));
        assert_eq!(a.freq_value, None);
        assert_eq!(a.freq_fallback_reason, None);
        let start = V6Params::weather().freq_start.unwrap();
        assert_eq!(a.freq_start, start);
        assert_eq!(
            a.freq_start_unix,
            freq_v1::parse_freq_start(&start).unwrap()
        );
        let b = read(&V6Params::freq_fallback());
        assert_eq!(b.source, SeedSource::Freq);
        assert_eq!(b.freq_value.as_deref(), Some(V6_FREQ_VALUE));
        let fi = b.freq_input();
        assert_eq!(fi.freq_start, start);
        assert_eq!(fi.value.as_deref(), Some(V6_FREQ_VALUE));
        assert_eq!(fi.fallback_reason, None);
        assert_eq!(fi.draw_id, b.draw_id);
        let c = read(&V6Params::fallback());
        assert_eq!(c.source, SeedSource::DrandOnly);
        assert_eq!(c.freq_value, None);
        assert_eq!(
            c.freq_fallback_reason.as_deref(),
            Some(freq_v1::FALLBACK_NO_FREQUENCY)
        );
    }

    #[test]
    fn from_bundle_refuses_a_receipt_outside_the_three_states() {
        for name in [
            "weather_with_freq_value",
            "weather_with_freq_fallback_reason",
            "freq_fallback_value_null_reason_null",
            "freq_value_without_weather_fallback_reason",
        ] {
            let (json, _, _) = v6_negative_bundle(name);
            let err =
                AttestInput::from_bundle(&ProofBundle::from_json(&json).unwrap()).unwrap_err();
            assert!(err.contains("none of the three states"), "{name}: {err}");
        }
    }

    #[test]
    fn a_present_reading_on_a_fallback_says_it_cannot_tell_late_from_withheld() {
        // Ogimet and Land Obs both hold the hour; the receipt fell back (state c).
        let mut server = mockito::Server::new();
        server.mock("GET", "/gcnfur").with_body(ROW_03749).create();
        mock_synop(&mut server, "03749", SYNOP_03749);
        serve_elexon(&mut server, &elexon_body(&FREQ_TEXT));
        let landobs_client = http::LandObsClient::new(&server.url(), "k");
        let lines = attest(
            &input_fallback(),
            Some(&landobs_client),
            &ogimet(&server),
            &elexon(&server),
            NOW,
        );
        let weather: Vec<_> = lines
            .iter()
            .filter(|l| !l.label.starts_with("Elexon"))
            .collect();
        assert_eq!(weather.len(), 2, "{lines:?}");
        for l in weather {
            assert_eq!(
                l.outcome,
                Outcome::Present(PRESENT_CAVEAT.into()),
                "{}",
                l.label
            );
        }
        // State (c): Elexon holds the window now, with the same caveat.
        let grid = lines
            .iter()
            .find(|l| l.label.starts_with("Elexon"))
            .unwrap();
        assert!(
            matches!(&grid.outcome, Outcome::Present(d)
                if d.starts_with("Elexon now holds a valid window") && d.ends_with(&format!("; {PRESENT_CAVEAT}"))),
            "{grid:?}"
        );
        let r = report(&input_fallback(), &lines);
        assert!(r.contains(&format!("PRESENT ({PRESENT_CAVEAT})")), "{r}");
        let flat = r.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains("PRESENT means the record holds that hour, or that grid window, now. Its publication time is unknown, so a late reading can't be told from a withheld one."),
            "{r}"
        );
        assert!(!r.contains("does not show"), "{r}");
    }

    #[test]
    fn a_frequency_fallback_is_checked_against_elexon() {
        // State (b): Middle Wallop presence lines, then Elexon for T..T+105s.
        let mut server = mockito::Server::new();
        mock_synop(&mut server, "03749", "");
        let window = serve_elexon(&mut server, &elexon_body(&FREQ_TEXT));
        let lines = attest(
            &input_freq_fallback(FREQ),
            None,
            &ogimet(&server),
            &elexon(&server),
            NOW,
        );
        window.assert();
        let labels: Vec<&str> = lines.iter().map(|l| l.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Land Observations, wmo-03749",
                "SYNOP via Ogimet, wmo-03749",
                "Elexon FREQ from 19:25:00 UTC"
            ]
        );
        assert_eq!(
            lines[2].outcome,
            Outcome::Match(format!("8 readings {FREQ}"))
        );
        assert!(!has_mismatch(&lines));

        // A different signed window is a mismatch.
        let mut server = mockito::Server::new();
        mock_synop(&mut server, "03749", "");
        serve_elexon(&mut server, &elexon_body(&FREQ_TEXT));
        let other = FREQ.replace("49883", "49884");
        let lines = attest(
            &input_freq_fallback(&other),
            None,
            &ogimet(&server),
            &elexon(&server),
            NOW,
        );
        assert!(
            matches!(&lines[2].outcome, Outcome::Mismatch(d) if d.contains("49884")),
            "{lines:?}"
        );
        assert!(has_mismatch(&lines));
    }

    #[test]
    fn a_weather_draw_does_not_ask_elexon() {
        let mut server = mockito::Server::new();
        mock_synop(&mut server, "03749", SYNOP_03749);
        let never = server.mock("GET", "/").expect(0).create();
        let lines = attest(
            &input("wmo-03749", Some("184;1021;51;4114")),
            None,
            &ogimet(&server),
            &elexon(&server),
            NOW,
        );
        never.assert();
        assert!(lines.iter().all(|l| !l.label.starts_with("Elexon")));
    }

    #[test]
    fn report_says_which_source_fed_the_seed() {
        let attribution = "Contains BMRS data © Elexon Limited copyright and database right 2026.";
        let a = report(&input("wmo-03749", Some("184;1021;51;4114")), &[]);
        assert!(
            a.contains("Seed source ......... Middle Wallop's reading\n"),
            "{a}"
        );
        assert!(!a.contains("Contains BMRS data"), "{a}");

        let b = report(&input_freq_fallback(FREQ), &[]);
        assert!(
            b.contains("Seed source ......... grid frequency (Middle Wallop's reading was not stored by the deadline)\n"),
            "{b}"
        );
        assert!(
            b.contains(&format!("Grid frequency ...... {FREQ} (mHz)")),
            "{b}"
        );
        assert!(
            b.contains(&format!("Readings from ....... {FREQ_START}")),
            "{b}"
        );
        assert!(b.contains(attribution), "{b}");
        assert!(!b.contains("drand only"), "{b}");

        let c = report(&input_fallback(), &[]);
        assert!(
            c.contains(
                "Seed source ......... drand only (no reading and no grid window by the deadline)\n"
            ),
            "{c}"
        );
        assert!(
            c.contains("Grid frequency ...... none (receipt reason: no_frequency_by_deadline)"),
            "{c}"
        );
        assert!(c.contains(attribution), "{c}");

        // The seed source line follows the observation hour.
        for r in [&a, &b, &c] {
            let hour = r.find("Observation hour").unwrap();
            let seed = r.find("Seed source").unwrap();
            assert!(hour < seed, "{r}");
        }
    }

    #[test]
    fn a_state_b_bundle_runs_end_to_end_without_printing_the_key() {
        const KEY: &str = "fake-metoffice-key-do-not-print";
        let (json, _, _) = build_v6_bundle(&V6Params::freq_fallback());
        let input = AttestInput::from_bundle(&ProofBundle::from_json(&json).unwrap()).unwrap();
        let mut server = mockito::Server::new();
        server.mock("GET", "/gcnfur").with_status(500).create();
        mock_synop(&mut server, "03749", "");
        // The real window for the fixture's own freq_start: the fixture
        // signs the same readings the frequency tests serve.
        assert_eq!(V6_FREQ_VALUE, FREQ);
        let window = serve_at(
            &mut server,
            input.freq_start_unix,
            200,
            &body_at(input.freq_start_unix, &FREQ_TEXT),
        );
        let landobs_client = http::LandObsClient::new(&server.url(), KEY);
        let lines = attest(
            &input,
            Some(&landobs_client),
            &ogimet(&server),
            &elexon(&server),
            input.weather_time_unix + 3600,
        );
        window.assert();
        let out = report(&input, &lines);
        assert!(out.contains("Elexon FREQ from"), "{out}");
        let grid = lines
            .iter()
            .find(|l| l.label.starts_with("Elexon"))
            .unwrap();
        assert_eq!(
            grid.outcome,
            Outcome::Match(format!("8 readings {V6_FREQ_VALUE}")),
            "{out}"
        );
        assert!(!has_mismatch(&lines), "{out}");
        assert!(!out.contains(KEY), "{out}");
    }
}
