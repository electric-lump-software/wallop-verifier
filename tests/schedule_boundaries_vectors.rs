//! wallop_core's schedule boundary vectors (`schedule-boundaries-v1.json`):
//! v6 draw schedules for every whole minute from 22:00 to 02:59 UTC across
//! both UK clock changes, a month end, a year end, a February without a
//! leap day and both sides of 29 February 2028, plus off-minute quicknet
//! grid points. The expected values come from a reference written
//! independently of both core and this crate.
//!
//! Every case must match the verifier's own schedule functions: the round's
//! publication time, `weather_time` and the latest lock for the Land Obs
//! tag, and `freq_start` and the latest lock for the grid-frequency tag.
//! The fetch deadlines follow from the tags' constants.
//!
//! Read under the rules in `tests/common`: the vendored copy; a failure if
//! it is missing once any v6 vector is vendored; before that,
//! `WALLOP_SCHEDULE_BOUNDARY_VECTORS` or `WALLOP_CORE_VECTORS_DIR`.

mod common;

use wallop_verifier::drand::quicknet_round_time;
use wallop_verifier::protocol::{freq_v1, landobs_v1};

const ENV: &str = "WALLOP_SCHEDULE_BOUNDARY_VECTORS";

const WINDOWS: [&str; 7] = [
    "bst_ends",
    "bst_starts",
    "month_end",
    "year_end",
    "no_leap_day",
    "leap_day_eve",
    "leap_day",
];

fn vector() -> serde_json::Value {
    common::core_vector("schedule-boundaries-v1.json", Some(ENV))
}

/// The vector's `YYYY-MM-DDTHH:MM:SSZ` as the receipts' canonical form.
fn canonical(iso: &str) -> String {
    let stem = iso
        .strip_suffix('Z')
        .unwrap_or_else(|| panic!("{iso} has no Z"));
    assert_eq!(stem.len(), 19, "{iso} is not whole seconds");
    format!("{stem}.000000Z")
}

/// The verifier's rendering of unix seconds.
fn render(secs: i64) -> String {
    freq_v1::format_freq_start(secs)
}

fn field<'a>(c: &'a serde_json::Value, key: &str) -> &'a str {
    c[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} missing in {c}"))
}

/// The case's round, checked against its `draw_at`; returns pub(round).
fn published(c: &serde_json::Value) -> (u64, i64) {
    let round = c["round"].as_u64().expect("round");
    let pub_secs = quicknet_round_time(round).expect("round time");
    assert_eq!(
        render(pub_secs),
        canonical(field(c, "draw_at")),
        "pub({round})"
    );
    (round, pub_secs)
}

fn cases<'a>(v: &'a serde_json::Value, keys: &[&str]) -> Vec<&'a serde_json::Value> {
    keys.iter()
        .flat_map(|k| {
            v[*k]
                .as_array()
                .unwrap_or_else(|| panic!("{k} missing"))
                .iter()
        })
        .collect()
}

#[test]
fn every_window_is_every_whole_minute_from_22_00_to_02_59() {
    let v = vector();
    for key in ["landobs", "freq"] {
        for window in WINDOWS {
            let pubs: Vec<i64> = v[key]
                .as_array()
                .unwrap()
                .iter()
                .filter(|c| c["window"] == window)
                .map(|c| published(c).1)
                .collect();
            assert_eq!(pubs.len(), 300, "{key} {window}");
            assert_eq!(pubs[0].rem_euclid(86_400), 22 * 3600, "{key} {window}");
            assert!(pubs.windows(2).all(|w| w[1] - w[0] == 60), "{key} {window}");
        }
    }
}

#[test]
fn landobs_schedule_matches_every_case() {
    let v = vector();
    let all = cases(&v, &["landobs", "landobs_grid_seconds"]);
    let w30 = &v["landobs_w30_not_w40"];
    let mut n = 0;
    for c in all.into_iter().chain(std::iter::once(w30)) {
        let (round, pub_secs) = published(c);
        let label = field(c, "draw_at");
        let wt = landobs_v1::weather_time_for_round(round).expect("weather_time");
        let expected_wt = canonical(field(c, "weather_time"));
        assert_eq!(render(wt), expected_wt, "{label} weather_time");
        assert_eq!(
            landobs_v1::parse_weather_time(&expected_wt),
            Ok(wt),
            "{label} parse_weather_time"
        );
        let lock = landobs_v1::latest_lock_at(wt).expect("latest lock");
        assert_eq!(
            render(lock),
            canonical(field(c, "latest_lock_at")),
            "{label} latest_lock_at"
        );
        let deadline = wt + landobs_v1::W_SECS;
        assert_eq!(
            render(deadline),
            canonical(field(c, "fetch_deadline")),
            "{label} fetch_deadline"
        );
        assert!(
            deadline + landobs_v1::PUBLISH_MARGIN_SECS <= pub_secs,
            "{label}"
        );
        n += 1;
    }
    assert!(n > 2_100, "{n} cases");
}

#[test]
fn landobs_w30_case_tells_w30_from_w40() {
    let v = vector();
    let c = &v["landobs_w30_not_w40"];
    let (round, pub_secs) = published(c);
    let w40 = (pub_secs - 40 * 60 - landobs_v1::PUBLISH_MARGIN_SECS).div_euclid(3600) * 3600;
    assert_ne!(Some(w40), landobs_v1::weather_time_for_round(round));
}

#[test]
fn freq_schedule_matches_every_case() {
    let v = vector();
    let mut n = 0;
    for c in cases(&v, &["freq", "freq_grid_seconds"]) {
        let (round, pub_secs) = published(c);
        let label = field(c, "draw_at");
        let t = freq_v1::freq_start_for_round(round).expect("freq_start");
        let expected_t = canonical(field(c, "freq_start"));
        assert_eq!(render(t), expected_t, "{label} freq_start");
        assert_eq!(
            freq_v1::parse_freq_start(&expected_t),
            Ok(t),
            "{label} parse_freq_start"
        );
        let lock = freq_v1::latest_lock_at(t).expect("latest lock");
        assert_eq!(
            render(lock),
            canonical(field(c, "latest_lock_at")),
            "{label} latest_lock_at"
        );
        let deadline = t + freq_v1::SPAN_SECS + freq_v1::W_FREQ_SECS;
        assert_eq!(
            render(deadline),
            canonical(field(c, "fetch_deadline")),
            "{label} fetch_deadline"
        );
        assert!(deadline + freq_v1::MARGIN_SECS <= pub_secs, "{label}");
        n += 1;
    }
    assert!(n > 2_100, "{n} cases");
}
