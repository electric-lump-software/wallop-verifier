//! Frozen rules for the `drand-quicknet+elexon-freq-v1` entropy tag (GB
//! grid frequency), carried by lock receipt schema 6 and execution receipt
//! schema 5.
//!
//! The tag fixes every value in this module. Changing any of them needs a
//! new tag.

use crate::drand::quicknet_round_time;

/// The `entropy_composition` value of grid-frequency receipts.
pub const ENTROPY_COMPOSITION: &str = "drand-quicknet+elexon-freq-v1";

/// Readings per window.
pub const READINGS: usize = 8;

/// Seconds between readings.
pub const SPACING_SECS: i64 = 15;

/// From the first reading to the last.
pub const SPAN_SECS: i64 = (READINGS as i64 - 1) * SPACING_SECS;

/// W_freq, in seconds: a window may be stored until `F = T + SPAN_SECS +
/// W_FREQ_SECS`. Provisional (240 s) until the Elexon latency measurement
/// ends. Before the release that ships this tag it is set to the largest
/// observed Elexon batch latency (measured from T + 105 s) plus 40 s, and
/// stays at most 240 s; core's fetch window changes in the same release.
pub const W_FREQ_SECS: i64 = 240;

/// M, in seconds: F is never later than `pub(R) - MARGIN_SECS`, so the
/// window is settled (and committed) before the drand round exists.
pub const MARGIN_SECS: i64 = 15;

/// The lock must be signed at least this long before `freq_start`.
pub const LOCK_GAP_SECS: i64 = 60;

/// N: this many identical readings in a row make a window invalid.
pub const STUCK_RUN: usize = 6;

/// Lowest reading, in mHz, inclusive.
pub const MIN_MHZ: u32 = 47_000;

/// Highest reading, in mHz, inclusive.
pub const MAX_MHZ: u32 = 52_999;

/// The only reason an execution receipt may give for having no readings.
pub const FALLBACK_NO_FREQUENCY: &str = "no_frequency_by_deadline";

/// Allowed `freq_fallback_reason` values.
pub const VALID_FREQ_FALLBACK_REASONS: &[Option<&str>] = &[None, Some(FALLBACK_NO_FREQUENCY)];

/// Every key of a lock receipt schema 6 under this tag, sorted bytewise.
/// Equal to core's lock key set for the tag.
pub const LOCK_KEYS: [&str; 20] = [
    "commitment_hash",
    "drand_chain",
    "drand_round",
    "draw_id",
    "entropy_composition",
    "entry_hash",
    "fair_pick_version",
    "freq_start",
    "jcs_version",
    "locked_at",
    "operator_id",
    "operator_slug",
    "schema_version",
    "sequence",
    "signature_algorithm",
    "signing_key_id",
    "wallop_core_version",
    "weather_station",
    "weather_time",
    "winner_count",
];

/// Every key of an execution receipt schema 5 under this tag, sorted
/// bytewise. Equal to core's execution key set for the tag.
pub const EXEC_KEYS: [&str; 28] = [
    "drand_chain",
    "drand_randomness",
    "drand_round",
    "drand_signature",
    "drand_signature_algorithm",
    "draw_id",
    "entropy_composition",
    "entry_hash",
    "executed_at",
    "fair_pick_version",
    "freq_fallback_reason",
    "freq_value",
    "jcs_version",
    "lock_receipt_hash",
    "merkle_algorithm",
    "operator_id",
    "operator_slug",
    "results",
    "schema_version",
    "seed",
    "sequence",
    "signature_algorithm",
    "signing_key_id",
    "wallop_core_version",
    "weather_fallback_reason",
    "weather_observation_time",
    "weather_station",
    "weather_value",
];

const _: () = assert!(W_FREQ_SECS > 0 && W_FREQ_SECS <= 240);
const _: () = assert!(MARGIN_SECS >= 15);
const _: () = assert!(STUCK_RUN >= 2 && STUCK_RUN <= READINGS);
const _: () = assert!(MIN_MHZ >= 10_000 && MAX_MHZ <= 99_999 && MIN_MHZ < MAX_MHZ);

/// `Ok` when `value` is a JSON object whose keys are exactly `keys`
/// (`keys` sorted bytewise, as `LOCK_KEYS` and `EXEC_KEYS` are).
pub fn exact_keys(value: &serde_json::Value, keys: &[&str]) -> Result<(), String> {
    let mut got: Vec<&str> = value
        .as_object()
        .ok_or("the receipt is not a JSON object")?
        .keys()
        .map(String::as_str)
        .collect();
    got.sort_unstable();
    if got == keys {
        Ok(())
    } else {
        Err(format!(
            "the receipt's keys are not the {ENTROPY_COMPOSITION} key set"
        ))
    }
}

/// The window start T (unix seconds) for quicknet `round`:
/// floor15(pub(round) - SPAN_SECS - W_FREQ_SECS - MARGIN_SECS). `None` for
/// round 0 or on overflow.
pub fn freq_start_for_round(round: u64) -> Option<i64> {
    let published = quicknet_round_time(round)?;
    let latest = published.checked_sub(SPAN_SECS + W_FREQ_SECS + MARGIN_SECS)?;
    Some(latest.div_euclid(SPACING_SECS) * SPACING_SECS)
}

/// The latest permitted `locked_at` (unix seconds) for `freq_start`.
/// `None` on overflow.
pub fn latest_lock_at(freq_start: i64) -> Option<i64> {
    freq_start.checked_sub(LOCK_GAP_SECS)
}

/// Unix seconds as the receipts' canonical `YYYY-MM-DDTHH:MM:SS.000000Z`.
/// Public, so tests and tools outside the crate (the vector tests,
/// `weather-attest`) render times without `verify_steps` internals.
pub fn format_freq_start(secs: i64) -> String {
    crate::verify_steps::format_canonical(secs, 0)
}

/// Parse a lock receipt `freq_start`: exactly `YYYY-MM-DDTHH:MM:SS.ffffffZ`,
/// a whole multiple of 15 seconds, and a real calendar time (the string must
/// equal its own canonical rendering). Returns unix seconds.
pub fn parse_freq_start(s: &str) -> Result<i64, String> {
    let t = crate::verify_steps::chrono_parse_canonical(s)?;
    let secs = t.timestamp();
    if t.subsec_micros() != 0 || secs.rem_euclid(SPACING_SECS) != 0 {
        return Err(format!(
            "{s} is not a whole multiple of {SPACING_SECS} seconds"
        ));
    }
    if format_freq_start(secs) != s {
        return Err(format!("{s} is not a valid calendar time"));
    }
    Ok(secs)
}

/// Parse `freq_value`: 8 readings of exactly 5 digits, `;`-joined, each in
/// bounds, with no run of `STUCK_RUN` identical readings.
pub fn parse_freq_value(s: &str) -> Result<[u32; READINGS], String> {
    let parts: Vec<&str> = s.split(';').collect();
    if parts.len() != READINGS {
        return Err(format!(
            "freq_value has {} readings, expected {READINGS}",
            parts.len()
        ));
    }
    let mut out = [0u32; READINGS];
    for (i, (slot, part)) in out.iter_mut().zip(&parts).enumerate() {
        if part.len() != 5 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("freq_value reading {i} ({part:?}) is not 5 digits"));
        }
        let n: u32 = part
            .parse()
            .map_err(|e| format!("freq_value reading {i}: {e}"))?;
        if !(MIN_MHZ..=MAX_MHZ).contains(&n) {
            return Err(format!(
                "freq_value reading {i} ({n}) is outside [{MIN_MHZ}, {MAX_MHZ}]"
            ));
        }
        *slot = n;
    }
    check_stuck(&out)?;
    Ok(out)
}

/// One Elexon `frequency` JSON number text as whole mHz: digits, then at
/// most 3 decimal places padded with zeros. Never through a float. No sign,
/// exponent or leading zero; not 0; in bounds. A quoted number (`"50.018"`),
/// `null` or an empty text (no `frequency` at all) is invalid.
pub fn reading_from_text(text: &str) -> Result<u32, String> {
    let (int, frac) = match text.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (text, None),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(int) || int.len() > 6 || (int.len() > 1 && int.starts_with('0')) {
        return Err(format!("{text:?} is not a plain decimal reading"));
    }
    let frac = match frac {
        None => "",
        Some(f) if digits(f) && f.len() <= 3 => f,
        Some(_) => {
            return Err(format!(
                "{text:?} has more than 3 decimal places or a bad fraction"
            ));
        }
    };
    let whole: u32 = int.parse().map_err(|e| format!("{text:?}: {e}"))?;
    let thousandths: u32 = format!("{frac:0<3}")
        .parse()
        .map_err(|e| format!("{text:?}: {e}"))?;
    let mhz = whole * 1000 + thousandths;
    if mhz == 0 {
        return Err("reading is 0".into());
    }
    if !(MIN_MHZ..=MAX_MHZ).contains(&mhz) {
        return Err(format!("reading {mhz} is outside [{MIN_MHZ}, {MAX_MHZ}]"));
    }
    Ok(mhz)
}

/// The `freq_value` of the window starting at `freq_start`, from Elexon
/// rows `(measurementTime, frequency JSON text)`, or the first reason the
/// window is invalid.
///
/// The row rule, identical to core's. The caller turns the body's `data`
/// list into rows:
///
/// * a list item that is not a JSON object is dropped;
/// * an object with a repeated key keeps the last value for that key;
/// * an object whose `measurementTime` is missing or not a JSON string is
///   dropped (it matches no reading time);
/// * every other object is a row, with `frequency` exactly as its JSON
///   source text (`49.98`, `"49.98"`, `null`), or `""` when it has none.
///
/// Then each reading time, in time order, is matched by exact
/// `YYYY-MM-DDTHH:MM:SSZ` text (so `...T19:55:00.000Z` matches nothing);
/// rows at no reading time are ignored. No matching row is a missing
/// reading; two or more are a duplicate, whatever they hold; one gives the
/// reading through `reading_from_text`. The first failure is returned. A
/// stuck run is checked once all 8 readings are good.
pub fn window_from_rows(rows: &[(String, String)], freq_start: i64) -> Result<String, String> {
    let mut readings = [0u32; READINGS];
    for (i, slot) in readings.iter_mut().enumerate() {
        let at = freq_start
            .checked_add(SPACING_SECS * i as i64)
            .ok_or_else(|| format!("{freq_start} is out of range"))?;
        let stamp = elexon_stamp(at)?;
        let matching: Vec<&String> = rows
            .iter()
            .filter(|(t, _)| *t == stamp)
            .map(|(_, f)| f)
            .collect();
        *slot = match matching.as_slice() {
            [] => return Err(format!("no reading for {stamp}")),
            [text] => reading_from_text(text).map_err(|e| format!("{stamp}: {e}"))?,
            _ => return Err(format!("more than one reading for {stamp}")),
        };
    }
    check_stuck(&readings)?;
    Ok(readings
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(";"))
}

fn check_stuck(readings: &[u32]) -> Result<(), String> {
    let mut run = 1;
    for pair in readings.windows(2) {
        run = if pair[0] == pair[1] { run + 1 } else { 1 };
        if run >= STUCK_RUN {
            return Err(format!("{STUCK_RUN} or more identical readings in a row"));
        }
    }
    Ok(())
}

/// Unix seconds as Elexon's `measurementTime` text, `YYYY-MM-DDTHH:MM:SSZ`.
fn elexon_stamp(secs: i64) -> Result<String, String> {
    let canonical = format_freq_start(secs);
    match canonical.strip_suffix(".000000Z") {
        Some(prefix) if prefix.len() == 19 => Ok(format!("{prefix}Z")),
        _ => Err(format!("{secs} is out of range")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round 33_068_212 publishes at 2026-10-14T20:00:00Z.
    const ROUND: u64 = 33_068_212;
    const PUB: i64 = 1_792_008_000;
    const REAL: &str = "50018;50012;49983;49980;49953;49912;49883;49887";
    const REAL_TEXT: [&str; 8] = [
        "50.018", "50.012", "49.983", "49.98", "49.953", "49.912", "49.883", "49.887",
    ];

    fn stamp(secs: i64) -> String {
        let canonical = crate::verify_steps::format_canonical(secs, 0);
        format!("{}Z", &canonical[..19])
    }

    /// Rows newest first, as Elexon returns them.
    fn rows(texts: &[&str]) -> Vec<(String, String)> {
        let start = PUB - 360;
        let mut out: Vec<(String, String)> = texts
            .iter()
            .enumerate()
            .map(|(i, t)| (stamp(start + 15 * i as i64), (*t).to_string()))
            .collect();
        out.reverse();
        out
    }

    #[test]
    fn constants_are_the_tag_values() {
        assert_eq!(ENTROPY_COMPOSITION, "drand-quicknet+elexon-freq-v1");
        assert_eq!(READINGS, 8);
        assert_eq!(SPACING_SECS, 15);
        assert_eq!(SPAN_SECS, 105);
        assert_eq!(W_FREQ_SECS, 240);
        assert_eq!(MARGIN_SECS, 15);
        assert_eq!(LOCK_GAP_SECS, 60);
        assert_eq!(STUCK_RUN, 6);
        assert_eq!((MIN_MHZ, MAX_MHZ), (47_000, 52_999));
        assert_eq!(FALLBACK_NO_FREQUENCY, "no_frequency_by_deadline");
        assert_eq!(
            VALID_FREQ_FALLBACK_REASONS,
            &[None, Some("no_frequency_by_deadline")]
        );
    }

    #[test]
    fn stamp_helper_matches_elexon_form() {
        assert_eq!(stamp(PUB - 360), "2026-10-14T19:54:00Z");
        assert_eq!(
            elexon_stamp(PUB - 360),
            Ok("2026-10-14T19:54:00Z".to_string())
        );
    }

    #[test]
    fn key_sets_are_sorted_and_sized() {
        assert!(LOCK_KEYS.windows(2).all(|w| w[0] < w[1]));
        assert!(EXEC_KEYS.windows(2).all(|w| w[0] < w[1]));
        let lock = serde_json::Value::Object(
            LOCK_KEYS
                .iter()
                .map(|k| (k.to_string(), serde_json::Value::Null))
                .collect(),
        );
        assert_eq!(exact_keys(&lock, &LOCK_KEYS), Ok(()));
        let mut short = lock.clone();
        short.as_object_mut().unwrap().remove("weather_time");
        assert!(exact_keys(&short, &LOCK_KEYS).is_err());
        let mut long = lock.clone();
        long.as_object_mut()
            .unwrap()
            .insert("weather_value".into(), serde_json::Value::Null);
        assert!(exact_keys(&long, &LOCK_KEYS).is_err());
        assert!(exact_keys(&serde_json::Value::Null, &LOCK_KEYS).is_err());
        let exec = serde_json::Value::Object(
            EXEC_KEYS
                .iter()
                .map(|k| (k.to_string(), serde_json::Value::Null))
                .collect(),
        );
        assert_eq!(exact_keys(&exec, &EXEC_KEYS), Ok(()));
        assert!(exact_keys(&exec, &LOCK_KEYS).is_err());
    }

    #[test]
    fn worked_example_at_w_240_m_15() {
        assert_eq!(
            W_FREQ_SECS, 240,
            "recompute this example for the new W_FREQ_SECS"
        );
        assert_eq!(
            MARGIN_SECS, 15,
            "recompute this example for the new MARGIN_SECS"
        );
        assert_eq!(quicknet_round_time(ROUND), Some(PUB));
        assert_eq!(freq_start_for_round(ROUND), Some(PUB - 360)); // 19:54:00
        assert_eq!(freq_start_for_round(ROUND + 1), Some(PUB - 360)); // 20:00:03 shares it
        assert_eq!(freq_start_for_round(ROUND + 5), Some(PUB - 345)); // 20:00:15 -> 19:54:15
        assert_eq!(freq_start_for_round(ROUND - 1), Some(PUB - 375)); // 19:59:57 -> 19:53:45
        assert_eq!(latest_lock_at(PUB - 360), Some(PUB - 420)); // 19:53:00
        assert_eq!(format_freq_start(PUB - 360), "2026-10-14T19:54:00.000000Z");
        assert_eq!(
            parse_freq_start(&format_freq_start(PUB - 360)),
            Ok(PUB - 360)
        );
    }

    #[test]
    fn freq_start_is_the_latest_boundary_that_fits() {
        for round in (1_000_000u64..1_002_000).chain([1, 2, ROUND, ROUND + 1, ROUND + 4, ROUND + 5])
        {
            let published = quicknet_round_time(round).unwrap();
            let t = freq_start_for_round(round).unwrap();
            assert_eq!(t.rem_euclid(SPACING_SECS), 0, "round {round}");
            assert!(
                t + SPAN_SECS + W_FREQ_SECS + MARGIN_SECS <= published,
                "round {round}"
            );
            assert!(
                t + SPACING_SECS + SPAN_SECS + W_FREQ_SECS + MARGIN_SECS > published,
                "round {round}"
            );
        }
        assert_eq!(freq_start_for_round(0), None);
        assert_eq!(freq_start_for_round(u64::MAX), None);
        assert_eq!(latest_lock_at(i64::MIN), None);
    }

    #[test]
    fn parse_freq_start_accepts_only_canonical_15_second_boundaries() {
        assert_eq!(
            parse_freq_start("2026-10-14T19:54:00.000000Z"),
            Ok(PUB - 360)
        );
        assert_eq!(
            parse_freq_start("2026-10-14T19:54:15.000000Z"),
            Ok(PUB - 345)
        );
        for bad in [
            "2026-10-14T19:54:16.000000Z",
            "2026-10-14T19:54:15.000001Z",
            "2026-10-14T19:53:60.000000Z",
            "2026-09-31T19:54:00.000000Z",
            "2026-10-14T19:54:15Z",
            "2026-10-14T19:54:15.000000+00:00",
            "",
        ] {
            assert!(parse_freq_start(bad).is_err(), "{bad}");
        }
        assert!(
            parse_freq_start("2026-10-14T19:54:15.000001Z")
                .unwrap_err()
                .contains("multiple of 15")
        );
    }

    #[test]
    fn reading_from_text_reads_the_number_text_exactly() {
        for (text, mhz) in [
            ("50.018", 50_018),
            ("49.98", 49_980),
            ("50", 50_000),
            ("50.0", 50_000),
            ("50.00", 50_000),
            ("47", 47_000),
            ("52.999", 52_999),
        ] {
            assert_eq!(reading_from_text(text), Ok(mhz), "{text}");
        }
        for bad in [
            "0",
            "0.000",
            "46.999",
            "53",
            "53.1",
            "49.9871",
            "4.9987e1",
            "5E1",
            "-49.987",
            "+49.987",
            "049.987",
            "49.",
            ".5",
            " 50",
            "50 ",
            "\"50.018\"",
            "null",
            "",
            "1234567",
            "9999999",
        ] {
            assert!(reading_from_text(bad).is_err(), "{bad}");
        }
        assert!(reading_from_text("0").unwrap_err().contains("is 0"));
        assert!(reading_from_text("0.000").unwrap_err().contains("is 0"));
        assert!(reading_from_text("53").unwrap_err().contains("outside"));
        assert!(!reading_from_text("5E1").unwrap_err().contains("outside"));
    }

    #[test]
    fn parse_freq_value_checks_shape_bounds_and_the_stuck_run() {
        assert_eq!(parse_freq_value(REAL).unwrap()[3], 49_980);
        assert_eq!(
            parse_freq_value(REAL).unwrap(),
            [50018, 50012, 49983, 49980, 49953, 49912, 49883, 49887]
        );
        assert!(parse_freq_value("50000;50000;50000;50000;50000;50011;50012;50013").is_ok());
        assert!(parse_freq_value("47000;52999;50000;50001;50000;50001;50000;50001").is_ok());
        for bad in [
            "50018;50012;49983;49980;49953;49912;49883",
            "50018;50012;49983;49980;49953;49912;49883;49887;49887",
            "4998;50012;49983;49980;49953;49912;49883;49887",
            "00000;50012;49983;49980;49953;49912;49883;49887",
            "53000;50012;49983;49980;49953;49912;49883;49887",
            "46999;50012;49983;49980;49953;49912;49883;49887",
            "50000;50000;50000;50000;50000;50000;50012;50013",
            "50011;50012;50000;50000;50000;50000;50000;50000",
            "50000;50000;50000;50000;50000;50000;50000;50000",
            "+5001;50012;49983;49980;49953;49912;49883;49887",
            "050000;50012;49983;49980;49953;49912;49883;49887",
            "+50000;50012;49983;49980;49953;49912;49883;49887",
            "50018;50012;49983;49980;49953;49912;49883;49887;",
            "50018,50012;49983;49980;49953;49912;49883;49887",
            "",
        ] {
            assert!(parse_freq_value(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn window_from_rows_matches_core() {
        let start = PUB - 360;
        assert_eq!(
            window_from_rows(&rows(&REAL_TEXT), start).as_deref(),
            Ok(REAL)
        );

        let mut extra = rows(&REAL_TEXT);
        extra.push((stamp(start - 15), "50.001".into()));
        extra.push((stamp(start + 120), "50.001".into()));
        extra.push((format!("{}.000Z", &stamp(start)[..19]), "50.001".into()));
        assert_eq!(window_from_rows(&extra, start).as_deref(), Ok(REAL));

        let mut missing = rows(&REAL_TEXT);
        missing.retain(|(t, _)| *t != stamp(start + 45));
        assert!(
            window_from_rows(&missing, start)
                .unwrap_err()
                .contains("2026-10-14T19:54:45Z")
        );

        let mut duplicate = rows(&REAL_TEXT);
        duplicate.push((stamp(start + 45), "49.98".into()));
        assert!(
            window_from_rows(&duplicate, start)
                .unwrap_err()
                .contains("more than one")
        );

        // A matching row with no frequency (given as "") still counts.
        let mut dup_empty = rows(&REAL_TEXT);
        dup_empty.push((stamp(start + 45), String::new()));
        assert!(
            window_from_rows(&dup_empty, start)
                .unwrap_err()
                .contains("more than one")
        );

        let mut zero = REAL_TEXT;
        zero[2] = "0";
        assert!(window_from_rows(&rows(&zero), start).is_err());

        // The first failure in time order is reported.
        let mut two = REAL_TEXT;
        two[1] = "53";
        two[5] = "0";
        let err = window_from_rows(&rows(&two), start).unwrap_err();
        assert!(err.contains("2026-10-14T19:54:15Z"), "{err}");

        let six = [
            "50.0", "50.0", "50.0", "50.0", "50.0", "50.0", "50.012", "50.013",
        ];
        assert!(
            window_from_rows(&rows(&six), start)
                .unwrap_err()
                .contains("identical")
        );
        // Equal values from different texts are still identical readings.
        let six_end = [
            "50.011", "50.012", "50", "50.0", "50.00", "50.000", "50", "50.0",
        ];
        assert!(
            window_from_rows(&rows(&six_end), start)
                .unwrap_err()
                .contains("identical")
        );
        let five = [
            "50.0", "50.0", "50.0", "50.0", "50.0", "50.011", "50.012", "50.013",
        ];
        assert_eq!(
            window_from_rows(&rows(&five), start).as_deref(),
            Ok("50000;50000;50000;50000;50000;50011;50012;50013")
        );

        assert!(
            window_from_rows(&[], start)
                .unwrap_err()
                .contains("no reading")
        );
    }
}
