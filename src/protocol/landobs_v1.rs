//! Frozen rules for the `drand-quicknet+metoffice-landobs-v1` entropy tag,
//! carried by lock receipt schema 6 and execution receipt schema 5.
//!
//! The tag fixes every value in this module. Changing any of them needs a
//! new tag and, with it, new receipt schemas.

use crate::drand::quicknet_round_time;

/// The `entropy_composition` value of lock v6 and execution v5 receipts.
pub const ENTROPY_COMPOSITION: &str = "drand-quicknet+metoffice-landobs-v1";

/// Middle Wallop (ICAO EGVP), the tag's only station. Every lock and
/// execution receipt under the tag names it.
pub const PRIMARY_STATION: &str = "wmo-03749";

/// W, in seconds: the observation for `weather_time` may be fetched until
/// `weather_time + W_SECS`.
///
/// 30 minutes, frozen with the tag. Middle Wallop's publication latency
/// drifts, so a reading can miss this deadline; the draw then falls back.
/// Every derived value, fixture and unit test follows this one constant.
pub const W_SECS: i64 = 30 * 60;

/// Gap between the end of the fetch window and the drand round's
/// publication.
pub const PUBLISH_MARGIN_SECS: i64 = 60;

/// The lock must be signed at least this long before `weather_time`.
pub const LOCK_OFFSET_SECS: i64 = 46 * 60;

/// The only reason an execution v5 receipt may give for having no weather.
pub const FALLBACK_NO_OBSERVATION: &str = "no_observation_by_deadline";

/// Allowed `weather_fallback_reason` values on an execution v5 receipt.
pub const VALID_WEATHER_FALLBACK_REASONS: &[Option<&str>] = &[None, Some(FALLBACK_NO_OBSERVATION)];

/// Both lock schema 6 tags share one lock key set and one execution key
/// set; the Land Observations tag signs `freq_start`, and on a fallback
/// `freq_value` / `freq_fallback_reason`, with the grid-frequency tag's
/// meaning. The fallback's constants are `freq_v1`'s, frozen by this tag
/// by reference.
pub use super::freq_v1::{EXEC_KEYS, LOCK_KEYS};

const _: () = assert!(W_SECS > 0 && W_SECS <= 90 * 60 && W_SECS % 60 == 0);

const HOUR_SECS: i64 = 3600;

/// The observation hour (unix seconds) for quicknet `round`: the latest
/// whole UTC hour h with `h + W_SECS + PUBLISH_MARGIN_SECS <= pub(round)`.
/// `None` for round 0 or on overflow.
pub fn weather_time_for_round(round: u64) -> Option<i64> {
    let published = quicknet_round_time(round)?;
    let latest = published.checked_sub(W_SECS + PUBLISH_MARGIN_SECS)?;
    Some(latest.div_euclid(HOUR_SECS) * HOUR_SECS)
}

/// The latest permitted `locked_at` (unix seconds) for `weather_time`.
/// `None` on overflow.
pub fn latest_lock_at(weather_time: i64) -> Option<i64> {
    weather_time.checked_sub(LOCK_OFFSET_SECS)
}

/// Parse a lock receipt `weather_time` under this tag. It must be exactly
/// `YYYY-MM-DDTHH:MM:SS.ffffffZ` (six fractional digits, `Z` only), a whole
/// UTC hour, and a real calendar time: the string must equal its own
/// canonical rendering, so `18:60` or `09-31` is rejected rather than
/// normalised. Returns unix seconds.
pub fn parse_weather_time(s: &str) -> Result<i64, String> {
    let t = crate::verify_steps::chrono_parse_canonical(s)?;
    let secs = t.timestamp();
    if t.subsec_micros() != 0 || secs.rem_euclid(HOUR_SECS) != 0 {
        return Err(format!("{s} is not a whole UTC hour"));
    }
    if crate::verify_steps::format_canonical(secs, 0) != s {
        return Err(format!("{s} is not a valid calendar time"));
    }
    Ok(secs)
}

/// Bounds on each part of `weather_value`, inclusive. Physical limits, not
/// climate expectations: temperature in tenths of a degree C, pressure in
/// whole hPa, humidity in whole percent, visibility in decametres. They
/// apply to the canonical parts, after rounding. The shared vector
/// `weather-value-landobs-v1.json` freezes the same values under `bounds`.
pub const T_MIN: i64 = -900;
pub const T_MAX: i64 = 600;
pub const MSLP_MIN: i64 = 850;
pub const MSLP_MAX: i64 = 1100;
pub const RH_MIN: i64 = 0;
pub const RH_MAX: i64 = 100;
pub const VIS_MIN: i64 = 0;
pub const VIS_MAX: i64 = 10_000;

/// Longest `weather_value` accepted, in bytes.
const WEATHER_VALUE_MAX_LEN: usize = 32;

/// A parsed `weather_value`: `"<t>;<mslp>;<rh>;<vis>"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeatherValue {
    /// Temperature, tenths of a degree C.
    pub t: i64,
    /// Mean sea-level pressure, whole hPa.
    pub mslp: i64,
    /// Relative humidity, whole percent.
    pub rh: i64,
    /// Visibility, decametres.
    pub vis: i64,
}

/// Parse `weather_value` under the tag's grammar. Each part is a decimal
/// integer with no leading zeros, and only `t` may carry a `-` (never on
/// zero). Every part must lie within its bounds.
pub fn parse_weather_value(s: &str) -> Result<WeatherValue, String> {
    if s.len() > WEATHER_VALUE_MAX_LEN {
        return Err(format!(
            "weather_value is longer than {WEATHER_VALUE_MAX_LEN} bytes"
        ));
    }
    let parts: Vec<&str> = s.split(';').collect();
    if parts.len() != 4 {
        return Err(format!(
            "weather_value must have 4 parts separated by ';', got {}",
            parts.len()
        ));
    }
    Ok(WeatherValue {
        t: parse_part(parts[0], "t", true, T_MIN, T_MAX)?,
        mslp: parse_part(parts[1], "mslp", false, MSLP_MIN, MSLP_MAX)?,
        rh: parse_part(parts[2], "rh", false, RH_MIN, RH_MAX)?,
        vis: parse_part(parts[3], "vis", false, VIS_MIN, VIS_MAX)?,
    })
}

fn parse_part(text: &str, name: &str, signed: bool, min: i64, max: i64) -> Result<i64, String> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) if signed => (true, rest),
        Some(_) => return Err(format!("weather_value {name} must not be negative")),
        None => (false, text),
    };
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "weather_value {name} ({text:?}) is not a decimal integer"
        ));
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(format!(
            "weather_value {name} ({text:?}) has a leading zero"
        ));
    }
    if negative && digits == "0" {
        return Err(format!("weather_value {name} is -0"));
    }
    let magnitude: i64 = digits
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let value = if negative { -magnitude } else { magnitude };
    if !(min..=max).contains(&value) {
        return Err(format!(
            "weather_value {name} ({value}) is outside [{min}, {max}]"
        ));
    }
    Ok(value)
}

/// Round the plain decimal `text` times 10^`shift` to an integer, half
/// away from zero (19.55 -> 196, -0.05 -> -1, -0.04 -> 0, never "-0").
/// With `exact`, any digits that would be rounded away must be zero.
/// Exponents, NaN, quotes and signs other than a leading `-` are rejected.
fn scale_decimal(text: &str, shift: i32, exact: bool) -> Result<i64, String> {
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (int_part, frac_part) = match body.split_once('.') {
        Some((i, f)) if !f.is_empty() => (i, f),
        Some(_) => return Err(format!("{text:?} is not a plain decimal number")),
        None => (body, ""),
    };
    let digits_ok = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if int_part.is_empty() || !digits_ok(int_part) || !digits_ok(frac_part) {
        return Err(format!("{text:?} is not a plain decimal number"));
    }
    if int_part.len() + frac_part.len() > 15 {
        return Err(format!("{text:?} has too many digits"));
    }
    let n: i64 = format!("{int_part}{frac_part}")
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let exp = shift - frac_part.len() as i32;
    let magnitude = if exp >= 0 {
        n.checked_mul(10i64.pow(exp as u32))
            .ok_or_else(|| format!("{text:?} is too large"))?
    } else {
        let div = 10i64.pow(exp.unsigned_abs());
        let (q, r) = (n / div, n % div);
        if exact && r != 0 {
            return Err(format!("{text:?} is not a whole number at this precision"));
        }
        if r * 2 >= div { q + 1 } else { q }
    };
    Ok(if negative { -magnitude } else { magnitude })
}

/// `text` unchanged, or an error if it starts with `-`. Pressure, humidity
/// and visibility are never signed, so `-0`, `-4` and `-0.0` are all
/// invalid, even where the value would round to zero.
fn unsigned(text: &str) -> Result<&str, String> {
    if text.starts_with('-') {
        Err(format!("{text:?} must not be negative"))
    } else {
        Ok(text)
    }
}

/// Visibility in metres as decametres. The metres must be a whole number
/// with no `-` sign: a fractional value is invalid, never rounded to whole
/// metres. The division by 10 rounds half up (25 m -> 3).
fn decametres(text: &str) -> Result<i64, String> {
    let metres = scale_decimal(unsigned(text)?, 0, true)?;
    Ok((metres + 5) / 10)
}

/// The JSON text of `field`, or why it can't be used.
fn number<'a>(
    field_text: &impl Fn(&str) -> Option<&'a str>,
    field: &str,
) -> Result<&'a str, String> {
    match field_text(field) {
        None => Err(format!("{field} is missing")),
        Some("null") => Err(format!("{field} is null")),
        Some(text) => Ok(text),
    }
}

/// The `weather_value` one Land Observations row yields under the tag's
/// rules, or why the row is not a valid observation.
///
/// `field_text` returns a field's value exactly as it appears in the JSON
/// source (for example `18.38`, `"50"` or `null`), or `None` if the row
/// lacks the field. Numbers are rounded from their decimal digits, never
/// through a float.
///
/// The rules are per field: an exponent, a string, a null or a missing
/// value in a required field makes the row invalid; other fields are
/// never read. Temperature may carry a `-`; pressure, humidity and
/// visibility may not. Bounds are checked on the canonical parts, after
/// rounding.
pub fn row_to_value<'a>(field_text: impl Fn(&str) -> Option<&'a str>) -> Result<String, String> {
    let t = scale_decimal(number(&field_text, "temperature")?, 1, false)
        .map_err(|e| format!("temperature: {e}"))?;
    let mslp = unsigned(number(&field_text, "mslp")?)
        .and_then(|text| scale_decimal(text, 0, true))
        .map_err(|e| format!("mslp: {e}"))?;
    let rh = unsigned(number(&field_text, "humidity")?)
        .and_then(|text| scale_decimal(text, 0, true))
        .map_err(|e| format!("humidity: {e}"))?;
    let vis =
        decametres(number(&field_text, "visibility")?).map_err(|e| format!("visibility: {e}"))?;
    let value = format!("{t};{mslp};{rh};{vis}");
    parse_weather_value(&value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drand::{QUICKNET_GENESIS_TIME, QUICKNET_PERIOD_SECS};
    use crate::verify_steps::{chrono_parse_canonical, format_canonical};

    /// 2026-10-01T19:00:00Z.
    const H: i64 = 1_790_881_200;

    /// The quicknet round published at unix time `t` (`t` must be on the grid).
    fn round_at(t: i64) -> u64 {
        let elapsed = t - QUICKNET_GENESIS_TIME as i64;
        assert_eq!(
            elapsed % QUICKNET_PERIOD_SECS as i64,
            0,
            "{t} is off the quicknet grid"
        );
        (elapsed / QUICKNET_PERIOD_SECS as i64) as u64 + 1
    }

    #[test]
    fn constants_are_the_tag_values() {
        assert_eq!(ENTROPY_COMPOSITION, "drand-quicknet+metoffice-landobs-v1");
        assert_eq!(PRIMARY_STATION, "wmo-03749");
        assert_eq!(LOCK_OFFSET_SECS, 46 * 60);
        assert_eq!(PUBLISH_MARGIN_SECS, 60);
        assert_eq!(FALLBACK_NO_OBSERVATION, "no_observation_by_deadline");
        assert_eq!(
            VALID_WEATHER_FALLBACK_REASONS,
            &[None, Some("no_observation_by_deadline")]
        );
    }

    #[test]
    fn round_publishing_exactly_at_the_bound_takes_that_hour() {
        let r = round_at(H + W_SECS + PUBLISH_MARGIN_SECS);
        assert_eq!(weather_time_for_round(r), Some(H));
    }

    #[test]
    fn one_round_before_the_bound_takes_the_previous_hour() {
        let r = round_at(H + W_SECS + PUBLISH_MARGIN_SECS);
        assert_eq!(weather_time_for_round(r - 1), Some(H - 3600));
    }

    #[test]
    fn last_round_before_the_next_bound_keeps_the_hour() {
        let r = round_at(H + 3600 + W_SECS + PUBLISH_MARGIN_SECS);
        assert_eq!(weather_time_for_round(r - 1), Some(H));
    }

    #[test]
    fn weather_time_is_always_a_whole_hour() {
        for r in [1u64, 1000, 32_693_812, 32_694_631, 32_694_632] {
            let wt = weather_time_for_round(r).unwrap();
            assert_eq!(wt.rem_euclid(3600), 0, "round {r}");
            let published = quicknet_round_time(r).unwrap();
            assert!(wt + W_SECS + PUBLISH_MARGIN_SECS <= published, "round {r}");
            assert!(
                wt + 3600 + W_SECS + PUBLISH_MARGIN_SECS > published,
                "round {r}"
            );
        }
    }

    #[test]
    fn round_zero_has_no_weather_time() {
        assert_eq!(weather_time_for_round(0), None);
    }

    #[test]
    fn latest_lock_is_the_offset_before_the_hour() {
        assert_eq!(latest_lock_at(H), Some(H - 46 * 60));
    }

    #[test]
    fn latest_lock_fails_closed_on_underflow() {
        assert_eq!(latest_lock_at(i64::MIN), None);
    }

    #[test]
    fn grammar_accepts_canonical_values() {
        assert_eq!(
            parse_weather_value("184;1021;51;4114"),
            Ok(WeatherValue {
                t: 184,
                mslp: 1021,
                rh: 51,
                vis: 4114
            })
        );
        assert_eq!(
            parse_weather_value("-35;998;100;0"),
            Ok(WeatherValue {
                t: -35,
                mslp: 998,
                rh: 100,
                vis: 0
            })
        );
        assert!(parse_weather_value("0;850;0;10000").is_ok());
        assert!(parse_weather_value("-900;1100;0;0").is_ok());
        assert!(parse_weather_value("600;1100;100;10000").is_ok());
    }

    #[test]
    fn grammar_rejects_malformed_values() {
        for bad in [
            "",
            "184;1021;51",
            "184;1021;51;4114;1",
            ";;;",
            "0184;1021;51;4114",
            "184;01021;51;4114",
            "-0;1021;51;4114",
            "184;-1021;51;4114",
            "184;1021;-51;4114",
            "184;1021;51;-4114",
            "+184;1021;51;4114",
            "18.4;1021;51;4114",
            "1e2;1021;51;4114",
            " 184;1021;51;4114",
            "184;1021;51;4114 ",
            "184,1021,51,4114",
            "１８４;1021;51;4114",
            "--1;1021;51;4114",
            "-;1021;51;4114",
            "1234567;1021;51;4114",
            "184;1021;051;4114",
            "184;1021;51;04114",
            "00;1021;51;4114",
            "-00;1021;51;4114",
            "184;1021;51;-0",
            "184;;51;4114",
        ] {
            assert!(parse_weather_value(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn grammar_rejects_out_of_bounds_values() {
        for bad in [
            "601;1021;51;4114",
            "-901;1021;51;4114",
            "184;849;51;4114",
            "184;1101;51;4114",
            "184;1021;101;4114",
            "184;1021;51;10001",
        ] {
            assert!(parse_weather_value(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn grammar_rejects_overlong_values() {
        let long = format!("184;1021;51;4114{}", ";".repeat(WEATHER_VALUE_MAX_LEN));
        assert!(
            parse_weather_value(&long)
                .unwrap_err()
                .contains("longer than")
        );
    }

    #[test]
    fn format_canonical_renders_known_instants() {
        assert_eq!(format_canonical(H, 0), "2026-10-01T19:00:00.000000Z");
        assert_eq!(
            format_canonical(1_692_806_364, 0),
            "2023-08-23T15:59:24.000000Z"
        );
        assert_eq!(format_canonical(0, 1), "1970-01-01T00:00:00.000001Z");
        assert_eq!(
            format_canonical(951_782_400, 0),
            "2000-02-29T00:00:00.000000Z"
        );
    }

    #[test]
    fn format_canonical_round_trips_through_the_parser() {
        for (secs, micros) in [(H, 0), (H - 1, 999_999), (1_692_803_367, 123_456)] {
            let s = format_canonical(secs, micros);
            let parsed = chrono_parse_canonical(&s).unwrap();
            assert_eq!(parsed.timestamp(), secs);
            assert_eq!(parsed.subsec_micros(), micros as i64);
            assert_eq!(parsed.timestamp_micros(), secs * 1_000_000 + micros as i64);
        }
    }

    #[test]
    fn parse_weather_time_accepts_a_whole_hour() {
        assert_eq!(parse_weather_time("2026-10-01T19:00:00.000000Z"), Ok(H));
    }

    #[test]
    fn parse_weather_time_rejects_part_hours() {
        for bad in [
            "2026-10-01T19:30:00.000000Z",
            "2026-10-01T19:00:01.000000Z",
            "2026-10-01T19:00:00.000001Z",
        ] {
            assert!(
                parse_weather_time(bad)
                    .unwrap_err()
                    .contains("whole UTC hour"),
                "{bad}"
            );
        }
    }

    #[test]
    fn parse_weather_time_rejects_out_of_range_fields() {
        for bad in [
            "2026-10-01T18:60:00.000000Z",
            "2026-09-31T19:00:00.000000Z",
            "2026-10-01T24:00:00.000000Z",
            "2026-13-01T19:00:00.000000Z",
        ] {
            assert!(
                parse_weather_time(bad)
                    .unwrap_err()
                    .contains("valid calendar time"),
                "{bad}"
            );
        }
    }

    #[test]
    fn parse_weather_time_rejects_fields_that_would_wrap() {
        for bad in [
            "2026-00-01T00:00:00.000000Z",
            "2026-10-00T00:00:00.000000Z",
            "2026-10-99T00:00:00.000000Z",
            "2026-02-29T00:00:00.000000Z",
            "2026-12-31T23:59:60.000000Z",
        ] {
            assert!(
                parse_weather_time(bad)
                    .unwrap_err()
                    .contains("valid calendar time"),
                "{bad}"
            );
        }
    }

    #[test]
    fn parse_weather_time_accepts_a_leap_day() {
        assert_eq!(
            parse_weather_time("2024-02-29T00:00:00.000000Z"),
            Ok(1_709_164_800)
        );
    }

    #[test]
    fn parse_weather_time_rejects_non_canonical_text() {
        for bad in [
            "2026-10-01T19:00:00Z",
            "2026-10-01T19:00:00.000000+00:00",
            "",
        ] {
            assert!(parse_weather_time(bad).is_err(), "accepted {bad:?}");
        }
    }

    /// `row_to_value` of one row given as JSON members, verbatim (for
    /// example `"temperature":18.38,"mslp":1021`). Values hold no commas.
    fn value_of(fields: &str) -> Result<String, String> {
        let members: Vec<(&str, &str)> = fields
            .split(',')
            .map(|m| {
                let (k, v) = m.split_once(':').expect("member has a colon");
                (k.trim_matches('"'), v)
            })
            .collect();
        row_to_value(|f| members.iter().find(|(k, _)| *k == f).map(|(_, v)| *v))
    }

    #[test]
    fn scale_decimal_rounds_half_away_from_zero_from_the_text() {
        assert_eq!(scale_decimal("19.59", 1, false), Ok(196));
        assert_eq!(scale_decimal("19.55", 1, false), Ok(196));
        assert_eq!(scale_decimal("19.549", 1, false), Ok(195));
        assert_eq!(scale_decimal("19.54", 1, false), Ok(195));
        assert_eq!(scale_decimal("18.38", 1, false), Ok(184));
        assert_eq!(scale_decimal("7", 1, false), Ok(70));
        assert_eq!(scale_decimal("0.0", 1, false), Ok(0));
        assert_eq!(scale_decimal("1021", 0, true), Ok(1021));
        assert_eq!(scale_decimal("1021.0", 0, true), Ok(1021));
    }

    #[test]
    fn scale_decimal_negative_half_rounds_away_from_zero() {
        assert_eq!(scale_decimal("-0.05", 1, false), Ok(-1));
        assert_eq!(scale_decimal("-0.04", 1, false), Ok(0));
        assert_eq!(scale_decimal("-0.0", 1, false), Ok(0));
        assert_eq!(scale_decimal("-3.45", 1, false), Ok(-35));
        assert_eq!(scale_decimal("-12.35", 1, false), Ok(-124));
        // Never "-0".
        assert_eq!(scale_decimal("-0.04", 1, false).unwrap().to_string(), "0");
    }

    #[test]
    fn scale_decimal_rejects_non_plain_decimals() {
        for bad in [
            "1e2",
            "1.0E2",
            "NaN",
            "",
            "-",
            ".5",
            "5.",
            "\"18.3\"",
            "null",
            "+1",
            "1021.5",
            "1234567890123456",
        ] {
            assert!(scale_decimal(bad, 0, true).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn visibility_must_be_whole_metres() {
        assert_eq!(decametres("41140.0"), Ok(4114));
        assert_eq!(decametres("41140"), Ok(4114));
        assert_eq!(decametres("25"), Ok(3));
        assert_eq!(decametres("24"), Ok(2));
        assert_eq!(decametres("0"), Ok(0));
        for bad in ["41140.5", "41140.04", "4.114e4", "\"41140\""] {
            assert!(decametres(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn visibility_must_not_carry_a_minus_sign() {
        for bad in ["-0", "-4", "-0.0", "-25", "-41140.0"] {
            assert!(
                decametres(bad)
                    .unwrap_err()
                    .contains("must not be negative"),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn row_to_value_follows_the_grammar() {
        assert_eq!(
            value_of(
                r#""datetime":"2026-10-01T19:00:00Z","temperature":18.38,"mslp":1021,"humidity":51,"visibility":41140.0,"wind_speed":7.4,"weather_code":1"#
            ),
            Ok("184;1021;51;4114".to_string())
        );
    }

    #[test]
    fn row_with_a_missing_or_null_field_is_invalid() {
        let missing = value_of(r#""temperature":18.38,"mslp":1021,"visibility":41140.0"#);
        assert!(missing.unwrap_err().contains("humidity is missing"));
        let null = value_of(r#""temperature":null,"mslp":1021,"humidity":51,"visibility":41140.0"#);
        assert!(null.unwrap_err().contains("temperature is null"));
    }

    #[test]
    fn a_minus_sign_invalidates_mslp_humidity_and_visibility_even_on_zero() {
        for (fields, field) in [
            (
                r#""temperature":1.0,"mslp":-0,"humidity":50,"visibility":1000"#,
                "mslp",
            ),
            (
                r#""temperature":1.0,"mslp":-4,"humidity":50,"visibility":1000"#,
                "mslp",
            ),
            (
                r#""temperature":1.0,"mslp":-0.0,"humidity":50,"visibility":1000"#,
                "mslp",
            ),
            (
                r#""temperature":1.0,"mslp":1000,"humidity":-0,"visibility":1000"#,
                "humidity",
            ),
            (
                r#""temperature":1.0,"mslp":1000,"humidity":-4,"visibility":1000"#,
                "humidity",
            ),
            (
                r#""temperature":1.0,"mslp":1000,"humidity":-0.0,"visibility":1000"#,
                "humidity",
            ),
            (
                r#""temperature":1.0,"mslp":1000,"humidity":50,"visibility":-0"#,
                "visibility",
            ),
            (
                r#""temperature":1.0,"mslp":1000,"humidity":50,"visibility":-4"#,
                "visibility",
            ),
            (
                r#""temperature":1.0,"mslp":1000,"humidity":50,"visibility":-0.0"#,
                "visibility",
            ),
        ] {
            let err = value_of(fields).unwrap_err();
            assert!(
                err.starts_with(&format!("{field}: ")) && err.contains("must not be negative"),
                "{fields}: {err}"
            );
        }
    }

    #[test]
    fn temperature_keeps_its_signed_rules() {
        let t = |text: &str| {
            value_of(&format!(
                r#""temperature":{text},"mslp":1000,"humidity":50,"visibility":1000"#
            ))
        };
        assert_eq!(t("-0.04"), Ok("0;1000;50;100".to_string()));
        assert_eq!(t("-0.05"), Ok("-1;1000;50;100".to_string()));
        assert_eq!(t("-0"), Ok("0;1000;50;100".to_string()));
        assert_eq!(t("-0.0"), Ok("0;1000;50;100".to_string()));
        assert_eq!(t("-4"), Ok("-40;1000;50;100".to_string()));
    }

    #[test]
    fn from_row_edge_cases() {
        let ok = |fields: &str, want: &str| {
            assert_eq!(value_of(fields), Ok(want.to_string()), "{fields}")
        };
        let invalid = |fields: &str, field: &str| {
            let err = value_of(fields).unwrap_err();
            assert!(err.contains(field), "{fields}: {err}");
        };
        let out_of_bounds = |fields: &str| assert!(value_of(fields).is_err(), "accepted {fields}");

        // Temperature: tenths, half away from zero, from the decimal text.
        ok(
            r#""temperature":19.55,"mslp":1000,"humidity":50,"visibility":1000"#,
            "196;1000;50;100",
        );
        ok(
            r#""temperature":-0.05,"mslp":1000,"humidity":50,"visibility":1000"#,
            "-1;1000;50;100",
        );
        ok(
            r#""temperature":-0.04,"mslp":1000,"humidity":50,"visibility":1000"#,
            "0;1000;50;100",
        );
        ok(
            r#""temperature":-0.0,"mslp":1000,"humidity":50,"visibility":1000"#,
            "0;1000;50;100",
        );

        // Visibility: whole metres only, then decametres half away from zero.
        ok(
            r#""temperature":1.0,"mslp":1000,"humidity":50,"visibility":25"#,
            "10;1000;50;3",
        );
        ok(
            r#""temperature":1.0,"mslp":1000,"humidity":50,"visibility":24320.0"#,
            "10;1000;50;2432",
        );
        invalid(
            r#""temperature":1.0,"mslp":1000,"humidity":50,"visibility":41140.5"#,
            "visibility",
        );

        // mslp and humidity: whole numbers only.
        ok(
            r#""temperature":1.0,"mslp":1021.0,"humidity":50,"visibility":1000"#,
            "10;1021;50;100",
        );
        invalid(
            r#""temperature":1.0,"mslp":1020.4,"humidity":50,"visibility":1000"#,
            "mslp",
        );
        invalid(
            r#""temperature":1.0,"mslp":1000,"humidity":76.5,"visibility":1000"#,
            "humidity",
        );

        // An exponent invalidates the field it is in, and only that field.
        invalid(
            r#""temperature":1.959e1,"mslp":1000,"humidity":50,"visibility":1000"#,
            "temperature",
        );
        invalid(
            r#""temperature":1.0,"mslp":1.0E3,"humidity":50,"visibility":1000"#,
            "mslp",
        );
        invalid(
            r#""temperature":1.0,"mslp":1000,"humidity":50,"visibility":4.114e4"#,
            "visibility",
        );
        ok(
            r#""temperature":1.0,"mslp":1000,"humidity":50,"visibility":1000,"wind_speed":7.4e0"#,
            "10;1000;50;100",
        );

        // A string is not a number.
        invalid(
            r#""temperature":1.0,"mslp":1000,"humidity":"50","visibility":1000"#,
            "humidity",
        );

        // Bounds apply to the canonical parts, after rounding.
        ok(
            r#""temperature":60.04,"mslp":1000,"humidity":50,"visibility":1000"#,
            "600;1000;50;100",
        );
        out_of_bounds(r#""temperature":60.05,"mslp":1000,"humidity":50,"visibility":1000"#);
        ok(
            r#""temperature":-90.04,"mslp":1000,"humidity":50,"visibility":1000"#,
            "-900;1000;50;100",
        );
        out_of_bounds(r#""temperature":-90.05,"mslp":1000,"humidity":50,"visibility":1000"#);
        ok(
            r#""temperature":1.0,"mslp":850,"humidity":0,"visibility":0"#,
            "10;850;0;0",
        );
        out_of_bounds(r#""temperature":1.0,"mslp":849,"humidity":50,"visibility":1000"#);
        ok(
            r#""temperature":1.0,"mslp":1100,"humidity":100,"visibility":100004"#,
            "10;1100;100;10000",
        );
        out_of_bounds(r#""temperature":1.0,"mslp":1101,"humidity":50,"visibility":1000"#);
        out_of_bounds(r#""temperature":1.0,"mslp":1000,"humidity":101,"visibility":1000"#);
        out_of_bounds(r#""temperature":1.0,"mslp":1000,"humidity":50,"visibility":100005"#);
    }

    /// The facts the fallback rule relies on, for every draw second of the
    /// hour: pub = wt + 1860 + d, d in 0..=3597 step 3.
    #[test]
    fn both_stores_settle_before_drand_for_every_draw_second() {
        use crate::protocol::freq_v1;
        const GENESIS: i64 = 1_692_803_367;
        // 2026-10-25T00:00Z, 01:00Z (clock change), 2026-03-29T00:00Z, 2026-12-31T23:00Z.
        for wt in [
            1_792_886_400_i64,
            1_792_890_000,
            1_774_742_400,
            1_798_758_000,
        ] {
            for d in (0..=3597_i64).step_by(3) {
                let pub_ = wt + 1860 + d;
                let round = u64::try_from((pub_ - GENESIS) / 3 + 1).unwrap();
                assert_eq!(
                    crate::drand::quicknet_round_time(round),
                    Some(pub_),
                    "d={d}"
                );
                assert_eq!(weather_time_for_round(round), Some(wt), "d={d}");
                let t = freq_v1::freq_start_for_round(round).unwrap();
                let f = wt + W_SECS;
                let f_freq = t + freq_v1::SPAN_SECS + freq_v1::W_FREQ_SECS;
                assert_eq!(t, wt + 1500 + d - d % 15, "d={d}");
                assert!(f_freq - f >= 45, "d={d}");
                assert!(f + 60 <= pub_, "d={d}");
                assert!(f_freq + freq_v1::MARGIN_SECS <= pub_, "d={d}");
                assert!(
                    latest_lock_at(wt).unwrap() <= t - freq_v1::LOCK_GAP_SECS,
                    "d={d}"
                );
                assert!(t >= wt + 25 * 60, "d={d}");
            }
        }
    }
}
