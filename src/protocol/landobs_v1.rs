//! Frozen rules for the `drand-quicknet+metoffice-landobs-v1` entropy tag,
//! carried by lock receipt schema 6 and execution receipt schema 5.
//!
//! The tag fixes every value in this module. Changing any of them needs a
//! new tag and, with it, new receipt schemas.

use crate::drand::quicknet_round_time;

/// The `entropy_composition` value of lock v6 and execution v5 receipts.
pub const ENTROPY_COMPOSITION: &str = "drand-quicknet+metoffice-landobs-v1";

/// Weather stations, in order. Every lock receipt names the first. An
/// execution receipt names the station whose observation was used.
/// `wmo-03749` is Middle Wallop; `wmo-03462` is Wittering, the backup.
pub const STATIONS: [&str; 2] = ["wmo-03749", "wmo-03462"];

/// The station every lock receipt names.
pub const PRIMARY_STATION: &str = STATIONS[0];

/// W, in seconds: the observation for `weather_time` may be fetched until
/// `weather_time + W_SECS`.
///
/// The value is provisional (40 minutes). Before the release that ships
/// this tag, it is set to the measured Land Observations publication
/// latency: p99 plus 10 minutes, capped at 90 minutes. Every derived value,
/// fixture and unit test follows this one constant.
pub const W_SECS: i64 = 40 * 60;

/// Gap between the end of the fetch window and the drand round's
/// publication.
pub const PUBLISH_MARGIN_SECS: i64 = 60;

/// The lock must be signed at least this long before `weather_time`.
pub const LOCK_OFFSET_SECS: i64 = 46 * 60;

/// The only reason an execution v5 receipt may give for having no weather.
pub const FALLBACK_NO_OBSERVATION: &str = "no_observation_by_deadline";

/// Allowed `weather_fallback_reason` values on an execution v5 receipt.
pub const VALID_WEATHER_FALLBACK_REASONS: &[Option<&str>] = &[None, Some(FALLBACK_NO_OBSERVATION)];

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drand::{QUICKNET_GENESIS_TIME, QUICKNET_PERIOD_SECS};

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
        assert_eq!(STATIONS, ["wmo-03749", "wmo-03462"]);
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
}
