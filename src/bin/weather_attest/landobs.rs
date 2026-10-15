use std::collections::BTreeMap;

use serde_json::value::RawValue;
use wallop_verifier::protocol::landobs_v1::parse_weather_value;

use super::Outcome;

/// One Land Observations row, with each value kept as its JSON text so
/// numbers are rounded from their decimal digits, never through a float.
pub(crate) type Row = BTreeMap<String, Box<RawValue>>;

/// Land Observations location for each tagged station. The API response
/// carries no station identifier, so this table is the only link between
/// a geohash and a WMO station. It is not part of the signed protocol.
pub(crate) const GEOHASHES: [(&str, &str); 2] = [("wmo-03749", "gcnfur"), ("wmo-03462", "gcrem9")];

pub(crate) fn geohash_for(station: &str) -> Option<&'static str> {
    GEOHASHES
        .iter()
        .find(|(s, _)| *s == station)
        .map(|(_, g)| *g)
}

/// Round the plain decimal `text` times 10^`shift` to an integer, half
/// away from zero (19.55 -> 196, -0.05 -> -1, -0.04 -> 0, never "-0").
/// With `exact`, any digits that would be rounded away must be zero.
/// Exponents, NaN, quotes and signs other than a leading `-` are rejected.
pub(crate) fn scale_decimal(text: &str, shift: i32, exact: bool) -> Result<i64, String> {
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

fn number<'a>(row: &'a Row, field: &str) -> Result<&'a str, String> {
    let text = row
        .get(field)
        .ok_or_else(|| format!("{field} is missing"))?
        .get();
    if text == "null" {
        Err(format!("{field} is null"))
    } else {
        Ok(text)
    }
}

/// Visibility in metres as decametres. The metres must be a whole number:
/// a fractional value is invalid, never rounded to whole metres. The
/// division by 10 rounds half away from zero (25 m -> 3).
pub(crate) fn decametres(text: &str) -> Result<i64, String> {
    let metres = scale_decimal(text, 0, true)?;
    let q = (metres.abs() + 5) / 10;
    Ok(if metres < 0 { -q } else { q })
}

/// The `weather_value` this row yields under the tag's rules, or why the
/// row is not a valid observation. The rules are per field, identical to
/// core: an exponent, a string, a null or a missing value in a required
/// field makes the row invalid; other fields are never read. Bounds are
/// checked on the canonical parts, after rounding.
pub(crate) fn row_to_value(row: &Row) -> Result<String, String> {
    let t = scale_decimal(number(row, "temperature")?, 1, false)
        .map_err(|e| format!("temperature: {e}"))?;
    let mslp = scale_decimal(number(row, "mslp")?, 0, true).map_err(|e| format!("mslp: {e}"))?;
    let rh =
        scale_decimal(number(row, "humidity")?, 0, true).map_err(|e| format!("humidity: {e}"))?;
    let vis = decametres(number(row, "visibility")?).map_err(|e| format!("visibility: {e}"))?;
    let value = format!("{t};{mslp};{rh};{vis}");
    parse_weather_value(&value)?;
    Ok(value)
}

/// Requires a `weather_time` that has passed `landobs_v1::parse_weather_time`.
fn row_for<'a>(rows: &'a [Row], weather_time: &str) -> Option<&'a Row> {
    // Rows are stamped "YYYY-MM-DDTHH:MM:SSZ".
    let want = format!("\"{}Z\"", &weather_time[..19]);
    rows.iter()
        .find(|r| r.get("datetime").map(|d| d.get()) == Some(want.as_str()))
}

/// Requires a `weather_time` that has passed `landobs_v1::parse_weather_time`.
pub(crate) fn check(rows: &[Row], weather_time: &str, value: &str) -> Outcome {
    match row_for(rows, weather_time) {
        None => Outcome::Unavailable(format!("no row for {}", &weather_time[..16])),
        Some(row) => match row_to_value(row) {
            Ok(record) if record == value => Outcome::Match(record),
            Ok(record) => Outcome::Mismatch(format!("record {record}, receipt {value}")),
            // Core would have stored nothing from this row, so it can't
            // confirm the receipt either way.
            Err(e) => Outcome::Unavailable(format!("record row is not a valid observation: {e}")),
        },
    }
}

/// Requires a `weather_time` that has passed `landobs_v1::parse_weather_time`.
pub(crate) fn presence(rows: &[Row], weather_time: &str) -> Outcome {
    match row_for(rows, weather_time) {
        None => Outcome::Absent(format!("no row for {}", &weather_time[..16])),
        Some(row) => match row_to_value(row) {
            Ok(value) => Outcome::Present(value),
            Err(e) => Outcome::Absent(format!("row present but not a valid observation: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(json: &str) -> Vec<Row> {
        serde_json::from_str(json).unwrap()
    }

    const WT: &str = "2026-10-01T19:00:00.000000Z";
    const ROW: &str = r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":18.38,"mslp":1021,"humidity":51,"visibility":41140.0,"wind_speed":7.4,"weather_code":1}]"#;

    #[test]
    fn every_station_has_a_geohash() {
        for station in wallop_verifier::protocol::landobs_v1::STATIONS {
            assert!(geohash_for(station).is_some(), "{station}");
        }
        assert_eq!(geohash_for("wmo-03749"), Some("gcnfur"));
        assert_eq!(geohash_for("wmo-03462"), Some("gcrem9"));
        assert_eq!(geohash_for("wmo-03772"), None);
    }

    /// `row_to_value` of one row built from `fields` (JSON members, verbatim).
    fn value_of(fields: &str) -> Result<String, String> {
        let row: Row = serde_json::from_str(&format!(
            r#"{{"datetime":"2026-10-01T19:00:00Z",{fields}}}"#
        ))
        .unwrap();
        row_to_value(&row)
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
        for bad in ["41140.5", "41140.04", "4.114e4", "\"41140\""] {
            assert!(decametres(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn row_to_value_follows_the_grammar() {
        assert_eq!(
            row_to_value(&rows(ROW)[0]),
            Ok("184;1021;51;4114".to_string())
        );
    }

    #[test]
    fn row_with_a_missing_or_null_field_is_invalid() {
        let missing = rows(
            r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":18.38,"mslp":1021,"visibility":41140.0}]"#,
        );
        assert!(row_to_value(&missing[0]).unwrap_err().contains("humidity"));
        let null = rows(
            r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":null,"mslp":1021,"humidity":51,"visibility":41140.0}]"#,
        );
        assert!(row_to_value(&null[0]).unwrap_err().contains("temperature"));
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

    #[test]
    fn an_invalid_record_row_is_unavailable_not_a_rounded_match() {
        let half_metre = rows(&ROW.replace("41140.0", "41140.5"));
        assert!(
            matches!(check(&half_metre, WT, "184;1021;51;4114"), Outcome::Unavailable(r) if r.contains("visibility"))
        );
    }

    #[test]
    fn check_matches_mismatches_and_misses() {
        assert!(matches!(
            check(&rows(ROW), WT, "184;1021;51;4114"),
            Outcome::Match(_)
        ));
        assert!(matches!(
            check(&rows(ROW), WT, "185;1021;51;4114"),
            Outcome::Mismatch(_)
        ));
        assert!(matches!(
            check(
                &rows(ROW),
                "2026-10-01T20:00:00.000000Z",
                "184;1021;51;4114"
            ),
            Outcome::Unavailable(_)
        ));
    }

    #[test]
    fn presence_needs_a_valid_row() {
        assert!(matches!(presence(&rows(ROW), WT), Outcome::Present(_)));
        assert!(matches!(presence(&rows("[]"), WT), Outcome::Absent(_)));
        let invalid = rows(r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":18.38}]"#);
        assert!(matches!(presence(&invalid, WT), Outcome::Absent(_)));
    }
}
