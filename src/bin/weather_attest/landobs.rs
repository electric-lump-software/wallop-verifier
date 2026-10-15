use std::collections::BTreeMap;

use serde_json::value::RawValue;
use wallop_verifier::protocol::landobs_v1;

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

/// The `weather_value` this row yields under the tag's rules, or why the
/// row is not a valid observation. The grammar lives in
/// `landobs_v1::row_to_value`; this only hands it each field's JSON text.
fn row_to_value(row: &Row) -> Result<String, String> {
    landobs_v1::row_to_value(|field| row.get(field).map(|v| v.get()))
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

/// A row's `datetime` if it is exactly `YYYY-MM-DDTHH:MM:SSZ`. Stamps in
/// that one fixed shape sort as text in time order.
fn row_stamp(row: &Row) -> Option<&str> {
    let text = row.get("datetime")?.get();
    let stamp = text.strip_prefix('"')?.strip_suffix('"')?;
    let shape_ok = stamp.len() == 20
        && stamp.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            10 => b == b'T',
            13 | 16 => b == b':',
            19 => b == b'Z',
            _ => b.is_ascii_digit(),
        });
    let in_range = |range: std::ops::Range<usize>, lo: u8, hi: u8| {
        stamp[range]
            .parse::<u8>()
            .is_ok_and(|n| (lo..=hi).contains(&n))
    };
    (shape_ok && in_range(5..7, 1, 12) && in_range(8..10, 1, 31)).then_some(stamp)
}

/// Requires a `weather_time` that has passed `landobs_v1::parse_weather_time`.
///
/// ABSENT only when the rows reach back to (or before) the wanted hour, so
/// a missing row means the record really lacks it. Otherwise the hour may
/// simply have rolled off, and the record can't tell: UNAVAILABLE.
pub(crate) fn presence(rows: &[Row], weather_time: &str) -> Outcome {
    let want = format!("{}Z", &weather_time[..19]);
    let reaches_back = rows
        .iter()
        .filter_map(row_stamp)
        .any(|stamp| stamp <= want.as_str());
    match row_for(rows, weather_time) {
        None if !reaches_back => {
            Outcome::Unavailable("records no longer reach back to this hour".into())
        }
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

    #[test]
    fn row_to_value_reads_each_field_as_its_json_text() {
        assert_eq!(
            row_to_value(&rows(ROW)[0]),
            Ok("184;1021;51;4114".to_string())
        );
        let missing = rows(
            r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":18.38,"mslp":1021,"visibility":41140.0}]"#,
        );
        assert!(row_to_value(&missing[0]).unwrap_err().contains("humidity"));
        let null = rows(
            r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":null,"mslp":1021,"humidity":51,"visibility":41140.0}]"#,
        );
        assert!(row_to_value(&null[0]).unwrap_err().contains("temperature"));
        let negative_zero = rows(&ROW.replace("\"humidity\":51", "\"humidity\":-0"));
        assert!(
            row_to_value(&negative_zero[0])
                .unwrap_err()
                .contains("must not be negative")
        );
    }

    #[test]
    fn a_negative_zero_record_field_is_unavailable_not_a_match() {
        let negative_zero = rows(&ROW.replace("\"mslp\":1021", "\"mslp\":-0"));
        assert!(
            matches!(check(&negative_zero, WT, "184;0;51;4114"), Outcome::Unavailable(r) if r.contains("mslp"))
        );
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
        let invalid = rows(r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":18.38}]"#);
        assert!(matches!(presence(&invalid, WT), Outcome::Absent(_)));
    }

    #[test]
    fn presence_is_absent_only_when_the_rows_reach_back_to_the_hour() {
        let reaching = |r: &Outcome| matches!(r, Outcome::Unavailable(d) if d.contains("no longer reach back"));
        // Nothing at all: the record can't tell.
        assert!(
            reaching(&presence(&rows("[]"), WT)),
            "{:?}",
            presence(&rows("[]"), WT)
        );
        // Every row is later than the wanted hour: it has rolled off.
        let later = rows(&ROW.replace("19:00:00Z", "20:00:00Z"));
        assert!(
            reaching(&presence(&later, WT)),
            "{:?}",
            presence(&later, WT)
        );
        // Impossible months or days prove nothing either.
        for bad in [
            "2026-13-01T18:00:00Z",
            "2026-00-01T18:00:00Z",
            "2026-10-32T18:00:00Z",
            "2026-10-00T18:00:00Z",
        ] {
            let impossible = rows(&ROW.replace("2026-10-01T19:00:00Z", bad));
            assert!(
                reaching(&presence(&impossible, WT)),
                "{bad}: {:?}",
                presence(&impossible, WT)
            );
        }
        // Unreadable stamps prove nothing either.
        let junk = rows(&ROW.replace("2026-10-01T19:00:00Z", "yesterday"));
        assert!(reaching(&presence(&junk, WT)), "{:?}", presence(&junk, WT));
        // The rows cover the hour (one earlier, one later) but lack it.
        let covering = rows(&format!(
            "[{},{}]",
            &ROW.replace("19:00:00Z", "18:00:00Z")[1..ROW.len() - 1],
            &ROW.replace("19:00:00Z", "20:00:00Z")[1..ROW.len() - 1]
        ));
        assert!(
            matches!(presence(&covering, WT), Outcome::Absent(_)),
            "{:?}",
            presence(&covering, WT)
        );
        // A row at exactly the hour counts as reaching back.
        let at_hour = rows(r#"[{"datetime":"2026-10-01T19:00:00Z"}]"#);
        assert!(matches!(presence(&at_hour, WT), Outcome::Absent(_)));
    }
}
