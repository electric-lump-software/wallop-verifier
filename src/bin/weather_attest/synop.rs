use wallop_verifier::protocol::landobs_v1::{parse_weather_time, parse_weather_value};

use super::Outcome;

/// The WMO block number of a tagged station: `wmo-03749` -> `03749`.
pub(crate) fn block_for(station: &str) -> Result<&str, String> {
    station
        .strip_prefix("wmo-")
        .filter(|b| b.len() == 5 && b.bytes().all(|c| c.is_ascii_digit()))
        .ok_or_else(|| format!("{station} is not a WMO station"))
}

/// Ogimet is asked for this many seconds either side of the wanted hour,
/// in the same single request, so a missing report can be told apart from
/// a station Ogimet holds nothing for.
const WINDOW_SECS: i64 = 3 * 3600;

const NONE_AROUND: &str = "Ogimet has no reports for this station around this hour";

/// Unix seconds as Ogimet's `YYYYMMDDHHmm` (UTC).
fn ogimet_stamp(unix: i64) -> String {
    // Days to civil date: Howard Hinnant's `civil_from_days`.
    let z = unix.div_euclid(86_400) + 719_468;
    let secs = unix.rem_euclid(86_400);
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}{:02}{:02}",
        secs / 3600,
        secs % 3600 / 60
    )
}

/// `(begin, end)` for the Ogimet query: three hours either side of the
/// wanted hour, as `YYYYMMDDHHmm`.
pub(crate) fn ogimet_window(weather_time_unix: i64) -> (String, String) {
    (
        ogimet_stamp(weather_time_unix - WINDOW_SECS),
        ogimet_stamp(weather_time_unix + WINDOW_SECS),
    )
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SynopReading {
    /// `1snTTT`: temperature, tenths of a degree C.
    pub t_tenths: Option<i64>,
    /// `4PPPP`: mean sea-level pressure, tenths of hPa.
    pub mslp_tenths: Option<i64>,
    /// The report is `NIL`: no observation.
    pub nil: bool,
}

/// Requires a `weather_time` that has passed `landobs_v1::parse_weather_time`.
fn find_report<'a>(body: &'a str, block: &str, weather_time: &str) -> Option<&'a str> {
    let prefix = format!(
        "{block},{},{},{},{},{},",
        &weather_time[0..4],
        &weather_time[5..7],
        &weather_time[8..10],
        &weather_time[11..13],
        &weather_time[14..16]
    );
    body.lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
}

/// The `YYYYMMDDHHmm` of a body line holding a land SYNOP for `block`.
fn report_stamp(line: &str, block: &str) -> Option<String> {
    let mut fields = line.splitn(7, ',');
    if fields.next()? != block {
        return None;
    }
    let mut stamp = String::with_capacity(12);
    for len in [4, 2, 2, 2, 2] {
        let f = fields.next()?;
        if f.len() != len || !f.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        stamp.push_str(f);
    }
    fields
        .next()?
        .trim_start()
        .starts_with("AAXX")
        .then_some(stamp)
}

/// Whether `body` holds any land SYNOP for `station` inside the query
/// window, which shows Ogimet does hold reports for it around this hour.
fn reports_around(body: &str, station: &str, weather_time: &str) -> bool {
    let (Ok(block), Ok(unix)) = (block_for(station), parse_weather_time(weather_time)) else {
        return false;
    };
    let (begin, end) = ogimet_window(unix);
    body.lines()
        .filter_map(|line| report_stamp(line, block))
        .any(|stamp| begin <= stamp && stamp <= end)
}

/// Read the temperature and pressure groups from section 1 of a land
/// SYNOP (`AAXX YYGGi IIiii iRixhVV Nddff [00fff] 1snTTT … 4PPPP …`),
/// stopping at section 2 (`222Dv`), 3 (`333`), 4 (`444`) or 5 (`555`).
pub(crate) fn parse_section1(report: &str, block: &str) -> Result<SynopReading, String> {
    let groups: Vec<&str> = report
        .trim()
        .trim_end_matches('=')
        .split_whitespace()
        .collect();
    if groups.first() != Some(&"AAXX") {
        return Err("report is not a land SYNOP (AAXX)".into());
    }
    if groups.get(2) != Some(&block) {
        return Err(format!(
            "report is for station {:?}, not {block}",
            groups.get(2)
        ));
    }
    if groups.get(3) == Some(&"NIL") {
        return Ok(SynopReading {
            nil: true,
            ..SynopReading::default()
        });
    }
    let nddff = groups.get(4).ok_or("report is truncated")?;
    let mut start = 5;
    if nddff.is_ascii() && nddff.len() == 5 && &nddff[3..] == "99" {
        start += 1;
    }
    let mut reading = SynopReading::default();
    for g in groups.iter().skip(start) {
        let section_2 = g.len() == 5 && g.starts_with("222");
        if section_2 || *g == "333" || *g == "444" || *g == "555" {
            break;
        }
        if g.len() != 5 || !g.is_ascii() {
            continue;
        }
        match g.as_bytes()[0] {
            b'1' if reading.t_tenths.is_none() => reading.t_tenths = temperature(g),
            b'4' if reading.mslp_tenths.is_none() => reading.mslp_tenths = pressure(g),
            _ => {}
        }
    }
    Ok(reading)
}

fn temperature(g: &str) -> Option<i64> {
    let sign = match &g[1..2] {
        "0" => 1,
        "1" => -1,
        _ => return None,
    };
    let digits = &g[2..5];
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(sign * digits.parse::<i64>().ok()?)
}

fn pressure(g: &str) -> Option<i64> {
    let digits = &g[1..5];
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let v: i64 = digits.parse().ok()?;
    // The thousands digit is omitted: 0203 is 1020.3 hPa, 9987 is 998.7.
    let tenths = if v < 5000 { 10_000 + v } else { v };
    // Backstop only: a high-altitude station (which sends 4a3hhh, not
    // 4PPPP) would need a new tag. Outside 850.0..=1100.0 hPa is rejected.
    (8_500..=11_000).contains(&tenths).then_some(tenths)
}

/// Requires a `weather_time` that has passed `landobs_v1::parse_weather_time`.
fn reading_for(
    body: &str,
    station: &str,
    weather_time: &str,
) -> Result<Option<SynopReading>, String> {
    let block = block_for(station)?;
    match find_report(body, block, weather_time) {
        None => Ok(None),
        Some(report) => parse_section1(report, block).map(Some),
    }
}

/// Requires a `weather_time` that has passed `landobs_v1::parse_weather_time`.
pub(crate) fn check(body: Option<&str>, station: &str, weather_time: &str, value: &str) -> Outcome {
    let Some(body) = body else {
        return Outcome::Unavailable(NONE_AROUND.into());
    };
    let expected = match parse_weather_value(value) {
        Ok(v) => v,
        Err(e) => return Outcome::Mismatch(format!("receipt value is invalid: {e}")),
    };
    match reading_for(body, station, weather_time) {
        Err(e) => Outcome::Unavailable(e),
        Ok(None) => Outcome::Unavailable("response has no report for this station and hour".into()),
        Ok(Some(r)) => match (r.t_tenths, r.mslp_tenths) {
            (Some(t), Some(p)) => {
                let mslp = (p + 5) / 10;
                if t == expected.t && mslp == expected.mslp {
                    Outcome::Match(format!("t, mslp only: t {t}, mslp {mslp}"))
                } else {
                    Outcome::Mismatch(format!(
                        "SYNOP t {t}, mslp {mslp}; receipt t {}, mslp {}",
                        expected.t, expected.mslp
                    ))
                }
            }
            _ => Outcome::Unavailable("SYNOP has no temperature or pressure group".into()),
        },
    }
}

/// Requires a `weather_time` that has passed `landobs_v1::parse_weather_time`.
///
/// ABSENT for a missing hour only when Ogimet holds other reports for the
/// same station inside the window; otherwise it can't tell: UNAVAILABLE.
pub(crate) fn presence(body: Option<&str>, station: &str, weather_time: &str) -> Outcome {
    let Some(body) = body else {
        return Outcome::Unavailable(NONE_AROUND.into());
    };
    match reading_for(body, station, weather_time) {
        Err(e) => Outcome::Unavailable(e),
        Ok(None) if reports_around(body, station, weather_time) => {
            Outcome::Absent("no SYNOP for this hour".into())
        }
        Ok(None) => Outcome::Unavailable(NONE_AROUND.into()),
        Ok(Some(r)) if r.nil => Outcome::Absent("SYNOP is NIL".into()),
        Ok(Some(r)) => match (r.t_tenths, r.mslp_tenths) {
            (Some(t), Some(p)) => Outcome::Present(format!("t {t}, mslp {}", (p + 5) / 10)),
            _ => Outcome::Absent("SYNOP has no temperature or pressure group".into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WT: &str = "2026-10-01T19:00:00.000000Z";
    const BODY: &str = "03749,2026,10,01,19,00,AAXX 01194 03749 25481 82109 10184 20156 30096 40210 52001 88/// 333 10177 20130 60002==\n";

    #[test]
    fn ogimet_window_and_block() {
        // 2026-10-01T19:00Z, three hours either side.
        assert_eq!(
            ogimet_window(1_790_881_200),
            ("202610011600".to_string(), "202610012200".to_string())
        );
        // Across a year boundary: 2026-01-01T01:00Z.
        assert_eq!(
            ogimet_window(1_767_229_200),
            ("202512312200".to_string(), "202601010400".to_string())
        );
        // Across a leap day: 2028-02-29T23:00Z.
        assert_eq!(
            ogimet_window(1_835_478_000),
            ("202802292000".to_string(), "202803010200".to_string())
        );
        assert_eq!(block_for("wmo-03749"), Ok("03749"));
        assert!(block_for("middle-wallop").is_err());
    }

    #[test]
    fn parses_temperature_and_pressure_from_section_1_only() {
        let r = parse_section1(
            "AAXX 15094 03749 25481 82109 10177 20156 30096 40203 52001 88/// 333 10199 20130 60002==",
            "03749",
        )
        .unwrap();
        assert_eq!(r.t_tenths, Some(177));
        assert_eq!(r.mslp_tenths, Some(10203));
    }

    #[test]
    fn parses_negative_temperature_and_low_pressure() {
        let r = parse_section1(
            "AAXX 01064 03749 46/50 /0000 11023 21045 39990 49987=",
            "03749",
        )
        .unwrap();
        assert_eq!(r.t_tenths, Some(-23));
        assert_eq!(r.mslp_tenths, Some(9987));
    }

    #[test]
    fn skips_the_extra_wind_group() {
        let r = parse_section1("AAXX 01064 03749 46/50 12099 00105 10100 40100=", "03749").unwrap();
        assert_eq!(r.t_tenths, Some(100));
        assert_eq!(r.mslp_tenths, Some(10100));
    }

    #[test]
    fn nil_and_missing_groups() {
        assert!(
            parse_section1("AAXX 01194 03749 NIL=", "03749")
                .unwrap()
                .nil
        );
        let r = parse_section1("AAXX 01194 03749 25481 82109 1//// 4////=", "03749").unwrap();
        assert_eq!((r.t_tenths, r.mslp_tenths), (None, None));
    }

    #[test]
    fn stops_at_section_2() {
        let r = parse_section1("AAXX 01194 03749 25481 82109 22200 10184 40210=", "03749").unwrap();
        assert_eq!((r.t_tenths, r.mslp_tenths), (None, None));
    }

    #[test]
    fn stops_at_section_4() {
        let r = parse_section1("AAXX 01194 03749 25481 82109 444 10184 40210=", "03749").unwrap();
        assert_eq!((r.t_tenths, r.mslp_tenths), (None, None));
    }

    #[test]
    fn pressure_outside_850_to_1100_hpa_is_none() {
        // A high-altitude station reports 4a3hhh (geopotential height),
        // which would otherwise decode as an implausible pressure.
        let r = parse_section1("AAXX 01194 03749 25481 82109 10184 48499=", "03749").unwrap();
        assert_eq!(r.mslp_tenths, None);
        let r = parse_section1("AAXX 01194 03749 25481 82109 10184 41010=", "03749").unwrap();
        assert_eq!(r.mslp_tenths, None);
        let r = parse_section1("AAXX 01194 03749 25481 82109 10184 48500=", "03749").unwrap();
        assert_eq!(r.mslp_tenths, Some(8500));
        let r = parse_section1("AAXX 01194 03749 25481 82109 10184 41000=", "03749").unwrap();
        assert_eq!(r.mslp_tenths, Some(11000));
    }

    #[test]
    fn rejects_another_station_or_a_non_land_report() {
        assert!(parse_section1("AAXX 01194 03462 25481 82109 10184 40210=", "03749").is_err());
        assert!(parse_section1("BBXX 01194 03749 25481=", "03749").is_err());
    }

    #[test]
    fn check_uses_only_the_wanted_hours_report() {
        let neighbours = "03749,2026,10,01,18,00,AAXX 01184 03749 25481 82109 10184 40210=\n";
        assert!(matches!(
            check(Some(neighbours), "wmo-03749", WT, "184;1021;51;4114"),
            Outcome::Unavailable(_)
        ));
        let wrong_neighbour = "03749,2026,10,01,18,00,AAXX 01184 03749 25481 82109 10999 40999=\n";
        let body = format!("{wrong_neighbour}{BODY}");
        assert!(matches!(
            check(Some(&body), "wmo-03749", WT, "184;1021;51;4114"),
            Outcome::Match(_)
        ));
    }

    #[test]
    fn check_compares_t_and_rounded_mslp() {
        assert_eq!(
            check(Some(BODY), "wmo-03749", WT, "184;1021;51;4114"),
            Outcome::Match("t, mslp only: t 184, mslp 1021".into())
        );
        assert!(matches!(
            check(Some(BODY), "wmo-03749", WT, "183;1021;51;4114"),
            Outcome::Mismatch(_)
        ));
        assert!(matches!(
            check(Some(BODY), "wmo-03749", WT, "184;1022;51;4114"),
            Outcome::Mismatch(_)
        ));
        assert!(matches!(
            check(None, "wmo-03749", WT, "184;1021;51;4114"),
            Outcome::Unavailable(_)
        ));
        assert!(matches!(
            check(
                Some("Sorry, too many requests"),
                "wmo-03749",
                WT,
                "184;1021;51;4114"
            ),
            Outcome::Unavailable(_)
        ));
    }

    #[test]
    fn presence_distinguishes_absent_from_unavailable() {
        assert!(matches!(
            presence(Some(BODY), "wmo-03749", WT),
            Outcome::Present(_)
        ));
        let none_around = |o: &Outcome| matches!(o, Outcome::Unavailable(r) if r == "Ogimet has no reports for this station around this hour");
        // Nothing in the window at all: Ogimet can't tell us.
        assert!(none_around(&presence(None, "wmo-03749", WT)));
        // Reports only for another station: still can't tell.
        let other = "03462,2026,10,01,18,00,AAXX 01184 03462 25481 82109 10184 40210=\n";
        assert!(none_around(&presence(Some(other), "wmo-03749", WT)));
        // The station reported either side of the hour but not at it.
        let around = "03749,2026,10,01,18,00,AAXX 01184 03749 25481 82109 10184 40210=\n\
                      03749,2026,10,01,20,00,AAXX 01204 03749 25481 82109 10184 40210=\n";
        assert!(
            matches!(presence(Some(around), "wmo-03749", WT), Outcome::Absent(_)),
            "{:?}",
            presence(Some(around), "wmo-03749", WT)
        );
        // A neighbouring report outside the window proves nothing.
        let far = "03749,2026,10,01,23,00,AAXX 01234 03749 25481 82109 10184 40210=\n";
        assert!(none_around(&presence(Some(far), "wmo-03749", WT)));
        // The wanted hour, among neighbours, is still found.
        let with_wanted = format!("{around}{BODY}");
        assert!(matches!(
            presence(Some(&with_wanted), "wmo-03749", WT),
            Outcome::Present(_)
        ));
        let nil = "03749,2026,10,01,19,00,AAXX 01194 03749 NIL=\n";
        assert!(matches!(
            presence(Some(nil), "wmo-03749", WT),
            Outcome::Absent(_)
        ));
        assert!(matches!(
            presence(Some("<html>error</html>"), "wmo-03749", WT),
            Outcome::Unavailable(_)
        ));
    }
}
