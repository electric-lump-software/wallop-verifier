use wallop_verifier::protocol::landobs_v1::parse_weather_value;

use super::Outcome;

/// The WMO block number of a tagged station: `wmo-03749` -> `03749`.
pub(crate) fn block_for(station: &str) -> Result<&str, String> {
    station
        .strip_prefix("wmo-")
        .filter(|b| b.len() == 5 && b.bytes().all(|c| c.is_ascii_digit()))
        .ok_or_else(|| format!("{station} is not a WMO station"))
}

/// `2026-10-01T19:00:00.000000Z` -> `202610011900`.
/// Requires a `weather_time` that has passed `landobs_v1::parse_weather_time`.
pub(crate) fn ogimet_hour(weather_time: &str) -> String {
    format!(
        "{}{}{}{}{}",
        &weather_time[0..4],
        &weather_time[5..7],
        &weather_time[8..10],
        &weather_time[11..13],
        &weather_time[14..16]
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
    // Anything outside 850.0..=1100.0 hPa is not a sea-level pressure
    // (for example a high-altitude station's 4a3hhh height group).
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
        return Outcome::Unavailable("no SYNOP for this hour".into());
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
                    Outcome::Match(format!("t {t}, mslp {mslp}"))
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
pub(crate) fn presence(body: Option<&str>, station: &str, weather_time: &str) -> Outcome {
    let Some(body) = body else {
        return Outcome::Absent("no SYNOP for this hour".into());
    };
    match reading_for(body, station, weather_time) {
        Err(e) => Outcome::Unavailable(e),
        Ok(None) => Outcome::Unavailable("response has no report for this station and hour".into()),
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
    fn ogimet_hour_and_block() {
        assert_eq!(ogimet_hour(WT), "202610011900");
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
    fn check_compares_t_and_rounded_mslp() {
        assert!(matches!(
            check(Some(BODY), "wmo-03749", WT, "184;1021;51;4114"),
            Outcome::Match(_)
        ));
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
        assert!(matches!(
            presence(None, "wmo-03749", WT),
            Outcome::Absent(_)
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
