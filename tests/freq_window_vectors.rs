//! Grid-frequency window vectors: raw Elexon FREQ bodies from wallop_core,
//! each with the `freq_value` of the window or the reason it is invalid.
//!
//! The vector file is `spec/vectors/freq-window-v1.json` in the wallop
//! repo. This test reads the vendored copy under `vendor/wallop`. Only when
//! that file is missing does it read the path in `WALLOP_FREQ_WINDOW_VECTORS`,
//! and it skips, saying so, when neither exists. It prints which file it
//! used.

use std::collections::HashMap;

use serde_json::value::RawValue;
use wallop_verifier::protocol::freq_v1::{format_freq_start, parse_freq_start, window_from_rows};

const ENV: &str = "WALLOP_FREQ_WINDOW_VECTORS";
const VENDORED: &str = "vendor/wallop/spec/vectors/freq-window-v1.json";

/// The vector file: the vendored copy, else the path in
/// `WALLOP_FREQ_WINDOW_VECTORS`, else `None` (with a message).
fn vector() -> Option<serde_json::Value> {
    let vendored = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VENDORED);
    let path = if vendored.is_file() {
        eprintln!(
            "freq window vectors: using the vendored file {}",
            vendored.display()
        );
        vendored
    } else if let Ok(path) = std::env::var(ENV) {
        eprintln!(
            "freq window vectors: {} is missing; using {ENV}={path}",
            vendored.display()
        );
        path.into()
    } else {
        eprintln!(
            "skipping: {} is missing and {ENV} is unset; set {ENV} to the path of \
             freq-window-v1.json to run",
            vendored.display()
        );
        return None;
    };
    let shown = path.display();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{shown}: {e}"));
    Some(serde_json::from_str(&text).unwrap_or_else(|e| panic!("{shown}: {e}")))
}

/// `body.data` as `(measurementTime, frequency JSON text)` rows, under the
/// row rule `window_from_rows` documents: non-objects are dropped, a
/// repeated key keeps its last value, an object without a string
/// `measurementTime` is dropped, and a missing `frequency` is `""`.
fn rows_from_body(body: &str) -> Vec<(String, String)> {
    #[derive(serde::Deserialize)]
    struct Body<'a> {
        #[serde(borrow)]
        data: Vec<&'a RawValue>,
    }
    let body: Body = serde_json::from_str(body).expect("body has a data list");
    body.data
        .into_iter()
        .filter_map(|item| {
            let row: HashMap<String, &RawValue> = serde_json::from_str(item.get()).ok()?;
            let time = serde_json::from_str::<String>(row.get("measurementTime")?.get()).ok()?;
            let freq = row.get("frequency").map_or("", |v| v.get());
            Some((time, freq.to_string()))
        })
        .collect()
}

/// The text `window_from_rows`'s error must carry for core's `reason`.
fn expected_fragment(reason: &str) -> &'static str {
    match reason {
        "missing" => "no reading for",
        "duplicate" => "more than one reading for",
        "zero" => "reading is 0",
        "out_of_bounds" => "is outside [",
        "invalid" => "",
        "stuck" => "identical readings in a row",
        other => panic!("unknown reason {other}"),
    }
}

#[test]
fn the_row_parser_keeps_the_last_repeated_key_and_drops_non_objects() {
    let rows = rows_from_body(
        r#"{"data":[1,"x",null,[],{"frequency":50.1},{"measurementTime":7,"frequency":50.1},
        {"measurementTime":"a","frequency":49.98,"frequency":"50"},{"measurementTime":"b"}]}"#,
    );
    assert_eq!(
        rows,
        [
            ("a".to_string(), "\"50\"".to_string()),
            ("b".to_string(), String::new())
        ]
    );
}

#[test]
fn freq_window_vectors_match_core() {
    let Some(v) = vector() else { return };
    let start_text = v["freq_start"].as_str().expect("freq_start");
    let start = parse_freq_start(&start_text.replace('Z', ".000000Z")).expect("freq_start");
    assert_eq!(
        format_freq_start(start).replace(".000000Z", "Z"),
        start_text
    );
    let cases = v["cases"].as_array().expect("cases is a list");
    assert!(cases.len() >= 20, "only {} cases", cases.len());
    let (mut valid, mut invalid) = (0, 0);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let rows = rows_from_body(case["body"].as_str().expect("body"));
        let got = window_from_rows(&rows, start);
        match (&case["value"], &case["invalid"]) {
            (serde_json::Value::String(value), serde_json::Value::Null) => {
                assert_eq!(got.as_deref(), Ok(value.as_str()), "{name}");
                valid += 1;
            }
            (serde_json::Value::Null, serde_json::Value::Object(why)) => {
                let err = got.expect_err(name);
                let reason = why["reason"].as_str().expect("reason");
                assert!(
                    err.contains(expected_fragment(reason)),
                    "{name}: core says {reason}, got {err:?}"
                );
                if reason == "invalid" {
                    for other in ["missing", "duplicate", "zero", "out_of_bounds", "stuck"] {
                        assert!(
                            !err.contains(expected_fragment(other)),
                            "{name}: core says invalid, got {err:?}"
                        );
                    }
                }
                if let Some(at) = why.get("at") {
                    let at = at.as_str().expect("at");
                    assert!(err.contains(at), "{name}: expected {at} in {err:?}");
                }
                invalid += 1;
            }
            other => panic!("{name}: a case has a value or an invalid reason, got {other:?}"),
        }
    }
    eprintln!("freq window vectors: {valid} valid and {invalid} invalid cases agree with core");
}
