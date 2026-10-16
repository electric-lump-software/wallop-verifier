//! Grid-frequency window vectors: raw Elexon FREQ bodies from wallop_core,
//! each with the `freq_value` of the window or the reason it is invalid.
//!
//! The vector file is `spec/vectors/freq-window-v1.json` in the wallop
//! repo. This test reads the vendored copy under `vendor/wallop`. Only when
//! that file is missing does it read the path in `WALLOP_FREQ_WINDOW_VECTORS`,
//! and it skips, saying so, when neither exists. It prints which file it
//! used. Each body goes through `freq_v1::rows_from_body`, the parser
//! `weather-attest` uses, so the row rule is checked end to end.

use wallop_verifier::protocol::freq_v1::{
    format_freq_start, parse_freq_start, rows_from_body, window_from_rows,
};

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
        let rows = rows_from_body(case["body"].as_str().expect("body").as_bytes())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
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
