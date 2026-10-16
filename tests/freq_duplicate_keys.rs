//! Duplicate JSON keys in an Elexon FREQ body.
//!
//! With a repeated key, a first-wins and a last-wins reader of the same
//! bytes get different values: `{"data":[],"data":[rows]}` is an empty
//! or a full window, and a row with two `frequency` keys has two readings.
//! The stored bytes would then not prove one value, so `rows_from_body`
//! refuses a repeated key at any level, as core does.

use wallop_verifier::protocol::freq_v1::{rows_from_body, window_from_rows};

const T: i64 = 1_792_007_640; // 2026-10-14T19:54:00Z
const TEXTS: [&str; 8] = [
    "50.012", "50.018", "50.012", "49.983", "49.98", "49.953", "49.912", "49.883",
];

fn body() -> String {
    let times = [
        "19:54:00", "19:54:15", "19:54:30", "19:54:45", "19:55:00", "19:55:15", "19:55:30",
        "19:55:45",
    ];
    let rows: Vec<String> = TEXTS
        .iter()
        .zip(times)
        .rev()
        .map(|(f, t)| {
            format!(r#"{{"dataset":"FREQ","measurementTime":"2026-10-14T{t}Z","frequency":{f}}}"#)
        })
        .collect();
    format!(r#"{{"data":[{}]}}"#, rows.join(","))
}

fn window(b: &str) -> Result<String, String> {
    window_from_rows(&rows_from_body(b.as_bytes())?, T)
}

#[test]
fn the_plain_body_gives_the_window() {
    assert_eq!(
        window(&body()),
        Ok("50012;50018;50012;49983;49980;49953;49912;49883".to_string())
    );
}

#[test]
fn a_duplicate_top_level_data_is_refused() {
    let b = body().replacen(r#"{"data":["#, r#"{"data":[],"data":["#, 1);
    assert_eq!(
        rows_from_body(b.as_bytes()),
        Err(r#"duplicate key "data""#.into())
    );
}

#[test]
fn a_row_with_two_frequency_keys_is_refused() {
    let b = body().replacen(
        r#""frequency":49.883"#,
        r#""frequency":50.999,"frequency":49.883"#,
        1,
    );
    assert_eq!(window(&b), Err(r#"duplicate key "frequency""#.into()));
}
