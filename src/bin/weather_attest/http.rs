//! Blocking HTTP clients for the public weather and grid-frequency
//! records. Errors never include the Met Office key.

use std::cell::Cell;
use std::io::Read;
use std::time::{Duration, Instant};

use wallop_verifier::protocol::freq_v1;

use super::USER_AGENT;
use super::landobs::Row;

pub(crate) const LANDOBS_BASE_URL: &str =
    "https://data.hub.api.metoffice.gov.uk/observation-land/1";
pub(crate) const OGIMET_BASE_URL: &str = "https://www.ogimet.com";
/// Ogimet asks clients to leave at least 20 seconds between requests.
pub(crate) const OGIMET_MIN_GAP: Duration = Duration::from_secs(20);
/// Elexon's BMRS FREQ dataset. Public; no key.
pub(crate) const ELEXON_BASE_URL: &str = "https://data.elexon.co.uk/bmrs/api/v1/datasets/FREQ";
/// Elexon serves at most one day of FREQ readings per request.
const ELEXON_MAX_SPAN_SECS: i64 = 86_400 - 1;
const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY_BYTES: u64 = 1024 * 1024;

fn describe(source: &str, err: ureq::Error) -> String {
    match err {
        ureq::Error::Status(code, _) => format!("{source} returned HTTP {code}"),
        ureq::Error::Transport(t) => format!("{source} unreachable: {}", t.kind()),
    }
}

/// The response body, or an error if it is larger than `MAX_BODY_BYTES`
/// (a truncated body must never be parsed as if it were whole).
fn read_capped(response: ureq::Response, source: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{source} response unreadable: {e}"))?;
    if bytes.len() as u64 > MAX_BODY_BYTES {
        return Err(format!(
            "{source} response is larger than {MAX_BODY_BYTES} bytes"
        ));
    }
    Ok(bytes)
}

pub(crate) struct LandObsClient {
    agent: ureq::Agent,
    base_url: String,
    key: String,
}

impl LandObsClient {
    pub(crate) fn new(base_url: &str, key: &str) -> Self {
        // ureq re-sends custom headers on a redirect, so never follow one:
        // the key must only ever go to `base_url`. Over https, refuse any
        // downgrade too (tests run against plain-http mock servers);
        // that relies on the caller passing the pinned https
        // `LANDOBS_BASE_URL`.
        let agent = ureq::AgentBuilder::new()
            .timeout(TIMEOUT)
            .redirects(0)
            .https_only(base_url.starts_with("https://"))
            .build();
        Self {
            agent,
            base_url: base_url.trim_end_matches('/').to_string(),
            key: key.to_string(),
        }
    }

    /// Every row the API currently holds for `geohash` (about 48 hours).
    pub(crate) fn fetch(&self, geohash: &str) -> Result<Vec<Row>, String> {
        let response = self
            .agent
            .get(&format!("{}/{geohash}", self.base_url))
            .set("apikey", &self.key)
            .set("accept", "application/json")
            .set("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| describe("Land Observations", e))?;
        if (300..400).contains(&response.status()) {
            return Err(format!(
                "Land Observations returned HTTP {}",
                response.status()
            ));
        }
        let bytes = read_capped(response, "Land Observations")?;
        let rows = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Land Observations response is not a list of rows: {e}"))?;
        // A repeated key would let first-wins and last-wins readers see
        // different observations in the same bytes, as for Elexon.
        wallop_verifier::protocol::refuse_duplicate_keys(&bytes)
            .map_err(|e| format!("Land Observations response: {e}"))?;
        Ok(rows)
    }
}

pub(crate) struct ElexonClient {
    agent: ureq::Agent,
    base_url: String,
}

impl ElexonClient {
    pub(crate) fn new(base_url: &str) -> Self {
        // Never follow a redirect, and over https refuse any downgrade
        // (tests run against plain-http mock servers). `https_only` is
        // decided from `base_url`, so it holds only because `run` passes
        // the pinned `ELEXON_BASE_URL`, which is https (a test pins that).
        let agent = ureq::AgentBuilder::new()
            .timeout(TIMEOUT)
            .redirects(0)
            .https_only(base_url.starts_with("https://"))
            .build();
        Self {
            agent,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Every FREQ row with `from <= measurementTime <= to` (unix seconds),
    /// as `(measurementTime, frequency JSON text)` under core's row rule
    /// (`freq_v1::rows_from_body`). At most one day. Any HTTP error, an
    /// oversized body or a body that is not a FREQ response is an `Err`,
    /// which the caller reports as unavailable, never as a mismatch.
    pub(crate) fn fetch(&self, from: i64, to: i64) -> Result<Vec<(String, String)>, String> {
        if to < from || to - from > ELEXON_MAX_SPAN_SECS {
            return Err("Elexon allows at most one day per request".into());
        }
        let stamp = |secs: i64| {
            let canonical = freq_v1::format_freq_start(secs);
            match canonical.strip_suffix(".000000Z") {
                Some(prefix) if prefix.len() == 19 => Ok(format!("{prefix}Z")),
                _ => Err(format!("{secs} is out of range")),
            }
        };
        let response = self
            .agent
            .get(&self.base_url)
            .query("measurementDateTimeFrom", &stamp(from)?)
            .query("measurementDateTimeTo", &stamp(to)?)
            .query("format", "json")
            .set("accept", "application/json")
            .set("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| describe("Elexon", e))?;
        if response.status() != 200 {
            return Err(format!("Elexon returned HTTP {}", response.status()));
        }
        let bytes = read_capped(response, "Elexon")?;
        freq_v1::rows_from_body(&bytes).map_err(|e| format!("Elexon response: {e}"))
    }
}

/// Pacing is per client: a run must build one `OgimetClient` and pass
/// `&OgimetClient` down, or the 20-second gap is not kept.
pub(crate) struct OgimetClient {
    agent: ureq::Agent,
    base_url: String,
    min_gap: Duration,
    last_request: Cell<Option<Instant>>,
    sleep: Box<dyn Fn(Duration)>,
}

impl OgimetClient {
    pub(crate) fn new(base_url: &str) -> Self {
        Self::with_pacing(base_url, OGIMET_MIN_GAP, Box::new(std::thread::sleep))
    }

    pub(crate) fn with_pacing(
        base_url: &str,
        min_gap: Duration,
        sleep: Box<dyn Fn(Duration)>,
    ) -> Self {
        // As for Elexon: never follow a redirect, and over https refuse
        // any downgrade, which relies on the caller passing the pinned
        // https `OGIMET_BASE_URL` (tests run against plain-http mocks).
        let agent = ureq::AgentBuilder::new()
            .timeout(TIMEOUT)
            .redirects(0)
            .https_only(base_url.starts_with("https://"))
            .build();
        Self {
            agent,
            base_url: base_url.trim_end_matches('/').to_string(),
            min_gap,
            last_request: Cell::new(None),
            sleep,
        }
    }

    /// The SYNOP lines for WMO `block` from `begin` to `end` inclusive
    /// (each `YYYYMMDDHHmm`).
    /// `Ok(None)` when the response is empty; a redirect is an `Err` (it
    /// is never followed); anything else, including an error page, is
    /// returned as text for the caller to parse.
    pub(crate) fn fetch(
        &self,
        block: &str,
        begin: &str,
        end: &str,
    ) -> Result<Option<String>, String> {
        debug_assert!(
            [block, begin, end]
                .iter()
                .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
            "block, begin and end must be ASCII digits"
        );
        self.wait_turn();
        let response = self
            .agent
            .get(&format!(
                "{}/cgi-bin/getsynop?block={block}&begin={begin}&end={end}",
                self.base_url
            ))
            .set("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| describe("Ogimet", e))?;
        if (300..400).contains(&response.status()) {
            return Err(format!("Ogimet returned HTTP {}", response.status()));
        }
        let body = String::from_utf8_lossy(&read_capped(response, "Ogimet")?).into_owned();
        Ok(if body.trim().is_empty() {
            None
        } else {
            Some(body)
        })
    }

    /// Sleep until `min_gap` has passed since the previous request, then
    /// mark this one. A failed request still counts towards the gap.
    fn wait_turn(&self) {
        if let Some(previous) = self.last_request.get() {
            let elapsed = previous.elapsed();
            if elapsed < self.min_gap {
                (self.sleep)(self.min_gap - elapsed);
            }
        }
        self.last_request.set(Some(Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Matcher;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// 2026-10-14T19:54:00Z and 19:55:45Z.
    const FROM: i64 = 1_792_007_640;
    const TO: i64 = 1_792_007_745;

    #[test]
    fn elexon_is_https_and_sends_the_window_as_query() {
        assert!(ELEXON_BASE_URL.starts_with("https://"));
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded(
                    "measurementDateTimeFrom".into(),
                    "2026-10-14T19:54:00Z".into(),
                ),
                Matcher::UrlEncoded(
                    "measurementDateTimeTo".into(),
                    "2026-10-14T19:55:45Z".into(),
                ),
                Matcher::UrlEncoded("format".into(), "json".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"data":[{"measurementTime":"2026-10-14T19:55:00Z","frequency":49.98}]}"#)
            .create();
        let rows = ElexonClient::new(&server.url()).fetch(FROM, TO).unwrap();
        assert_eq!(
            rows,
            [("2026-10-14T19:55:00Z".to_string(), "49.98".to_string())]
        );
        mock.assert();
    }

    #[test]
    fn elexon_refuses_more_than_a_day_and_never_follows_a_redirect() {
        let client = ElexonClient::new("http://127.0.0.1:9");
        assert!(client.fetch(0, 86_400).unwrap_err().contains("one day"));
        assert!(client.fetch(10, 9).unwrap_err().contains("one day"));

        let mut server = mockito::Server::new();
        let target = server
            .mock("GET", "/elsewhere")
            .with_status(200)
            .with_body(r#"{"data":[]}"#)
            .expect(0)
            .create();
        server
            .mock("GET", "/")
            .match_query(Matcher::Any)
            .with_status(302)
            .with_header("location", &format!("{}/elsewhere", server.url()))
            .create();
        let err = ElexonClient::new(&server.url())
            .fetch(FROM, TO)
            .unwrap_err();
        assert!(err.contains("302"), "{err}");
        target.assert();
    }

    #[test]
    fn elexon_body_over_the_cap_is_refused() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(" ".repeat(MAX_BODY_BYTES as usize + 1))
            .create();
        let err = ElexonClient::new(&server.url())
            .fetch(FROM, TO)
            .unwrap_err();
        assert!(err.contains("larger than"), "{err}");
    }

    #[test]
    fn elexon_errors_and_unparseable_bodies_are_errors() {
        for (status, body) in [
            (500, r#"{"data":[]}"#),
            (404, ""),
            (204, ""),
            (200, "<html>maintenance</html>"),
            (200, r#"{"data":{}}"#),
        ] {
            let mut server = mockito::Server::new();
            server
                .mock("GET", "/")
                .match_query(Matcher::Any)
                .with_status(status)
                .with_body(body)
                .create();
            assert!(
                ElexonClient::new(&server.url()).fetch(FROM, TO).is_err(),
                "{status} {body}"
            );
        }
    }

    #[test]
    fn landobs_sends_the_key_and_parses_rows() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/gcnfur")
            .match_header("apikey", "test-key")
            .with_status(200)
            .with_body(r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":18.38}]"#)
            .create();
        let rows = LandObsClient::new(&server.url(), "test-key")
            .fetch("gcnfur")
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["temperature"].get(), "18.38");
        mock.assert();
    }

    #[test]
    fn landobs_http_error_is_reported_without_the_key() {
        let mut server = mockito::Server::new();
        server.mock("GET", "/gcnfur").with_status(401).create();
        let err = LandObsClient::new(&server.url(), "secret-key")
            .fetch("gcnfur")
            .unwrap_err();
        assert!(err.contains("401"), "{err}");
        assert!(!err.contains("secret-key"), "{err}");
    }

    #[test]
    fn landobs_never_follows_a_redirect_with_the_key() {
        let mut elsewhere = mockito::Server::new();
        let stolen = elsewhere
            .mock("GET", Matcher::Any)
            .with_status(200)
            .with_body("[]")
            .expect(0)
            .create();
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/gcnfur")
            .with_status(302)
            .with_header("location", &format!("{}/gcnfur", elsewhere.url()))
            .with_body("[]")
            .create();
        let err = LandObsClient::new(&server.url(), "secret-key")
            .fetch("gcnfur")
            .unwrap_err();
        assert_eq!(err, "Land Observations returned HTTP 302");
        assert!(!err.contains("secret-key"), "{err}");
        stolen.assert();
    }

    #[test]
    fn landobs_rejects_a_non_list_body() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/gcnfur")
            .with_status(200)
            .with_body(r#"{"error":"x"}"#)
            .create();
        assert!(
            LandObsClient::new(&server.url(), "k")
                .fetch("gcnfur")
                .is_err()
        );
    }

    #[test]
    fn ogimet_queries_the_given_window_and_maps_empty_to_none() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/cgi-bin/getsynop")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("block".into(), "03749".into()),
                Matcher::UrlEncoded("begin".into(), "202610011600".into()),
                Matcher::UrlEncoded("end".into(), "202610012200".into()),
            ]))
            .with_status(200)
            .with_body("\n")
            .create();
        let client = OgimetClient::with_pacing(&server.url(), Duration::ZERO, Box::new(|_| {}));
        assert_eq!(
            client.fetch("03749", "202610011600", "202610012200"),
            Ok(None)
        );
        mock.assert();
    }

    #[test]
    fn ogimet_waits_the_minimum_gap_between_requests() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", Matcher::Any)
            .with_status(200)
            .with_body("x")
            .expect(2)
            .create();
        let slept = Rc::new(RefCell::new(Vec::new()));
        let record = Rc::clone(&slept);
        let client = OgimetClient::with_pacing(
            &server.url(),
            OGIMET_MIN_GAP,
            Box::new(move |d| record.borrow_mut().push(d)),
        );
        client
            .fetch("03749", "202610011900", "202610011900")
            .unwrap();
        assert!(slept.borrow().is_empty());
        client
            .fetch("03462", "202610011900", "202610011900")
            .unwrap();
        let waits = slept.borrow();
        assert_eq!(waits.len(), 1);
        assert!(waits[0] > Duration::from_secs(19), "{waits:?}");
    }

    #[test]
    fn ogimet_is_https_and_never_follows_a_redirect() {
        assert!(OGIMET_BASE_URL.starts_with("https://"));
        let mut server = mockito::Server::new();
        let target = server
            .mock("GET", "/elsewhere")
            .with_status(200)
            .with_body("x")
            .expect(0)
            .create();
        server
            .mock("GET", "/cgi-bin/getsynop")
            .match_query(Matcher::Any)
            .with_status(302)
            .with_header("location", &format!("{}/elsewhere", server.url()))
            .with_body("redirect page")
            .create();
        let client = OgimetClient::with_pacing(&server.url(), Duration::ZERO, Box::new(|_| {}));
        let err = client
            .fetch("03749", "202610011900", "202610011900")
            .unwrap_err();
        assert_eq!(err, "Ogimet returned HTTP 302");
        target.assert();
    }

    #[test]
    fn https_clients_refuse_a_plain_http_url() {
        // Nothing listens on port 9; https_only refuses before connecting.
        let refused = |agent: &ureq::Agent| {
            let err = agent.get("http://127.0.0.1:9/").call().unwrap_err();
            matches!(&err, ureq::Error::Transport(t)
                if t.kind() == ureq::ErrorKind::InsecureRequestHttpsOnly)
        };
        assert!(refused(&ElexonClient::new("https://127.0.0.1:9").agent));
        assert!(refused(
            &OgimetClient::with_pacing("https://127.0.0.1:9", Duration::ZERO, Box::new(|_| {}))
                .agent
        ));
        assert!(refused(
            &LandObsClient::new("https://127.0.0.1:9", "k").agent
        ));
        assert!(!refused(&OgimetClient::new("http://127.0.0.1:9").agent));
    }

    #[test]
    fn landobs_refuses_a_body_with_a_repeated_key() {
        for body in [
            r#"[{"datetime":"2026-10-01T19:00:00Z","temperature":1,"temperature":18.38}]"#,
            r#"[{"datetime":"2026-10-01T19:00:00Z","datetime":"2026-10-01T18:00:00Z"}]"#,
        ] {
            let mut server = mockito::Server::new();
            server
                .mock("GET", "/gcnfur")
                .with_status(200)
                .with_body(body)
                .create();
            let err = LandObsClient::new(&server.url(), "k")
                .fetch("gcnfur")
                .unwrap_err();
            assert!(err.contains("duplicate key"), "{body}: {err}");
        }
    }

    #[test]
    fn ogimet_minimum_gap_is_twenty_seconds() {
        assert_eq!(OGIMET_MIN_GAP, Duration::from_secs(20));
    }

    #[test]
    fn an_oversized_response_is_an_error_not_a_truncated_body() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", Matcher::Any)
            .with_status(200)
            .with_body(vec![b'x'; MAX_BODY_BYTES as usize + 1])
            .create();
        let client = OgimetClient::with_pacing(&server.url(), Duration::ZERO, Box::new(|_| {}));
        let err = client
            .fetch("03749", "202610011900", "202610011900")
            .unwrap_err();
        assert!(err.contains("larger than"), "{err}");
    }

    #[test]
    fn a_body_at_the_cap_is_accepted() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", Matcher::Any)
            .with_status(200)
            .with_body(vec![b'x'; MAX_BODY_BYTES as usize])
            .create();
        let client = OgimetClient::with_pacing(&server.url(), Duration::ZERO, Box::new(|_| {}));
        let body = client
            .fetch("03749", "202610011900", "202610011900")
            .unwrap()
            .unwrap();
        assert_eq!(body.len(), MAX_BODY_BYTES as usize);
    }
}
