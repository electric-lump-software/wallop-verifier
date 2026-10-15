//! Blocking HTTP clients for the two public weather records.
//! Errors never include the Met Office key.

use std::cell::Cell;
use std::io::Read;
use std::time::{Duration, Instant};

use super::USER_AGENT;
use super::landobs::Row;

pub(crate) const LANDOBS_BASE_URL: &str =
    "https://data.hub.api.metoffice.gov.uk/observation-land/1";
pub(crate) const OGIMET_BASE_URL: &str = "https://www.ogimet.com";
/// Ogimet asks clients to leave at least 20 seconds between requests.
pub(crate) const OGIMET_MIN_GAP: Duration = Duration::from_secs(20);
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
        Self {
            agent: ureq::AgentBuilder::new().timeout(TIMEOUT).build(),
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
        let bytes = read_capped(response, "Land Observations")?;
        serde_json::from_slice(&bytes)
            .map_err(|e| format!("Land Observations response is not a list of rows: {e}"))
    }
}

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
        Self {
            agent: ureq::AgentBuilder::new().timeout(TIMEOUT).build(),
            base_url: base_url.trim_end_matches('/').to_string(),
            min_gap,
            last_request: Cell::new(None),
            sleep,
        }
    }

    /// The SYNOP lines for WMO `block` at `hour` (`YYYYMMDDHHmm`).
    /// `Ok(None)` when the response is empty; anything else, including an
    /// error page, is returned as text for the caller to parse.
    pub(crate) fn fetch(&self, block: &str, hour: &str) -> Result<Option<String>, String> {
        self.wait_turn();
        let response = self
            .agent
            .get(&format!(
                "{}/cgi-bin/getsynop?block={block}&begin={hour}&end={hour}",
                self.base_url
            ))
            .set("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| describe("Ogimet", e))?;
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
    fn ogimet_queries_one_hour_and_maps_empty_to_none() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/cgi-bin/getsynop")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("block".into(), "03749".into()),
                Matcher::UrlEncoded("begin".into(), "202610011900".into()),
                Matcher::UrlEncoded("end".into(), "202610011900".into()),
            ]))
            .with_status(200)
            .with_body("\n")
            .create();
        let client = OgimetClient::with_pacing(&server.url(), Duration::ZERO, Box::new(|_| {}));
        assert_eq!(client.fetch("03749", "202610011900"), Ok(None));
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
        client.fetch("03749", "202610011900").unwrap();
        assert!(slept.borrow().is_empty());
        client.fetch("03462", "202610011900").unwrap();
        let waits = slept.borrow();
        assert_eq!(waits.len(), 1);
        assert!(waits[0] > Duration::from_secs(19), "{waits:?}");
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
        let err = client.fetch("03749", "202610011900").unwrap_err();
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
        let body = client.fetch("03749", "202610011900").unwrap().unwrap();
        assert_eq!(body.len(), MAX_BODY_BYTES as usize);
    }
}
