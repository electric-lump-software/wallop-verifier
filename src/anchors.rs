//! Bundled trust anchor for tier-1 attributable verification.
//!
//! Per spec §4.2.4 ("Bundled-anchor trust root for attributable mode"),
//! a verifier in attributable mode MUST hold an out-of-band trust
//! anchor for wallop's infrastructure signing key(s); without one it
//! MUST refuse `--mode attributable` and exit non-zero, never silently
//! downgrading to attestable.
//!
//! This file IS the trust root. Its contents are reproducible from the
//! production wallop deployment via `mix wallop.export_infra_anchor`
//! (read-only, public-data-only) and are an OSS-auditable transparency
//! artefact.
//!
//! ## Anchor record shape (spec §4.2.4)
//!
//! Each entry MUST carry exactly:
//!
//! - `key_id` — 8-character lowercase hex per the §4.2.4 fingerprint rule
//! - `public_key_hex` — 64-character lowercase hex
//! - `inserted_at` — RFC 3339 UTC microsecond per the §4.2.1 timestamp rule
//! - `revoked_at` — same format, or `None` for currently-active anchors
//!
//! The temporal-window check in pin verification operates on these
//! fields: a pin verifies if `anchor.inserted_at <= pin.published_at`,
//! and (`anchor.revoked_at` is `None` OR `pin.published_at < anchor.revoked_at`).
//!
//! ## Cadence (spec §4.2.4)
//!
//! The bundled set holds at most **two** entries: the current wallop
//! infrastructure key plus at most one previous key retained for a
//! 90-day grace window post-rotation. After the grace window elapses,
//! the previous anchor is removed in the next verifier crate release.
//!
//! Pins signed by an anchor that has aged out of this set are
//! unverifiable in this crate version. Verifier users with a need to
//! re-verify historical bundles obtain an older crate version (or
//! supply the historical anchor via `--infra-key-pin`).
//!
//! ## Compromise (spec §4.2.4)
//!
//! A wallop infrastructure key discovered to be compromised is removed
//! **immediately** from this bundled set in a new verifier crate release;
//! pins it signed become unverifiable in the new crate. There is no
//! "previously-signed pins remain valid" carve-out.

#[derive(Debug, Clone, Copy)]
pub struct Anchor {
    /// 8-character lowercase hex per §4.2.4.
    pub key_id: &'static str,
    /// 64-character lowercase hex (32 bytes) per §4.2.4.
    pub public_key_hex: &'static str,
    /// RFC 3339 UTC microsecond per §4.2.1.
    pub inserted_at: &'static str,
    /// RFC 3339 UTC microsecond per §4.2.1, or `None` for currently-
    /// active anchors. The §4.2.4 anchor record schema permits exactly
    /// these two states; do not introduce a third.
    pub revoked_at: Option<&'static str>,
}

/// Bundled wallop infrastructure trust anchors for tier-1 attributable
/// mode. Sourced from production via `mix wallop.export_infra_anchor`;
/// values are non-secret (the same bytes are served at
/// `/infrastructure/keys` on the production deployment).
///
/// Update procedure (per §4.2.4 cadence rule):
///
/// 1. After a wallop production infrastructure-key rotation, run
///    `mix wallop.export_infra_anchor --rust` against production.
/// 2. Replace the contents of this array with the output. The previous
///    anchor stays for 90 days (current + previous, N=2).
/// 3. Cut a new verifier crate release.
/// 4. After 90 days, run the export again; the previous anchor will
///    have aged out. Cut another release that drops it.
///
/// Compromise: do NOT wait 90 days. Remove the compromised anchor
/// immediately and cut a release; downstream verifiers update via
/// `cargo install`.
pub const ANCHORS: &[Anchor] = &[
    Anchor {
        key_id: "05705b1f",
        public_key_hex: "16e4843f23aae4348ba3d610e67dd1f9746413f3c379cf62f6592fa83b01914c",
        inserted_at: "2026-04-09T10:28:18.831846Z",
        revoked_at: None,
    },
    Anchor {
        key_id: "f5de8465",
        public_key_hex: "51a07045c0049354c4d9766a1f26258579b59bde5b1f1627a3ca7518023f6c51",
        inserted_at: "2026-04-09T20:30:02.749962Z",
        revoked_at: None,
    },
];

impl Anchor {
    /// Decode the anchor's 32-byte public key from its hex form.
    ///
    /// Returns `None` if the literal in the source is malformed —
    /// catches a transcription error at first use rather than silently
    /// rejecting every signature.
    pub fn public_key_bytes(&self) -> Option<[u8; 32]> {
        let bytes = hex::decode(self.public_key_hex).ok()?;
        bytes.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_anchor_has_canonical_field_shapes() {
        for anchor in ANCHORS {
            assert_eq!(
                anchor.key_id.len(),
                8,
                "key_id must be 8 lowercase hex chars; got {:?}",
                anchor.key_id
            );
            assert!(
                anchor
                    .key_id
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "key_id must be lowercase hex; got {:?}",
                anchor.key_id
            );

            assert_eq!(
                anchor.public_key_hex.len(),
                64,
                "public_key_hex must be 64 lowercase hex chars; got {:?}",
                anchor.public_key_hex
            );
            assert!(
                anchor
                    .public_key_hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "public_key_hex must be lowercase hex; got {:?}",
                anchor.public_key_hex
            );

            // Decoding must succeed; catches a transcription error at
            // build time rather than on every verify call.
            assert!(
                anchor.public_key_bytes().is_some(),
                "public_key_hex must decode to 32 bytes; got {:?}",
                anchor.public_key_hex
            );

            // Canonical RFC 3339 form per spec §4.2.1:
            //   YYYY-MM-DDTHH:MM:SS.<6 digits>Z (exactly 27 bytes).
            // Matching the same parser used by `chrono_parse_canonical`
            // in verify_steps; the detailed pipeline check is the
            // canonical reference, this is a structural well-formedness
            // assertion at compile-time-of-tests.
            assert_canonical_rfc3339(anchor.inserted_at, "inserted_at");
            if let Some(revoked) = anchor.revoked_at {
                assert_canonical_rfc3339(revoked, "revoked_at");
            }
        }
    }

    #[test]
    fn bundled_set_holds_at_most_two_anchors() {
        // Spec §4.2.4 cadence rule. Before bumping past 2, re-read the
        // §4.2.4 cadence section; the size is part of the protocol's
        // operational contract, not a free-form choice.
        assert!(
            ANCHORS.len() <= 2,
            "bundled anchor set must hold at most 2 entries (current + 1 previous within 90-day grace); got {}",
            ANCHORS.len()
        );
        assert!(
            !ANCHORS.is_empty(),
            "bundled anchor set must hold at least 1 entry; without one --mode attributable cannot run"
        );
    }

    fn assert_canonical_rfc3339(s: &str, field: &str) {
        let b = s.as_bytes();
        assert_eq!(
            b.len(),
            27,
            "{} length {:?}: canonical RFC 3339 microsecond form is exactly 27 bytes; got {:?}",
            field,
            b.len(),
            s
        );

        // Position-by-position structure: digits where digits go,
        // literal separators where separators go, ending in `Z`.
        let digit_positions = [
            0, 1, 2, 3, // YYYY
            5, 6, // MM
            8, 9, // DD
            11, 12, // HH
            14, 15, // MM
            17, 18, // SS
            20, 21, 22, 23, 24, 25, // 6 fractional digits
        ];
        for &p in digit_positions.iter() {
            assert!(
                b[p].is_ascii_digit(),
                "{} expected digit at byte {}; got {:?} ({:?})",
                field,
                p,
                b[p] as char,
                s
            );
        }

        let separators = [
            (4, b'-'),
            (7, b'-'),
            (10, b'T'),
            (13, b':'),
            (16, b':'),
            (19, b'.'),
            (26, b'Z'),
        ];
        for &(p, expected) in separators.iter() {
            assert_eq!(
                b[p], expected,
                "{} expected {:?} at byte {}; got {:?} ({:?})",
                field, expected as char, p, b[p] as char, s
            );
        }
    }

    #[test]
    fn key_id_matches_hash_of_public_key() {
        // Internal consistency: each anchor's key_id MUST equal the
        // first 4 bytes (8 hex chars) of SHA-256(public_key) per the
        // §4.2.4 fingerprint rule.
        for anchor in ANCHORS {
            let pk = anchor.public_key_bytes().unwrap();
            let derived = crate::key_id(&pk);
            assert_eq!(
                derived, anchor.key_id,
                "anchor {:?} has key_id {:?} but its public_key hashes to {:?}",
                anchor.public_key_hex, anchor.key_id, derived
            );
        }
    }
}
