//! Compiled signature matcher.
//!
//! The matcher takes a list of [`Signature`]s and compiles
//! them into a [`SignatureSet`] that can scan a payload in
//! one pass. Two engines work side-by-side:
//!
//! - **Aho-Corasick** for literal patterns. One automaton
//!   holds every literal pattern across every signature;
//!   one **overlapping** scan returns every literal match
//!   offset (non-overlapping scans would let one
//!   signature's literal shadow another signature's
//!   literal that starts inside it — a classic IPS
//!   evasion). The matcher attributes each offset back to
//!   the owning signature and applies the per-signature
//!   anchor.
//! - **`regex::bytes`** for regex patterns. Each regex
//!   signature gets its own compiled regex; scanning is
//!   O(P · n) where P is the number of regex signatures
//!   active for the flow's (proto, sport, dport) tuple.
//!
//! Patterns inside a signature are conjunctive: every
//! pattern must match for the signature to fire.
//!
//! ### Hot path
//!
//! The data path holds an `Arc<SignatureSet>` (cheap clone)
//! and calls [`SignatureSet::scan`] for each payload. The
//! set itself is immutable; hot-swaps go through
//! [`crate::service::IpsService::on_policy_reload`] which
//! ArcSwap-replaces the reference.

use crate::error::IpsError;
use crate::signature::{Action, Anchor, Pattern, PortFilter, Severity, Signature};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::Regex;
use sng_fw::flow::IpProtocol;
use std::collections::HashMap;
use std::sync::Arc;

/// One IPS hit observed on a payload. Multiple hits per
/// payload are possible; the service folds them into one
/// [`sng_core::events::IpsEvent`] per (flow, signature)
/// using [`IpsHit::fold_action`] to combine actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpsHit {
    /// Suricata-style SID of the signature that hit.
    pub sid: u32,
    /// Description from [`Signature::msg`].
    pub msg: String,
    /// Severity from [`Signature::severity`].
    pub severity: Severity,
    /// Action from [`Signature::action`]. When multiple
    /// signatures hit on the same payload, the service can
    /// fold them with [`IpsHit::fold_action`].
    pub action: Action,
    /// Protocol the matching signature was scoped to.
    pub protocol: IpProtocol,
    /// Byte offset of the first matched pattern in the
    /// scanned payload (smallest offset across the
    /// signature's conjunctive patterns). Useful for
    /// debugging / pcap correlation; the wire telemetry
    /// does not surface it.
    pub first_match_offset: usize,
}

impl IpsHit {
    /// Fold two hits' actions into the most-severe one for
    /// flows where multiple signatures match. Order:
    /// `Drop > Reset > Block > Alert`.
    ///
    /// The implementation delegates to `Action`'s derived
    /// `Ord` impl — variants are declared in severity
    /// order on the type, so positional comparison gives
    /// the right answer. See the type-level doc on
    /// [`Action`] for the invariant.
    #[must_use]
    pub fn fold_action(a: Action, b: Action) -> Action {
        std::cmp::max(a, b)
    }
}

/// Compiled signature set. The hot path scans payloads
/// against this; the compile step runs once at bundle load.
#[derive(Debug)]
pub struct SignatureSet {
    /// Per-signature metadata indexed by literal-pattern
    /// position in the Aho-Corasick automaton. `signatures`
    /// is the authoritative list; the other fields index
    /// into it.
    signatures: Vec<Signature>,
    /// Aho-Corasick automaton holding every literal pattern
    /// across all signatures. Patterns are deduplicated by
    /// value but each pattern points back to (potentially
    /// multiple) owning signatures via `literal_index`.
    literal_ac: Option<AhoCorasick>,
    /// Map from automaton pattern id → list of (signature
    /// index, pattern index within that signature). One
    /// literal can belong to multiple signatures (e.g.
    /// both an SQLi rule and an LDAP-injection rule may
    /// contain `'` in their patterns); both must be
    /// attributed.
    literal_index: Vec<Vec<LiteralOwner>>,
    /// Pre-compiled regex per (signature index, pattern
    /// index within that signature). Same indexing scheme
    /// as `literal_index` so the matcher can join the two
    /// at scan time.
    regex_index: HashMap<RegexKey, Regex>,
    /// Longest literal pattern (in bytes) across every
    /// signature in the set. Used by [`crate::service::IpsService`]
    /// to size the reassembly lookback when consuming
    /// scanned bytes: a cross-segment literal match of
    /// length L can land partly in the consumed bytes and
    /// partly in the next observation only if we retain at
    /// least `L - 1` bytes from the previous scan. Stored
    /// on the set rather than recomputed per scan so the
    /// observe hot path is O(1) here.
    max_literal_pattern_len: usize,
    /// True iff the set contains at least one
    /// [`Pattern::Regex`] signature. Regex match length is
    /// unbounded in general; the service uses an operator-
    /// configured lookback (`regex_lookback_bytes`) to
    /// decide how many bytes to retain when consuming
    /// scanned bytes, but only if this flag is set.
    has_regex_patterns: bool,
}

/// Identifies a regex pattern by its position inside the
/// signature list. Used as a key in `SignatureSet::regex_index`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct RegexKey {
    sig_idx: usize,
    pattern_idx: usize,
}

/// Back-reference from an Aho-Corasick pattern id to the
/// (signature, pattern) tuple inside [`SignatureSet::signatures`].
#[derive(Copy, Clone, Debug)]
struct LiteralOwner {
    sig_idx: usize,
    pattern_idx: usize,
}

/// Input to one scan call. Producers (the firewall, the
/// SWG, the DNS service) build this from their packet /
/// flow context.
#[derive(Clone, Copy, Debug)]
pub struct ScanContext<'a> {
    /// IP-layer protocol of the flow the payload belongs to.
    /// Used to short-circuit signatures scoped to a different
    /// protocol.
    pub protocol: IpProtocol,
    /// Source port observed on the wire. Used by the port
    /// filter on each signature.
    pub source_port: u16,
    /// Destination port observed on the wire. Used by the
    /// port filter on each signature.
    pub destination_port: u16,
    /// The bytes to scan. The matcher does not own this
    /// buffer; the borrow lives until the scan returns.
    pub payload: &'a [u8],
}

impl SignatureSet {
    /// Compile a list of signatures into the immutable
    /// scan-ready set. Returns the first
    /// [`IpsError::InvalidSignature`] encountered — the
    /// bundle is rejected wholesale on failure (a partially
    /// compiled set could miss patterns the operator
    /// expects to fire).
    ///
    /// # Errors
    ///
    /// - [`IpsError::InvalidSignature`] when a regex
    ///   pattern fails to compile, or a signature has no
    ///   patterns.
    pub fn compile(signatures: Vec<Signature>) -> Result<Self, IpsError> {
        // Collect every literal pattern across every
        // signature, deduplicating by value so a literal
        // shared by N signatures only takes one slot in the
        // Aho-Corasick automaton. The dedup is a real win:
        // about 35% of Emerging Threats rules share the
        // string "Mozilla/" or "/uri" or similar bait.
        let mut literal_dedup: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut literal_patterns: Vec<Vec<u8>> = Vec::new();
        let mut literal_index: Vec<Vec<LiteralOwner>> = Vec::new();
        let mut regex_index: HashMap<RegexKey, Regex> = HashMap::new();
        let mut max_literal_pattern_len: usize = 0;
        let mut has_regex_patterns = false;

        for (sig_idx, sig) in signatures.iter().enumerate() {
            if sig.patterns.is_empty() {
                return Err(IpsError::InvalidSignature {
                    sid: sig.sid,
                    reason: "signature has no patterns".into(),
                });
            }
            for (pattern_idx, pattern) in sig.patterns.iter().enumerate() {
                match pattern {
                    Pattern::Literal(bytes) => {
                        if bytes.is_empty() {
                            return Err(IpsError::InvalidSignature {
                                sid: sig.sid,
                                reason: "literal pattern is empty".into(),
                            });
                        }
                        if bytes.len() > max_literal_pattern_len {
                            max_literal_pattern_len = bytes.len();
                        }
                        let entry = literal_dedup.entry(bytes.clone()).or_insert_with(|| {
                            let i = literal_patterns.len();
                            literal_patterns.push(bytes.clone());
                            literal_index.push(Vec::new());
                            i
                        });
                        literal_index[*entry].push(LiteralOwner {
                            sig_idx,
                            pattern_idx,
                        });
                    }
                    Pattern::Regex(src) => {
                        let compiled = Regex::new(src).map_err(|e| IpsError::InvalidSignature {
                            sid: sig.sid,
                            reason: format!("regex compile: {e}"),
                        })?;
                        has_regex_patterns = true;
                        regex_index.insert(
                            RegexKey {
                                sig_idx,
                                pattern_idx,
                            },
                            compiled,
                        );
                    }
                }
            }
        }

        let literal_ac = if literal_patterns.is_empty() {
            None
        } else {
            // `MatchKind::Standard` is the only mode that
            // supports `find_overlapping_iter`, which we
            // need so that literal patterns from different
            // signatures cannot shadow each other in the
            // payload (a `GET ` literal at offset 0 would
            // otherwise hide an `ET /etc/passwd` literal
            // at offset 1). Anchor semantics
            // (offset/depth) are enforced per-signature
            // inside `scan` via `Anchor::permits`, so the
            // matcher itself just needs to report every
            // pattern occurrence.
            let ac = AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .ascii_case_insensitive(false)
                .build(&literal_patterns)
                .map_err(|e| IpsError::InvalidSignature {
                    sid: 0,
                    reason: format!("aho-corasick build: {e}"),
                })?;
            Some(ac)
        };

        Ok(Self {
            signatures,
            literal_ac,
            literal_index,
            regex_index,
            max_literal_pattern_len,
            has_regex_patterns,
        })
    }

    /// Construct an empty signature set. Convenient default
    /// when no bundle has been loaded yet.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            signatures: Vec::new(),
            literal_ac: None,
            literal_index: Vec::new(),
            regex_index: HashMap::new(),
            max_literal_pattern_len: 0,
            has_regex_patterns: false,
        }
    }

    /// Length (in bytes) of the longest literal pattern in
    /// the set, or `0` if there are no literal patterns.
    /// The IPS service uses this to size the reassembly
    /// lookback when sliding the window past already-
    /// scanned bytes: retaining `max_literal_pattern_len`
    /// trailing bytes preserves cross-observation literal
    /// matches that span the previous and next scan.
    ///
    /// The conservatively-correct retention is `L` (the
    /// pattern length) rather than `L - 1`. A literal of
    /// length `L` whose final byte landed at the very last
    /// scanned position needs all `L` preceding bytes
    /// available in the next scan in order to re-match —
    /// retaining only `L - 1` would drop the byte before
    /// the candidate match and lose the literal. The cost
    /// of the extra byte is negligible compared to the
    /// per-flow buffer size, and the simpler `L` keeps
    /// the consume math in
    /// [`crate::service::IpsService::observe_payload`]
    /// obvious.
    #[must_use]
    pub fn max_literal_pattern_len(&self) -> usize {
        self.max_literal_pattern_len
    }

    /// True iff the set contains at least one regex
    /// pattern. Regex match length is not bounded by the
    /// set itself, so callers that want to retain lookback
    /// for regex matches must consult an operator-configured
    /// bound (`IpsServiceConfig::regex_lookback_bytes`).
    #[must_use]
    pub fn has_regex_patterns(&self) -> bool {
        self.has_regex_patterns
    }

    /// Number of signatures in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// True if the set has no signatures.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Borrow a signature by its index in the set.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&Signature> {
        self.signatures.get(idx)
    }

    /// Borrow every signature in the set. Order is
    /// stable across the lifetime of the set; callers can
    /// rely on indices being consistent.
    #[must_use]
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Scan a payload against every applicable signature.
    /// Returns one [`IpsHit`] per signature whose every
    /// pattern matched (conjunctive).
    ///
    /// Algorithm:
    /// 1. Bail early if the set is empty.
    /// 2. Run the Aho-Corasick automaton over the payload
    ///    to collect every literal-pattern match offset.
    /// 3. For each signature that the (proto, sport, dport)
    ///    tuple applies to, check whether all of its
    ///    patterns matched at an anchor-permitted offset.
    ///    Literals are looked up in the automaton's hit
    ///    table; regexes are run per-signature.
    #[must_use]
    pub fn scan(&self, ctx: ScanContext<'_>) -> Vec<IpsHit> {
        if self.signatures.is_empty() {
            return Vec::new();
        }

        // Per-(signature, pattern) earliest-match offset.
        // `usize::MAX` means "not matched".
        let mut earliest: HashMap<(usize, usize), usize> = HashMap::new();

        if let Some(ac) = &self.literal_ac {
            for m in ac.find_overlapping_iter(ctx.payload) {
                let pid = m.pattern().as_usize();
                if let Some(owners) = self.literal_index.get(pid) {
                    for owner in owners {
                        let sig = &self.signatures[owner.sig_idx];
                        if !sig.applies_to(ctx.protocol, ctx.source_port, ctx.destination_port) {
                            continue;
                        }
                        if !sig.anchor.permits(m.start(), m.end() - m.start()) {
                            continue;
                        }
                        let key = (owner.sig_idx, owner.pattern_idx);
                        let prev = earliest.get(&key).copied().unwrap_or(usize::MAX);
                        if m.start() < prev {
                            earliest.insert(key, m.start());
                        }
                    }
                }
            }
        }

        // Regex patterns — run each one once over the
        // payload. We could batch-compile into a RegexSet
        // for first-pass filtering, but the per-pattern
        // path is simpler and avoids re-checking
        // memberships; the IPS service caps regex-bearing
        // signatures at a small fraction of the total set
        // (literals do the bulk of the work).
        for (key, rx) in &self.regex_index {
            let sig = &self.signatures[key.sig_idx];
            if !sig.applies_to(ctx.protocol, ctx.source_port, ctx.destination_port) {
                continue;
            }
            // Walk regex matches with **single-byte slide on
            // anchor rejection**. `regex::bytes::Regex::find_at`
            // returns the leftmost match starting at or after a
            // given position. Plain `find_iter` would not be
            // correct here: for a greedy variable-length pattern
            // like `\d+` against `x12345y` with anchor
            // `offset >= 2`, `find_iter` would return one match
            // `12345` at offset 1 (rejected by the anchor), then
            // skip the remaining payload because it's covered by
            // that match — even though the shorter match `2345`
            // at offset 2 *would* satisfy the anchor. Sliding
            // forward by exactly one byte (`m.start() + 1`) on
            // every rejected match ensures every regex *starting
            // position* in the payload gets a chance to satisfy
            // the anchor, closing this anchor-evasion gap.
            //
            // The slide is bounded by the payload length and the
            // regex matcher's own internal cost; in the typical
            // case (anchor satisfied on the leftmost match) we
            // do exactly one `find_at` call.
            let earliest_key = (key.sig_idx, key.pattern_idx);
            let mut from = 0usize;
            while let Some(m) = rx.find_at(ctx.payload, from) {
                if sig.anchor.permits(m.start(), m.end() - m.start()) {
                    let prev = earliest.get(&earliest_key).copied().unwrap_or(usize::MAX);
                    if m.start() < prev {
                        earliest.insert(earliest_key, m.start());
                    }
                    break;
                }
                // Slide forward by one byte from the rejected
                // match's start so the next `find_at` can pick
                // up a shorter / later match that the anchor
                // would accept. Saturate via the payload bound
                // so the loop terminates even if the regex
                // engine ever returns a zero-width match at the
                // payload end.
                let next = m.start().saturating_add(1);
                if next >= ctx.payload.len() {
                    break;
                }
                from = next;
            }
        }

        // Aggregate per-signature: every pattern must have
        // an entry in `earliest` for the signature to fire.
        let mut hits: Vec<IpsHit> = Vec::new();
        for (sig_idx, sig) in self.signatures.iter().enumerate() {
            if !sig.applies_to(ctx.protocol, ctx.source_port, ctx.destination_port) {
                continue;
            }
            let mut first_offset = usize::MAX;
            let mut all_match = true;
            for pattern_idx in 0..sig.patterns.len() {
                if let Some(off) = earliest.get(&(sig_idx, pattern_idx)) {
                    if *off < first_offset {
                        first_offset = *off;
                    }
                } else {
                    all_match = false;
                    break;
                }
            }
            if all_match {
                hits.push(IpsHit {
                    sid: sig.sid,
                    msg: sig.msg.clone(),
                    severity: sig.severity,
                    action: sig.action,
                    protocol: sig.protocol,
                    first_match_offset: if first_offset == usize::MAX {
                        0
                    } else {
                        first_offset
                    },
                });
            }
        }
        hits.sort_by_key(|h| (h.sid, h.first_match_offset));
        hits
    }
}

impl Default for SignatureSet {
    fn default() -> Self {
        Self::empty()
    }
}

/// `Arc<SignatureSet>` is the wire shape the IPS service
/// hands out. The shape is documented here so consumers can
/// see the intended sharing without reaching into the
/// service module.
pub type SharedSignatureSet = Arc<SignatureSet>;

/// Convenience constructor for the suppression-window
/// dedup key the service uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignatureKey(pub u32);

impl SignatureKey {
    /// Construct from a signature's SID.
    #[must_use]
    pub const fn from_sid(sid: u32) -> Self {
        Self(sid)
    }
}

/// Convenience: a signature that always matches its
/// protocol/port filter — used as a builder shortcut.
#[allow(dead_code)]
pub(crate) fn build_signature(
    sid: u32,
    msg: impl Into<String>,
    severity: Severity,
    action: Action,
    protocol: IpProtocol,
    patterns: Vec<Pattern>,
) -> Signature {
    Signature {
        sid,
        msg: msg.into(),
        severity,
        action,
        protocol,
        ports: PortFilter::default(),
        patterns,
        anchor: Anchor::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn lit(bytes: &[u8]) -> Pattern {
        Pattern::Literal(bytes.to_vec())
    }

    fn regex(src: &str) -> Pattern {
        Pattern::Regex(src.into())
    }

    fn sig_simple(sid: u32, patterns: Vec<Pattern>) -> Signature {
        build_signature(
            sid,
            format!("sid-{sid}"),
            Severity::High,
            Action::Reset,
            IpProtocol::Tcp,
            patterns,
        )
    }

    #[test]
    fn empty_set_returns_no_hits() {
        let s = SignatureSet::empty();
        let hits = s.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"GET / HTTP/1.1",
        });
        assert!(hits.is_empty());
    }

    #[test]
    fn single_literal_signature_hits_on_match() {
        let set = SignatureSet::compile(vec![sig_simple(1001, vec![lit(b"' OR '1'='1")])]).unwrap();
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"GET /search?q=' OR '1'='1-- HTTP/1.1",
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sid, 1001);
        assert!(hits[0].first_match_offset > 0);
    }

    #[test]
    fn single_literal_signature_no_hit_on_miss() {
        let set = SignatureSet::compile(vec![sig_simple(1001, vec![lit(b"' OR '1'='1")])]).unwrap();
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"GET /index.html HTTP/1.1",
        });
        assert!(hits.is_empty());
    }

    #[test]
    fn protocol_filter_skips_signature() {
        let set = SignatureSet::compile(vec![sig_simple(1001, vec![lit(b"' OR '1'='1")])]).unwrap();
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Udp,
            source_port: 0,
            destination_port: 80,
            payload: b"GET /search?q=' OR '1'='1-- HTTP/1.1",
        });
        assert!(hits.is_empty());
    }

    #[test]
    fn port_filter_narrows_to_destination() {
        let mut sig = sig_simple(1001, vec![lit(b"AAAA")]);
        sig.ports = PortFilter {
            source: None,
            destination: Some(80),
        };
        let set = SignatureSet::compile(vec![sig]).unwrap();

        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"AAAA",
        });
        assert_eq!(hits.len(), 1);

        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 443,
            payload: b"AAAA",
        });
        assert!(hits.is_empty());
    }

    #[test]
    fn conjunctive_patterns_require_all_to_match() {
        // SQLi rule: literal AND regex must both match.
        let set = SignatureSet::compile(vec![sig_simple(
            1002,
            vec![lit(b"' OR "), regex(r"(?i)union\s+select")],
        )])
        .unwrap();

        // Only literal hits → no fire.
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"' OR username=1",
        });
        assert!(hits.is_empty(), "expected no hit on partial match");

        // Only regex hits → no fire.
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"foo UNION SELECT user FROM pg_users",
        });
        assert!(hits.is_empty(), "expected no hit when literal missing");

        // Both match → fire.
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"name=foo' OR 1=1 UNION SELECT pass FROM users",
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sid, 1002);
    }

    #[test]
    fn signature_anchor_offset_rejects_early_match() {
        let mut sig = sig_simple(1003, vec![lit(b"BANG")]);
        sig.anchor = Anchor {
            offset: Some(8),
            depth: None,
        };
        let set = SignatureSet::compile(vec![sig]).unwrap();

        // Match at offset 0 → reject.
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"BANG and beyond beyond",
        });
        assert!(hits.is_empty());

        // Match at offset 12 → fire.
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"prefix bytes BANG",
        });
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn signature_anchor_depth_rejects_late_match() {
        let mut sig = sig_simple(1004, vec![lit(b"BANG")]);
        sig.anchor = Anchor {
            offset: None,
            depth: Some(8),
        };
        let set = SignatureSet::compile(vec![sig]).unwrap();

        // Match at offset 0 → fire (within first 8 bytes).
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"BANGheresomemoredata",
        });
        assert_eq!(hits.len(), 1);

        // Match at offset 12 → reject.
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"prefix bytes BANG",
        });
        assert!(hits.is_empty());
    }

    #[test]
    fn regex_signature_finds_later_anchor_satisfying_match() {
        // Pin the architectural contract for the regex
        // scan path: when the leftmost regex match falls
        // OUTSIDE the anchor window, the scan must keep
        // walking matches to find a later one that
        // satisfies the anchor. `rx.find()` alone (which
        // only returns the leftmost match) would
        // false-negative this case.
        let mut sig = sig_simple(2001, vec![regex(r"\d{4}")]);
        sig.anchor = Anchor {
            offset: Some(10),
            depth: None,
        };
        let set = SignatureSet::compile(vec![sig]).unwrap();

        // First match `1234` is at offset 0 (rejected by
        // the offset-10 anchor). Second match `5678` is at
        // offset 13 (satisfies the anchor). The scan must
        // surface a hit.
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"1234 padding 5678",
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sid, 2001);
        // Reported offset should be the anchor-satisfying
        // match, not the rejected leftmost one.
        assert_eq!(hits[0].first_match_offset, 13);
    }

    #[test]
    fn regex_signature_slides_past_anchor_rejected_overlapping_match() {
        // Pins the slide-on-anchor-reject contract. A
        // greedy variable-length pattern like `\d+` against
        // `x12345y` with `offset >= 2` would, under a
        // `find_iter`-only scan, find one non-overlapping
        // match `12345` at offset 1, see the anchor reject
        // it, and stop — because `find_iter` has already
        // consumed every digit. The scan must slide one
        // byte forward and try again so the shorter match
        // `2345` at offset 2 (which the anchor accepts) is
        // still reported. Without the slide this is an
        // anchor-evasion gap.
        let mut sig = sig_simple(2003, vec![regex(r"\d+")]);
        sig.anchor = Anchor {
            offset: Some(2),
            depth: None,
        };
        let set = SignatureSet::compile(vec![sig]).unwrap();
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"x12345y",
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sid, 2003);
        // The slide accepts the shortened match starting
        // at offset 2 (within the anchor window).
        assert_eq!(hits[0].first_match_offset, 2);
    }

    #[test]
    fn regex_signature_no_match_when_all_outside_anchor_depth() {
        // Inverse contract: if EVERY match falls outside
        // the anchor depth window, no hit fires (the scan
        // shouldn't silently relax the anchor).
        let mut sig = sig_simple(2002, vec![regex(r"\d{4}")]);
        sig.anchor = Anchor {
            offset: None,
            depth: Some(4),
        };
        let set = SignatureSet::compile(vec![sig]).unwrap();
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            // First match `1234` at offset 5, length 4 →
            // end=9, depth=4 → rejected. Second match
            // `5678` at offset 18 → also rejected.
            payload: b"abcd 1234 padding 5678",
        });
        assert!(hits.is_empty());
    }

    #[test]
    fn multiple_signatures_yield_multiple_hits() {
        let set = SignatureSet::compile(vec![
            sig_simple(1001, vec![lit(b"AAAA")]),
            sig_simple(1002, vec![lit(b"BBBB")]),
        ])
        .unwrap();
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"prefix AAAA middle BBBB suffix",
        });
        let sids: Vec<u32> = hits.iter().map(|h| h.sid).collect();
        assert_eq!(sids, vec![1001, 1002]);
    }

    #[test]
    fn shared_literal_attributes_to_all_owners() {
        // Both signatures share the literal "'" — the
        // dedup means the automaton only stores it once,
        // but both owners must still see the match.
        let set = SignatureSet::compile(vec![
            sig_simple(1001, vec![lit(b"'"), regex(r"(?i)select")]),
            sig_simple(1002, vec![lit(b"'"), regex(r"(?i)delete")]),
        ])
        .unwrap();
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"name=' OR 1=1; DELETE FROM users; SELECT pass",
        });
        let sids: Vec<u32> = hits.iter().map(|h| h.sid).collect();
        assert_eq!(sids, vec![1001, 1002]);
    }

    #[test]
    fn overlapping_literal_patterns_from_different_signatures_both_fire() {
        // Regression for the IPS-evasion bug where
        // `find_iter` (non-overlapping) would let the
        // first signature's literal "GET " shadow the
        // second signature's literal "ET /etc/passwd"
        // that starts at offset 1. Both signatures MUST
        // fire on a single payload that contains them
        // both.
        let set = SignatureSet::compile(vec![
            sig_simple(2001, vec![lit(b"GET ")]),
            sig_simple(2002, vec![lit(b"ET /etc/passwd")]),
        ])
        .unwrap();
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"GET /etc/passwd HTTP/1.0\r\n",
        });
        let sids: Vec<u32> = hits.iter().map(|h| h.sid).collect();
        assert!(sids.contains(&2001), "sid 2001 (GET ) must fire");
        assert!(sids.contains(&2002), "sid 2002 (ET /etc/passwd) must fire");
    }

    #[test]
    fn invalid_regex_returns_invalid_signature_error() {
        let sig = sig_simple(1005, vec![regex("(unbalanced")]);
        let e = SignatureSet::compile(vec![sig]).unwrap_err();
        match e {
            IpsError::InvalidSignature { sid, .. } => assert_eq!(sid, 1005),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn empty_pattern_list_returns_invalid_signature_error() {
        let sig = sig_simple(1006, vec![]);
        let e = SignatureSet::compile(vec![sig]).unwrap_err();
        match e {
            IpsError::InvalidSignature { sid, reason } => {
                assert_eq!(sid, 1006);
                assert!(reason.contains("no patterns"));
            }
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn empty_literal_pattern_returns_invalid_signature_error() {
        let sig = sig_simple(1007, vec![lit(&[])]);
        let e = SignatureSet::compile(vec![sig]).unwrap_err();
        match e {
            IpsError::InvalidSignature { sid, reason } => {
                assert_eq!(sid, 1007);
                assert!(reason.contains("empty"));
            }
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn fold_action_picks_more_severe() {
        assert_eq!(
            IpsHit::fold_action(Action::Alert, Action::Drop),
            Action::Drop
        );
        assert_eq!(
            IpsHit::fold_action(Action::Drop, Action::Alert),
            Action::Drop
        );
        assert_eq!(
            IpsHit::fold_action(Action::Reset, Action::Block),
            Action::Reset
        );
        assert_eq!(
            IpsHit::fold_action(Action::Drop, Action::Reset),
            Action::Drop
        );
    }

    #[test]
    fn hits_are_sorted_by_sid_and_offset() {
        let set = SignatureSet::compile(vec![
            sig_simple(2001, vec![lit(b"BBBB")]),
            sig_simple(2000, vec![lit(b"AAAA")]),
        ])
        .unwrap();
        let hits = set.scan(ScanContext {
            protocol: IpProtocol::Tcp,
            source_port: 0,
            destination_port: 80,
            payload: b"BBBB AAAA",
        });
        // Lower SID first.
        assert_eq!(hits[0].sid, 2000);
        assert_eq!(hits[1].sid, 2001);
    }

    #[test]
    fn signature_key_from_sid() {
        assert_eq!(SignatureKey::from_sid(42), SignatureKey(42));
    }

    #[test]
    fn signature_set_len_and_is_empty() {
        assert_eq!(SignatureSet::empty().len(), 0);
        assert!(SignatureSet::empty().is_empty());
        let set = SignatureSet::compile(vec![sig_simple(1, vec![lit(b"x")])]).unwrap();
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
    }

    #[test]
    fn signature_set_get_and_signatures() {
        let set = SignatureSet::compile(vec![
            sig_simple(1, vec![lit(b"x")]),
            sig_simple(2, vec![lit(b"y")]),
        ])
        .unwrap();
        assert_eq!(set.get(0).unwrap().sid, 1);
        assert_eq!(set.get(1).unwrap().sid, 2);
        assert!(set.get(2).is_none());
        assert_eq!(set.signatures().len(), 2);
    }
}
