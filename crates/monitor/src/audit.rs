//! Audit log: a BLAKE2s-256 hash chain over every verdict the monitor issues.
//!
//! Every verdict (ALLOW or any DENY/ERR) is folded into a running 256-bit
//! commitment (`head`) so that any reordering, omission, or edit of a past
//! entry changes the head and is detectable. A bounded ring keeps the most
//! recent `AUDIT_RING` entries in memory for local inspection (the
//! `ATTEST_READ` opcode reads the head); the head itself commits to the
//! entire history, even entries the ring has since overwritten.
//!
//! Fully deterministic: no clock, no RNG, no global state. `no_std`, no
//! `alloc` — the ring is a fixed inline array and the chain step serializes
//! each entry into a local `[u8; 41]` buffer.
#![forbid(unsafe_code)]

use blake2::{Blake2s256, Digest};

/// Recent-entry ring capacity: the `Audit::ring` buffer holds the most
/// recently appended `AUDIT_RING` entries. The chain `head` commits to every
/// entry ever appended, regardless of ring capacity.
pub const AUDIT_RING: usize = 64;

/// Fixed on-wire serialization length of one `Entry` (see `Entry::serialize`).
const ENTRY_BYTES: usize = 41;

/// One verdict record. Fully deterministic (no clock/RNG). `seq` is stamped
/// by `Audit::append`; callers construct an `Entry` with `seq = 0` and let
/// the log assign it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Monotonic sequence number, assigned by `Audit::append`.
    pub seq: u32,
    pub session_id: u16,
    pub tool_id: u16,
    /// `abi::ReasonCode` as `u8`.
    pub reason: u8,
    /// BLAKE2s-256 of the request bytes; binds the entry to what was
    /// decided.
    pub req_hash: [u8; 32],
}

impl Entry {
    /// Canonical 41-byte little-endian serialization folded into the chain:
    /// `seq(4) || session_id(2) || tool_id(2) || reason(1) || req_hash(32)`.
    fn serialize(&self) -> [u8; ENTRY_BYTES] {
        let mut out = [0u8; ENTRY_BYTES];
        out[0..4].copy_from_slice(&self.seq.to_le_bytes());
        out[4..6].copy_from_slice(&self.session_id.to_le_bytes());
        out[6..8].copy_from_slice(&self.tool_id.to_le_bytes());
        out[8] = self.reason;
        out[9..41].copy_from_slice(&self.req_hash);
        out
    }
}

/// A tamper-evident audit log: a BLAKE2s-256 hash chain over every appended
/// verdict, plus a bounded ring of the most recent entries for local
/// inspection.
pub struct Audit {
    head: [u8; 32],
    ring: [Entry; AUDIT_RING],
    /// Total entries appended so far (also the next `seq` to assign).
    count: u64,
}

impl Default for Audit {
    fn default() -> Self {
        let zero_entry =
            Entry { seq: 0, session_id: 0, tool_id: 0, reason: 0, req_hash: [0u8; 32] };
        Audit { head: [0u8; 32], ring: [zero_entry; AUDIT_RING], count: 0 }
    }
}

impl Audit {
    /// Append a verdict: stamp `e.seq = self.count`, fold it into the chain
    /// (`head = BLAKE2s256(old_head || serialize(e))`), store it in the ring
    /// at `count % AUDIT_RING`, and increment `count`. Never panics, never
    /// allocates.
    pub fn append(&mut self, mut e: Entry) {
        e.seq = self.count as u32;

        let bytes = e.serialize();
        let mut h = Blake2s256::new();
        h.update(self.head);
        h.update(bytes);
        let out = h.finalize();
        self.head.copy_from_slice(&out);

        // count % AUDIT_RING is always < AUDIT_RING (AUDIT_RING > 0), so
        // this index is provably in bounds.
        let slot = (self.count % AUDIT_RING as u64) as usize;
        self.ring[slot] = e;

        self.count = self.count.wrapping_add(1);
    }

    /// The current chain head: a 256-bit commitment to the whole verdict
    /// history.
    pub fn head(&self) -> [u8; 32] {
        self.head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::ReasonCode;

    fn entry(reason: ReasonCode) -> Entry {
        Entry { seq: 0, session_id: 1, tool_id: 7, reason: reason as u8, req_hash: [0u8; 32] }
    }

    fn replay(entries: &[Entry]) -> [u8; 32] {
        let mut a = Audit::default();
        for &e in entries {
            a.append(e);
        }
        a.head()
    }

    #[test]
    fn every_verdict_advances_head() {
        let mut a = Audit::default();
        let h0 = a.head();
        a.append(entry(ReasonCode::Allow));
        let h1 = a.head();
        assert_ne!(h0, h1);
        a.append(entry(ReasonCode::DenyArg));
        assert_ne!(h1, a.head());
    }

    #[test]
    fn chain_is_deterministic() {
        let entries = [entry(ReasonCode::Allow), entry(ReasonCode::DenyArg), entry(ReasonCode::Allow)];
        assert_eq!(replay(&entries), replay(&entries));
    }

    #[test]
    fn identical_entries_still_advance_head() {
        let mut a = Audit::default();
        a.append(entry(ReasonCode::Allow));
        let h1 = a.head();
        a.append(entry(ReasonCode::Allow));
        let h2 = a.head();
        assert_ne!(h1, h2);
    }

    #[test]
    fn order_matters_for_tamper_evidence() {
        let a = entry(ReasonCode::Allow);
        let b = entry(ReasonCode::DenyArg);
        assert_ne!(replay(&[a, b]), replay(&[b, a]));
    }

    #[test]
    fn ring_wrap_keeps_chain_intact() {
        let n = AUDIT_RING + 3;
        let entries: heapless_entries::EntryBuf = heapless_entries::build(n);

        let mut a = Audit::default();
        for &e in entries.as_slice() {
            a.append(e);
        }

        let expected = replay(entries.as_slice());
        assert_eq!(a.head(), expected);

        // The retained ring entries carry monotonic seqs: the ring holds the
        // most recent AUDIT_RING appends, whose seqs are
        // (n - AUDIT_RING) ..= (n - 1), in circular order.
        let first_retained_seq = (n - AUDIT_RING) as u32;
        for i in 0..AUDIT_RING {
            let slot = (i as u32).wrapping_add(first_retained_seq) as usize % AUDIT_RING;
            assert_eq!(a.ring[slot].seq, first_retained_seq + i as u32);
        }
    }

    // Small no-alloc helper to build a variable-length run of distinct
    // entries for the wrap test, without pulling in `alloc`/`std::vec`.
    mod heapless_entries {
        use super::Entry;

        pub const MAX: usize = 128;

        pub struct EntryBuf {
            buf: [Entry; MAX],
            len: usize,
        }

        impl EntryBuf {
            pub fn as_slice(&self) -> &[Entry] {
                &self.buf[..self.len]
            }
        }

        pub fn build(n: usize) -> EntryBuf {
            assert!(n <= MAX);
            let zero = Entry { seq: 0, session_id: 0, tool_id: 0, reason: 0, req_hash: [0u8; 32] };
            let mut buf = [zero; MAX];
            for (i, slot) in buf.iter_mut().enumerate().take(n) {
                *slot = Entry {
                    seq: 0,
                    session_id: (i as u16).wrapping_add(1),
                    tool_id: 7,
                    reason: (i % 2) as u8,
                    req_hash: [0u8; 32],
                };
            }
            EntryBuf { buf, len: n }
        }
    }
}
