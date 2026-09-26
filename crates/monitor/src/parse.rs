//! Parser guard: proves an incoming request lies fully inside the shared
//! SHARED_REQ region and copies it into private memory BEFORE any decoding
//! is attempted.
//!
//! This copy-before-decode ordering is the load-bearing anti-TOCTOU step: a
//! hostile co-resident component with write access to the shared region
//! cannot mutate the bytes after they have been validated but before they
//! are decoded, because decoding only ever inspects the private copy, never
//! `shared` again.
#![forbid(unsafe_code)]

use abi::{ReasonCode, RequestView};
use core::ops::Range;

/// Maximum total encoded request size, in bytes. This mirrors
/// `abi::MAX_REQ` (the wire codec's own limit) rather than duplicating a
/// second magic number: the private scratch buffer this module fills must
/// be exactly large enough to hold anything `abi::decode_request` could
/// ever accept, and no larger.
pub const MAX_REQ: usize = abi::MAX_REQ;

/// Bounds-check `[ptr, ptr+len)` against `region`, copy that byte range out
/// of `shared` into the caller-owned private `scratch` buffer, and only
/// then decode the copy.
///
/// # Why `scratch` is a parameter instead of a local
///
/// The returned `RequestView<'a>` must borrow the *private copy*, not
/// `shared` (that's the whole point of this guard). A private copy created
/// as a local inside this function would be dropped when the function
/// returns, so a view borrowing it could never be returned by value: Rust
/// has no way to express "return something that borrows a buffer this
/// function allocates" without heap allocation (unavailable: no_std,
/// no-alloc) or a self-referential type (unsafe, forbidden in this
/// module). So the caller owns the scratch buffer's storage and lends it
/// to us for lifetime `'a`; this function only ever writes into it. This
/// also matches the real call site: `mediate()` (Task 14) owns one
/// long-lived scratch buffer and reuses it across requests rather than
/// allocating a fresh one per call.
///
/// # Bounds proof
///
/// `ptr + len` is computed with `checked_add`, so a caller-supplied
/// `(ptr, len)` pair that would overflow `usize` is rejected outright
/// instead of silently wrapping to a small `end` that could slip past a
/// naive range check. The resulting range must satisfy
/// `region.start <= ptr` and `ptr + len <= region.end`, which proves the
/// entire request lies inside the SHARED_REQ region before a single byte
/// of it is read. The slice out of `shared` is taken with `.get(..)`
/// (never direct indexing), so even a `region` that disagrees with
/// `shared`'s actual length cannot panic.
///
/// Only after all of the above succeeds does this function copy `len`
/// bytes into `scratch` and hand the copy — never `shared` — to
/// `abi::decode_request`.
pub fn parse_into<'a>(
    shared: &[u8],
    ptr: usize,
    len: usize,
    region: Range<usize>,
    scratch: &'a mut [u8; MAX_REQ],
) -> Result<RequestView<'a>, ReasonCode> {
    if len > MAX_REQ {
        return Err(ReasonCode::DenyMalformed);
    }

    let end = ptr.checked_add(len).ok_or(ReasonCode::DenyMalformed)?;

    if ptr < region.start || end > region.end {
        return Err(ReasonCode::DenyMalformed);
    }

    let src = shared.get(ptr..end).ok_or(ReasonCode::DenyMalformed)?;

    // Copy BEFORE decode: everything below this line reads only the
    // private `scratch` copy. `shared` is never touched again.
    scratch[..len].copy_from_slice(src);

    abi::decode_request(&scratch[..len])
}

#[cfg(test)]
mod tests {
    // Test-only: build byte fixtures with `Vec`/`std::vec!`. The module
    // under test (`parse_into` above) remains no_std/no-alloc; this only
    // affects the host test harness for `cargo test -p monitor`.
    extern crate std;

    use super::*;
    use std::vec::Vec;

    const HEADER_LEN: usize = 16;

    /// Build a minimal, structurally valid request: header only, zero
    /// args, zero trailing labels.
    fn build_minimal_request() -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN);
        v.extend_from_slice(&abi::MAGIC.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // session_id
        v.extend_from_slice(&2u16.to_le_bytes()); // req_id
        v.extend_from_slice(&3u16.to_le_bytes()); // cap_handle
        v.extend_from_slice(&4u16.to_le_bytes()); // tool_id
        v.push(0); // n_args
        v.push(0); // reserved
        v.extend_from_slice(&0u16.to_le_bytes()); // labels_len
        v
    }

    /// Build a `shared` buffer larger than `region`, with a valid request
    /// placed at `region.start + 4` inside the region. Returns
    /// `(shared, region, ok_ptr, ok_len)`.
    fn fixture() -> (Vec<u8>, Range<usize>, usize, usize) {
        let region = 64usize..192usize;
        let req = build_minimal_request();
        let mut shared = std::vec![0u8; region.end + 64];
        let ok_ptr = region.start + 4;
        shared[ok_ptr..ok_ptr + req.len()].copy_from_slice(&req);
        (shared, region, ok_ptr, req.len())
    }

    #[test]
    fn ptr_outside_region_denies() {
        let (shared, region, _ok_ptr, ok_len) = fixture();
        let mut scratch = [0u8; MAX_REQ];
        let err = parse_into(&shared, region.start - 4, ok_len, region.clone(), &mut scratch)
            .unwrap_err();
        assert_eq!(err, ReasonCode::DenyMalformed);
    }

    #[test]
    fn end_past_region_denies() {
        let (shared, region, _ok_ptr, _ok_len) = fixture();
        let mut scratch = [0u8; MAX_REQ];
        // ptr itself is inside the region, but ptr+len overruns region.end.
        let ptr = region.end - 4;
        let err = parse_into(&shared, ptr, 16, region.clone(), &mut scratch).unwrap_err();
        assert_eq!(err, ReasonCode::DenyMalformed);
    }

    #[test]
    fn valid_request_copies_and_decodes() {
        let (shared, region, ok_ptr, ok_len) = fixture();
        let mut scratch = [0u8; MAX_REQ];
        let view = parse_into(&shared, ok_ptr, ok_len, region, &mut scratch).unwrap();
        assert_eq!(view.session_id, 1);
        assert_eq!(view.req_id, 2);
        assert_eq!(view.cap_handle, 3);
        assert_eq!(view.tool_id, 4);
        assert_eq!(view.args.count(), 0);
    }

    #[test]
    fn ptr_plus_len_overflow_denies() {
        let (shared, region, _ok_ptr, _ok_len) = fixture();
        let mut scratch = [0u8; MAX_REQ];
        // ptr + len must overflow usize, not merely be large.
        let err = parse_into(&shared, usize::MAX - 4, 16, region, &mut scratch).unwrap_err();
        assert_eq!(err, ReasonCode::DenyMalformed);
    }

    #[test]
    fn len_over_max_req_denies() {
        let (shared, region, ok_ptr, _ok_len) = fixture();
        let mut scratch = [0u8; MAX_REQ];
        let err = parse_into(&shared, ok_ptr, MAX_REQ + 1, region, &mut scratch).unwrap_err();
        assert_eq!(err, ReasonCode::DenyMalformed);
    }

    #[test]
    fn returned_view_borrows_private_copy_not_shared() {
        // Decode successfully, then mutate `shared` in place at the same
        // bytes the request was copied from. If the returned view were
        // (incorrectly) borrowing `shared`, this would either fail to
        // compile (borrow checker catching the aliasing) or the view's
        // fields would observe the mutation. Here we simply confirm the
        // view remains valid and unchanged after `shared` is dropped,
        // which is only possible because it borrows `scratch`, not
        // `shared`.
        let (shared, region, ok_ptr, ok_len) = fixture();
        let mut scratch = [0u8; MAX_REQ];
        let view = parse_into(&shared, ok_ptr, ok_len, region, &mut scratch).unwrap();
        drop(shared);
        assert_eq!(view.session_id, 1);
    }
}
