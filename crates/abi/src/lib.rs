#![no_std]
#![forbid(unsafe_code)]

pub const MAGIC: u32 = u32::from_le_bytes(*b"RDBT");

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ReasonCode {
    Allow = 0x00,
    DenyNoCap = 0x10,
    DenyTool = 0x11,
    DenyArg = 0x12,
    DenyFlow = 0x13,
    DenyMalformed = 0x14,
    DenyRevoked = 0x15,
    DenyQuota = 0x16,
    ErrEgress = 0x20,
    ErrTimeout = 0x21,
    ErrInternal = 0x2F,
}

#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Opcode {
    Mediate = 0x5244_0001,
    SessionOpen = 0x5244_0010,
    SessionRevoke = 0x5244_0011,
    SessionClose = 0x5244_0012,
    AttestRead = 0x5244_0020,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Label(pub u8); // bit0 = confidentiality (1=SECRET), bit1 = integrity (1=TRUSTED)

impl Label {
    pub const PUBLIC: Label = Label(0);
    pub const SECRET: Label = Label(0b01);
    pub const UNTRUSTED: Label = Label(0);
    pub const TRUSTED: Label = Label(0b10);

    pub fn is_secret(self) -> bool {
        self.0 & 0b01 != 0
    }
}

// ---------------------------------------------------------------------------
// Request / TypedArg wire codec
//
// Wire format (all integers little-endian; no padding beyond what is listed):
//
//   Header (16 bytes):
//     magic:       u32   (must equal MAGIC)
//     session_id:  u16
//     req_id:      u16
//     cap_handle:  u16
//     tool_id:     u16
//     n_args:      u8    (must be <= MAX_ARGS)
//     reserved:    u8    (ignored on decode)
//     labels_len:  u16   (length in bytes of the trailing in_labels blob)
//
//   Args section: exactly `n_args` TLV entries back-to-back, each:
//     tag: u8, len: u16, value: [u8; len]
//
//   Labels section: exactly `labels_len` bytes, running to the end of `buf`.
//
// `buf.len()` must exactly account for header + all TLVs + labels_len; any
// shortfall or trailing garbage is DenyMalformed. This is a deliberate
// stricter-than-necessary rule: it removes any ambiguity a hostile sender
// could otherwise exploit (e.g. smuggling extra bytes past a nominally
// "valid" prefix).
// ---------------------------------------------------------------------------

/// Maximum total encoded request size, in bytes.
pub const MAX_REQ: usize = 512;

/// Maximum number of TypedArg entries a request may carry.
pub const MAX_ARGS: usize = 8;

/// Fixed header size: magic(4) + session_id(2) + req_id(2) + cap_handle(2)
/// + tool_id(2) + n_args(1) + reserved(1) + labels_len(2) = 16 bytes.
const HEADER_LEN: usize = 16;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Scheme {
    Http,
    Https,
}

/// Pre-split URL fields as decoded off the wire. `host` is the
/// security-relevant field consumed by later predicate matching
/// (see `monitor::predicate`): it is borrowed verbatim from the input
/// buffer, never re-parsed or reinterpreted (no stripping of credential
/// prefixes, trailing dots, or percent-decoding), and is guaranteed to
/// contain no uppercase ASCII letters (see `parse_url` for why decode
/// enforces this instead of folding case in place).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct UrlParts<'a> {
    pub scheme: Scheme,
    pub host: &'a [u8],
    pub port: u16,
    pub path: &'a [u8],
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ArgVal<'a> {
    Url(UrlParts<'a>),
    Path(&'a [u8]),
    Enum(u16),
    Int(i64),
    Bytes(&'a [u8]),
    LabelSet(Label),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TypedArg<'a> {
    pub tag: u8,
    pub val: ArgVal<'a>,
}

/// Zero-copy, lazy iterator over a request's already-bounds-validated TLV
/// args section. All structural validation happens eagerly in
/// `decode_request`; by construction every step of this iterator succeeds.
/// The `Err` arm in `next` is unreachable in practice but is handled by
/// stopping iteration rather than panicking or indexing out of bounds, so a
/// bug elsewhere in this module can never turn into a panic on hostile
/// input.
#[derive(Debug)]
pub struct ArgsIter<'a> {
    buf: &'a [u8],
    remaining: usize,
}

impl<'a> Iterator for ArgsIter<'a> {
    type Item = TypedArg<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        match parse_tlv(self.buf) {
            Ok((arg, consumed)) => {
                self.buf = &self.buf[consumed..];
                self.remaining -= 1;
                Some(arg)
            }
            Err(_) => {
                // Should not happen post-validation; fail closed by ending
                // iteration instead of panicking.
                self.remaining = 0;
                None
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

#[derive(Debug)]
pub struct RequestView<'a> {
    pub session_id: u16,
    pub req_id: u16,
    pub cap_handle: u16,
    pub tool_id: u16,
    pub args: ArgsIter<'a>,
    pub in_labels: &'a [u8],
}

/// Decode one TLV (tag, u16 len, value) from the front of `buf`, returning
/// the parsed arg and the number of bytes consumed. Bounds are checked
/// before every slice; nothing here can index out of bounds or overflow.
fn parse_tlv(buf: &[u8]) -> Result<(TypedArg<'_>, usize), ReasonCode> {
    if buf.len() < 3 {
        return Err(ReasonCode::DenyMalformed);
    }
    let tag = buf[0];
    let len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
    let total = 3usize.checked_add(len).ok_or(ReasonCode::DenyMalformed)?;
    if total > buf.len() {
        return Err(ReasonCode::DenyMalformed);
    }
    let value = &buf[3..total];

    let val = match tag {
        0x01 => ArgVal::Url(parse_url(value)?),
        0x02 => ArgVal::Path(value),
        0x03 => {
            if value.len() != 2 {
                return Err(ReasonCode::DenyMalformed);
            }
            ArgVal::Enum(u16::from_le_bytes([value[0], value[1]]))
        }
        0x04 => {
            if value.len() != 8 {
                return Err(ReasonCode::DenyMalformed);
            }
            let mut a = [0u8; 8];
            a.copy_from_slice(value);
            ArgVal::Int(i64::from_le_bytes(a))
        }
        0x05 => ArgVal::Bytes(value),
        0x06 => {
            if value.len() != 1 {
                return Err(ReasonCode::DenyMalformed);
            }
            ArgVal::LabelSet(Label(value[0]))
        }
        _ => return Err(ReasonCode::DenyMalformed),
    };
    Ok((TypedArg { tag, val }, total))
}

/// Decode a URL TLV's value into `UrlParts`. The wire format carries the
/// URL fields pre-split by the sender (scheme byte, then length-prefixed
/// host, then port, then length-prefixed path) — this function does not
/// parse a raw URL string, it only splits/validates the already-separated
/// fields, so there is no ambiguity for a raw-text URL parser to get wrong.
///
/// `host` is returned as the exact borrowed byte range the sender supplied:
/// no credential-prefix stripping, no trailing-dot trimming, no
/// percent-decoding. Because `decode_request` takes an immutable, zero-copy
/// `&[u8]` (no alloc, no scratch buffer to write a folded-case copy into),
/// true in-place lower-casing is not possible without violating either the
/// zero-copy contract or `#![forbid(unsafe_code)]`. Instead this decoder
/// enforces "host is lower-case" as an output invariant by rejecting any
/// host containing an uppercase ASCII letter as `DenyMalformed` — so every
/// `UrlParts.host` that successfully decodes is guaranteed already
/// lower-case, without ever mutating or reinterpreting the bytes.
fn parse_url(value: &[u8]) -> Result<UrlParts<'_>, ReasonCode> {
    let mut off = 0usize;

    let scheme_byte = *value.first().ok_or(ReasonCode::DenyMalformed)?;
    let scheme = match scheme_byte {
        0 => Scheme::Http,
        1 => Scheme::Https,
        _ => return Err(ReasonCode::DenyMalformed),
    };
    off += 1;

    if value.len() < off + 2 {
        return Err(ReasonCode::DenyMalformed);
    }
    let host_len = u16::from_le_bytes([value[off], value[off + 1]]) as usize;
    off += 2;
    if value.len() < off + host_len {
        return Err(ReasonCode::DenyMalformed);
    }
    let host = &value[off..off + host_len];
    off += host_len;
    if host.iter().any(u8::is_ascii_uppercase) {
        return Err(ReasonCode::DenyMalformed);
    }

    if value.len() < off + 2 {
        return Err(ReasonCode::DenyMalformed);
    }
    let port = u16::from_le_bytes([value[off], value[off + 1]]);
    off += 2;

    if value.len() < off + 2 {
        return Err(ReasonCode::DenyMalformed);
    }
    let path_len = u16::from_le_bytes([value[off], value[off + 1]]) as usize;
    off += 2;
    if value.len() < off + path_len {
        return Err(ReasonCode::DenyMalformed);
    }
    let path = &value[off..off + path_len];
    off += path_len;

    // Exact consumption: no trailing junk left inside the URL TLV's value.
    if off != value.len() {
        return Err(ReasonCode::DenyMalformed);
    }

    Ok(UrlParts { scheme, host, port, path })
}

/// Decode a wire-format request. Bounds are validated before anything else
/// is trusted: overall length, magic, arg count, then every TLV's declared
/// length against the remaining buffer. Returns borrowed slices into `buf`
/// (zero-copy, no allocation) or `ReasonCode::DenyMalformed` on any
/// structural problem. Never panics or indexes out of bounds on hostile
/// input.
pub fn decode_request(buf: &[u8]) -> Result<RequestView<'_>, ReasonCode> {
    if buf.len() > MAX_REQ {
        return Err(ReasonCode::DenyMalformed);
    }
    if buf.len() < HEADER_LEN {
        return Err(ReasonCode::DenyMalformed);
    }

    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != MAGIC {
        return Err(ReasonCode::DenyMalformed);
    }

    let session_id = u16::from_le_bytes([buf[4], buf[5]]);
    let req_id = u16::from_le_bytes([buf[6], buf[7]]);
    let cap_handle = u16::from_le_bytes([buf[8], buf[9]]);
    let tool_id = u16::from_le_bytes([buf[10], buf[11]]);
    let n_args = buf[12] as usize;
    // buf[13] is reserved and intentionally ignored.
    let labels_len = u16::from_le_bytes([buf[14], buf[15]]) as usize;

    if n_args > MAX_ARGS {
        return Err(ReasonCode::DenyMalformed);
    }

    let mut offset = HEADER_LEN;
    for _ in 0..n_args {
        let (_, consumed) = parse_tlv(&buf[offset..])?;
        offset = offset.checked_add(consumed).ok_or(ReasonCode::DenyMalformed)?;
    }
    let args_end = offset;

    // args_end <= buf.len() is an invariant of the loop above (parse_tlv
    // only ever consumes bytes that exist within its input slice).
    let trailing = buf.len() - args_end;
    if trailing != labels_len {
        return Err(ReasonCode::DenyMalformed);
    }
    let in_labels = &buf[args_end..];

    let args = ArgsIter { buf: &buf[HEADER_LEN..args_end], remaining: n_args };

    Ok(RequestView { session_id, req_id, cap_handle, tool_id, args, in_labels })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_codes_have_spec_values() {
        assert_eq!(ReasonCode::Allow as u8, 0x00);
        assert_eq!(ReasonCode::DenyArg as u8, 0x12);
        assert_eq!(ReasonCode::DenyFlow as u8, 0x13);
        assert_eq!(ReasonCode::ErrTimeout as u8, 0x21);
        assert_eq!(Opcode::Mediate as u32, 0x5244_0001);
        assert_eq!(MAGIC, u32::from_le_bytes(*b"RDBT"));
    }
}

#[cfg(test)]
mod codec_tests {
    // Test-only: the codec itself is no_std/no-alloc; the test harness for a
    // host `cargo test -p abi` run always links std, so borrowing it here to
    // build byte buffers with `Vec` does not weaken the crate's own no_std/
    // no-alloc/zero-copy guarantees (enforced by `#![no_std]` + `#![forbid(unsafe_code)]`
    // on the crate and by the codec functions borrowing from `buf` only).
    extern crate std;

    use super::*;
    use std::vec::Vec;

    const HEADER_LEN: usize = 16;

    struct Req<'a> {
        session: u16,
        req_id: u16,
        cap: u16,
        tool: u16,
        args: &'a [(u8, &'a [u8])],
        labels: &'a [u8],
    }

    fn header(session: u16, req_id: u16, cap: u16, tool: u16, n_args: u8, labels_len: u16) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN);
        v.extend_from_slice(&MAGIC.to_le_bytes());
        v.extend_from_slice(&session.to_le_bytes());
        v.extend_from_slice(&req_id.to_le_bytes());
        v.extend_from_slice(&cap.to_le_bytes());
        v.extend_from_slice(&tool.to_le_bytes());
        v.push(n_args);
        v.push(0); // reserved
        v.extend_from_slice(&labels_len.to_le_bytes());
        v
    }

    fn build(req: &Req) -> Vec<u8> {
        let mut v = header(
            req.session,
            req.req_id,
            req.cap,
            req.tool,
            req.args.len() as u8,
            req.labels.len() as u16,
        );
        for (tag, val) in req.args {
            v.push(*tag);
            v.extend_from_slice(&(val.len() as u16).to_le_bytes());
            v.extend_from_slice(val);
        }
        v.extend_from_slice(req.labels);
        v
    }

    fn build_with_n_args(n: u8) -> Vec<u8> {
        // n_args alone triggers the MAX_ARGS bound before any TLV is read,
        // so a bare header with no argument bytes is a sufficient fixture.
        header(0, 0, 0, 0, n, 0)
    }

    fn encode_url_value(scheme: u8, host: &[u8], port: u16, path: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(scheme);
        v.extend_from_slice(&(host.len() as u16).to_le_bytes());
        v.extend_from_slice(host);
        v.extend_from_slice(&port.to_le_bytes());
        v.extend_from_slice(&(path.len() as u16).to_le_bytes());
        v.extend_from_slice(path);
        v
    }

    fn build_url_arg() -> Vec<u8> {
        let url_val = encode_url_value(1, b"example.com", 443, b"/x");
        build(&Req {
            session: 1,
            req_id: 2,
            cap: 3,
            tool: 4,
            args: &[(0x01, &url_val)],
            labels: &[],
        })
    }

    fn truncate(buf: Vec<u8>, drop: usize) -> Vec<u8> {
        let keep = buf.len() - drop;
        buf[..keep].to_vec()
    }

    #[test]
    fn decodes_minimal_request() {
        let buf = build(&Req {
            session: 1,
            req_id: 7,
            cap: 3,
            tool: 0x1000,
            args: &[],
            labels: &[],
        });
        let r = decode_request(&buf).unwrap();
        assert_eq!((r.session_id, r.cap_handle, r.tool_id), (1, 3, 0x1000));
        assert_eq!(r.req_id, 7);
        assert_eq!(r.in_labels, &[] as &[u8]);
        assert_eq!(r.args.count(), 0);
    }

    #[test]
    fn rejects_bad_magic() {
        assert_eq!(decode_request(&[0, 0, 0, 0]).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn rejects_too_many_args() {
        let b = build_with_n_args(9);
        assert_eq!(decode_request(&b).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn rejects_truncated_tlv() {
        let b = truncate(build_url_arg(), 3);
        assert_eq!(decode_request(&b).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn rejects_len_over_max() {
        assert_eq!(decode_request(&[0u8; MAX_REQ + 1][..]).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn decodes_url_arg_with_lowercase_host() {
        let buf = build_url_arg();
        let r = decode_request(&buf).unwrap();
        let args: Vec<TypedArg> = r.args.collect();
        assert_eq!(args.len(), 1);
        match &args[0].val {
            ArgVal::Url(parts) => {
                assert_eq!(parts.scheme, Scheme::Https);
                assert_eq!(parts.host, b"example.com");
                assert_eq!(parts.port, 443);
                assert_eq!(parts.path, b"/x");
            }
            _ => panic!("expected Url arg"),
        }
    }

    #[test]
    fn rejects_uppercase_host_as_malformed() {
        // decode_request cannot mutate its immutable, zero-copy input to fold
        // case in place, so it enforces the "host is lower-case" invariant by
        // rejecting any non-lowercase host outright rather than silently
        // reinterpreting it.
        let url_val = encode_url_value(1, b"Example.com", 443, b"/x");
        let buf = build(&Req {
            session: 1,
            req_id: 1,
            cap: 1,
            tool: 1,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        assert_eq!(decode_request(&buf).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn host_with_embedded_credentials_is_kept_faithful_not_masqueraded() {
        // A host field that (illegitimately) embeds "user@host" syntax must
        // NOT be reinterpreted/split by the decoder; it is passed through
        // byte-for-byte so later exact/allow-list matching sees the whole
        // literal string and fails closed rather than matching on a
        // naively-extracted suffix.
        let raw_host = b"user@evil.tld@api.example.com";
        let url_val = encode_url_value(1, raw_host, 443, b"/");
        let buf = build(&Req {
            session: 1,
            req_id: 1,
            cap: 1,
            tool: 1,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let r = decode_request(&buf).unwrap();
        let args: Vec<TypedArg> = r.args.collect();
        match &args[0].val {
            ArgVal::Url(parts) => assert_eq!(parts.host, &raw_host[..]),
            _ => panic!("expected Url arg"),
        }
    }

    #[test]
    fn trailing_dot_is_preserved_not_stripped() {
        let raw_host = b"api.example.com.";
        let url_val = encode_url_value(1, raw_host, 443, b"/");
        let buf = build(&Req {
            session: 1,
            req_id: 1,
            cap: 1,
            tool: 1,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let r = decode_request(&buf).unwrap();
        let args: Vec<TypedArg> = r.args.collect();
        match &args[0].val {
            ArgVal::Url(parts) => assert_eq!(parts.host, &raw_host[..]),
            _ => panic!("expected Url arg"),
        }
    }

    #[test]
    fn percent_encoding_in_host_is_preserved_not_decoded() {
        let raw_host = b"api%2eexample.com";
        let url_val = encode_url_value(1, raw_host, 443, b"/");
        let buf = build(&Req {
            session: 1,
            req_id: 1,
            cap: 1,
            tool: 1,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let r = decode_request(&buf).unwrap();
        let args: Vec<TypedArg> = r.args.collect();
        match &args[0].val {
            ArgVal::Url(parts) => assert_eq!(parts.host, &raw_host[..]),
            _ => panic!("expected Url arg"),
        }
    }

    #[test]
    fn decodes_all_typed_arg_tags() {
        let path_val = b"/a/b".to_vec();
        let enum_val = 7u16.to_le_bytes().to_vec();
        let int_val = (-42i64).to_le_bytes().to_vec();
        let bytes_val = b"blob".to_vec();
        let labelset_val = [Label::SECRET.0].to_vec();

        let buf = build(&Req {
            session: 1,
            req_id: 1,
            cap: 1,
            tool: 1,
            args: &[
                (0x02, &path_val),
                (0x03, &enum_val),
                (0x04, &int_val),
                (0x05, &bytes_val),
                (0x06, &labelset_val),
            ],
            labels: &[],
        });
        let r = decode_request(&buf).unwrap();
        let args: Vec<TypedArg> = r.args.collect();
        assert_eq!(args.len(), 5);
        assert_eq!(args[0].val, ArgVal::Path(b"/a/b"));
        assert_eq!(args[1].val, ArgVal::Enum(7));
        assert_eq!(args[2].val, ArgVal::Int(-42));
        assert_eq!(args[3].val, ArgVal::Bytes(b"blob"));
        assert_eq!(args[4].val, ArgVal::LabelSet(Label::SECRET));
    }

    #[test]
    fn rejects_wrong_length_fixed_size_tag() {
        // ENUM must be exactly 2 bytes.
        let bad_enum = [0u8, 0u8, 0u8].to_vec();
        let buf = build(&Req {
            session: 1,
            req_id: 1,
            cap: 1,
            tool: 1,
            args: &[(0x03, &bad_enum)],
            labels: &[],
        });
        assert_eq!(decode_request(&buf).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn rejects_unknown_tag() {
        let v = [1u8, 2, 3].to_vec();
        let buf = build(&Req {
            session: 1,
            req_id: 1,
            cap: 1,
            tool: 1,
            args: &[(0x07, &v)],
            labels: &[],
        });
        assert_eq!(decode_request(&buf).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn decodes_in_labels_trailing_blob() {
        let labels = [Label::SECRET.0, Label::TRUSTED.0];
        let buf = build(&Req {
            session: 1,
            req_id: 1,
            cap: 1,
            tool: 1,
            args: &[],
            labels: &labels,
        });
        let r = decode_request(&buf).unwrap();
        assert_eq!(r.in_labels, &labels[..]);
    }

    #[test]
    fn rejects_labels_len_mismatch() {
        // Declared labels_len does not match actual trailing bytes present.
        let mut buf = header(1, 1, 1, 1, 0, 5);
        buf.extend_from_slice(b"ab"); // only 2 bytes, declared 5
        assert_eq!(decode_request(&buf).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn rejects_trailing_garbage_past_declared_labels() {
        let mut buf = header(1, 1, 1, 1, 0, 2);
        buf.extend_from_slice(b"abXYZ"); // 5 bytes present, declared 2
        assert_eq!(decode_request(&buf).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn rejects_malformed_url_missing_fields() {
        // A URL value truncated mid pre-split-field is structurally invalid.
        let bad_url = [1u8, 5, 0].to_vec(); // scheme + host_len=5 but no host bytes
        let buf = build(&Req {
            session: 1,
            req_id: 1,
            cap: 1,
            tool: 1,
            args: &[(0x01, &bad_url)],
            labels: &[],
        });
        assert_eq!(decode_request(&buf).unwrap_err(), ReasonCode::DenyMalformed);
    }
}
