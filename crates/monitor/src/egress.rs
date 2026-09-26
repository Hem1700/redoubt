//! Egress sink trait + secret injector.
//!
//! This is the FINAL pipeline stage after a request has been allowed by
//! `predicate::eval` and `flow`: it performs the tool call against the
//! outside world and returns the result. Two properties are load-bearing:
//!
//! - **Secret inject-only (Review-Focus 5):** a resolved secret handed to
//!   `EgressSink::perform` is injected into the OUTBOUND request bytes only.
//!   It must never appear in the returned `Response` body.
//! - **Dial the exact structured host, never re-parse (Review-Focus 9 /
//!   Ruling R7):** a sink dials the exact `scheme`/`host`/`port` from the
//!   already-parsed, typed `UrlParts` obtained via `predicate::Args::url_parts`.
//!   There is no URL *string* anywhere in this module to parse, re-parse, or
//!   split — only structured fields. An `Args` with no `Url`-typed `url` slot
//!   yields `url_parts() == None`, and a sink must fail closed
//!   (`ReasonCode::ErrInternal`) rather than guess a target.
//!
//! `monitor` is `no_std` with no allocator: every buffer here is fixed size.
#![forbid(unsafe_code)]

use crate::cap::Cap;
use crate::predicate::Args;
use abi::{Label, ReasonCode};

/// Max bytes of a tool result body the monitor will hold (fixed, no alloc).
pub const RESP_BODY_MAX: usize = 512;

/// The result of a completed (successful) egress call.
///
/// `body`/`body_len` are private so callers can only read the body through
/// the length-bounded `body()` accessor -- there is no way to observe bytes
/// past what was actually written.
#[derive(Debug)]
pub struct Response {
    pub status: ReasonCode,
    pub out_label: Label,
    body: [u8; RESP_BODY_MAX],
    body_len: usize,
}

impl Response {
    /// Build a `Response`, copying up to `RESP_BODY_MAX` bytes of `bytes`
    /// into the fixed body buffer. Extra bytes beyond `RESP_BODY_MAX` are
    /// truncated, never panicked on.
    pub fn with_body(status: ReasonCode, out_label: Label, bytes: &[u8]) -> Response {
        let mut body = [0u8; RESP_BODY_MAX];
        let n = core::cmp::min(bytes.len(), RESP_BODY_MAX);
        body[..n].copy_from_slice(&bytes[..n]);
        Response { status, out_label, body, body_len: n }
    }

    /// The result body actually returned to the agent (len-bounded slice).
    pub fn body(&self) -> &[u8] {
        &self.body[..self.body_len]
    }
}

/// Performs an already-authorized tool call against the outside world.
pub trait EgressSink {
    /// Perform the (already-authorized) tool call. `secret` is the resolved
    /// secret bytes to INJECT into the outbound request (inject-only): if the
    /// sink uses it, it goes into the outbound bytes and MUST NOT appear in
    /// the returned Response body. Dial the exact structured host from
    /// `args.url_parts()`; never parse a URL string.
    fn perform(&mut self, cap: &Cap, args: &Args, secret: Option<&[u8]>)
        -> Result<Response, ReasonCode>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::CapType;
    use abi::{ArgVal, Scheme, UrlParts};

    // -- test doubles ---------------------------------------------------

    /// Fixed capacity of `MockSink`'s recorded-outbound buffer. Large
    /// enough for every fixture used below (host + 2-byte port + path +
    /// an injected secret) with headroom, never grown dynamically.
    const OUTBOUND_MAX: usize = 128;

    /// Records the exact outbound bytes a real HTTP sink would transmit,
    /// built ONLY from the structured `UrlParts` obtained via
    /// `args.url_parts()` -- there is no URL string anywhere in this type
    /// for it to parse. If `secret` is `Some`, those bytes are appended to
    /// the outbound record (simulating an injected auth header) but never
    /// placed into the returned `Response` body.
    struct MockSink {
        outbound: [u8; OUTBOUND_MAX],
        outbound_len: usize,
    }

    impl Default for MockSink {
        fn default() -> Self {
            Self { outbound: [0u8; OUTBOUND_MAX], outbound_len: 0 }
        }
    }

    impl MockSink {
        fn last_outbound(&self) -> &[u8] {
            &self.outbound[..self.outbound_len]
        }

        /// Append `bytes` to the outbound record, truncating (never
        /// panicking) if the fixed buffer is already full.
        fn record(&mut self, bytes: &[u8]) {
            let start = self.outbound_len;
            let remaining = OUTBOUND_MAX - start;
            let n = core::cmp::min(bytes.len(), remaining);
            self.outbound[start..start + n].copy_from_slice(&bytes[..n]);
            self.outbound_len += n;
        }
    }

    impl EgressSink for MockSink {
        fn perform(&mut self, _cap: &Cap, args: &Args, secret: Option<&[u8]>)
            -> Result<Response, ReasonCode>
        {
            // Fail closed: no structured target, no dial. There is no URL
            // string anywhere in this function to fall back to.
            let parts = args.url_parts().ok_or(ReasonCode::ErrInternal)?;

            self.outbound_len = 0;
            self.record(parts.host);
            self.record(&parts.port.to_be_bytes());
            self.record(parts.path);
            if let Some(s) = secret {
                self.record(s);
            }

            Ok(Response::with_body(ReasonCode::Allow, Label::UNTRUSTED, b"OK"))
        }
    }

    #[derive(Default)]
    struct FailingSink;

    impl EgressSink for FailingSink {
        fn perform(&mut self, _cap: &Cap, _args: &Args, _secret: Option<&[u8]>)
            -> Result<Response, ReasonCode>
        {
            Err(ReasonCode::ErrEgress)
        }
    }

    #[derive(Default)]
    struct TimeoutSink;

    impl EgressSink for TimeoutSink {
        fn perform(&mut self, _cap: &Cap, _args: &Args, _secret: Option<&[u8]>)
            -> Result<Response, ReasonCode>
        {
            Err(ReasonCode::ErrTimeout)
        }
    }

    // -- fixtures ---------------------------------------------------------

    fn cap_http() -> Cap {
        Cap {
            ctype: CapType::Tool as u8,
            rights: 0,
            tool_id: 0x1000,
            pred_ref: 0,
            flow_ref: 0,
            secret_ref: 0,
            aux: 0,
            epoch: 1,
            _pad: 0,
        }
    }

    fn args_get() -> Args<'static> {
        Args::new().with_url(ArgVal::Url(UrlParts {
            scheme: Scheme::Https,
            host: b"api.example.com",
            port: 443,
            path: b"/x",
        }))
    }

    // -- required tests (verbatim intent from the brief) ------------------

    #[test]
    fn secret_is_injected_but_not_returned() {
        let mut s = MockSink::default();
        let r = s.perform(&cap_http(), &args_get(), Some(b"KEY123")).unwrap();
        assert!(s.last_outbound().windows(6).any(|w| w == b"KEY123")); // used outbound
        assert!(!r.body().windows(6).any(|w| w == b"KEY123")); // never returned
    }

    #[test]
    fn sink_error_maps_to_err_egress() {
        assert_eq!(
            FailingSink.perform(&cap_http(), &args_get(), None).unwrap_err(),
            ReasonCode::ErrEgress
        );
    }

    #[test]
    fn sink_timeout_maps_to_err_timeout() {
        assert_eq!(
            TimeoutSink.perform(&cap_http(), &args_get(), None).unwrap_err(),
            ReasonCode::ErrTimeout
        );
    }

    // -- exact-host / no re-parse (Review-Focus 9) -------------------------

    #[test]
    fn dials_exact_structured_host_and_port() {
        let mut s = MockSink::default();
        let _ = s.perform(&cap_http(), &args_get(), None).unwrap();
        let out = s.last_outbound();
        assert!(out.windows(15).any(|w| w == b"api.example.com"));
        assert!(out.windows(2).any(|w| w == 443u16.to_be_bytes()));
    }

    #[test]
    fn missing_url_slot_yields_none_and_fails_closed() {
        // No url slot at all: url_parts() must be None, and the sink must
        // never dial anything -- there is no string to fall back to.
        let args = Args::new();
        assert!(args.url_parts().is_none());

        let mut s = MockSink::default();
        let err = s.perform(&cap_http(), &args, None).unwrap_err();
        assert_eq!(err, ReasonCode::ErrInternal);
        // Nothing was dialed: the outbound record is untouched (still empty).
        assert!(s.last_outbound().is_empty());
    }

    #[test]
    fn non_url_arg_in_url_slot_yields_none_and_fails_closed() {
        // A type-confused Args: something else occupies the "url" slot.
        // url_parts() must still be None -- there is no URL string inside
        // an ArgVal::Bytes for the sink to parse as a fallback.
        let args = Args::new().with_url(ArgVal::Bytes(b"http://evil.example/should-not-parse"));
        assert!(args.url_parts().is_none());

        let mut s = MockSink::default();
        let err = s.perform(&cap_http(), &args, None).unwrap_err();
        assert_eq!(err, ReasonCode::ErrInternal);
        assert!(s.last_outbound().is_empty());
    }

    // -- no-secret call -----------------------------------------------------

    #[test]
    fn no_secret_call_succeeds_with_no_stray_secret() {
        let mut s = MockSink::default();
        let r = s.perform(&cap_http(), &args_get(), None).unwrap();
        assert_eq!(r.status, ReasonCode::Allow);
        // Outbound record is exactly host + port(2) + path -- nothing extra.
        let expected_len = b"api.example.com".len() + 2 + b"/x".len();
        assert_eq!(s.last_outbound().len(), expected_len);
        assert!(!s.last_outbound().windows(6).any(|w| w == b"KEY123"));
    }

    // -- truncation safety ---------------------------------------------------

    #[test]
    fn with_body_truncates_oversized_input_without_panicking() {
        let big = [7u8; RESP_BODY_MAX + 100];
        let r = Response::with_body(ReasonCode::Allow, Label::UNTRUSTED, &big);
        assert_eq!(r.body().len(), RESP_BODY_MAX);
        assert!(r.body().iter().all(|&b| b == 7));
    }
}
