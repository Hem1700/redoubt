#![no_std]
#![forbid(unsafe_code)]

use abi::{ArgVal, Label, ReasonCode};
use blake2::{Blake2s256, Digest};
use core::ops::Range;

pub mod audit;
pub mod cap;
pub mod egress;
pub mod flow;
pub mod parse;
pub mod policy;
pub mod predicate;

pub use policy::Policy;

use audit::{Audit, Entry};
use parse::MAX_REQ;
use predicate::Args;

/// Check if a capability's tool_id matches the expected tool_id.
/// Returns `Ok(())` if they match, `Err(ReasonCode::DenyTool)` if they don't.
pub fn check_tool(cap: &cap::Cap, tool_id: u16) -> Result<(), ReasonCode> {
    if cap.tool_id == tool_id {
        Ok(())
    } else {
        Err(ReasonCode::DenyTool)
    }
}

/// An owned view of a completed tool call's response: a bounded copy of
/// the sink's result body plus the label the flow stage assigned. Every
/// field is owned (no borrow of a local), so `mediate` can return it by
/// value.
pub struct ResponseView {
    body: [u8; egress::RESP_BODY_MAX],
    body_len: usize,
    label: Label,
}

impl ResponseView {
    /// The response body actually returned to the agent (length-bounded
    /// slice -- never the padding past `body_len`).
    pub fn bytes(&self) -> &[u8] {
        &self.body[..self.body_len]
    }

    /// The label the flow stage assigned to this result.
    pub fn label(&self) -> Label {
        self.label
    }

    /// The empty response returned on every DENY/ERR path.
    pub const fn empty() -> Self {
        ResponseView {
            body: [0u8; egress::RESP_BODY_MAX],
            body_len: 0,
            label: Label::PUBLIC,
        }
    }

    /// Build from a completed sink `Response`, bounding the copy at
    /// `RESP_BODY_MAX` (matching `Response::body`'s own bound; the extra
    /// `min` is defense in depth, never relied on alone).
    fn from_sink(resp: &egress::Response, label: Label) -> Self {
        let src = resp.body();
        let mut body = [0u8; egress::RESP_BODY_MAX];
        let n = core::cmp::min(src.len(), egress::RESP_BODY_MAX);
        body[..n].copy_from_slice(&src[..n]);
        ResponseView { body, body_len: n, label }
    }
}

/// Mirrors `parse::parse_into`'s own bounds proof, but WITHOUT decoding, so
/// `mediate` can decide -- independent of whether decoding then accepts or
/// rejects the copied content -- whether the audit hash covers the copied
/// request bytes or the fixed zero hash (see `mediate`'s doc comment).
/// This duplicated check never influences the actual admission decision;
/// only `parse::parse_into`'s own checks (run separately, on the real
/// request path) do that.
fn request_bytes_were_copied(shared: &[u8], ptr: usize, len: usize, region: &Range<usize>) -> bool {
    if len > MAX_REQ {
        return false;
    }
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };
    if ptr < region.start || end > region.end {
        return false;
    }
    shared.get(ptr..end).is_some()
}

/// Route a request's already-decoded `TypedArg`s onto the named fields
/// `predicate::Args` exposes (Phase-1 bridging convention -- see the
/// task-14 brief). First occurrence of each variant wins (a well-formed
/// Phase-1 request has at most one of each); `Enum`/`LabelSet` args have no
/// named-field home in Phase 1 and are ignored here.
///
/// Phase 3's manifest compiler replaces this fixed variant->field routing
/// with schema-driven mapping: a tool's manifest will say which argument
/// *position* means "url", "method", etc., rather than this module
/// inferring it from the `ArgVal`'s shape.
fn bridge_args(args_iter: abi::ArgsIter<'_>) -> Args<'_> {
    let mut args = Args::new();
    let mut have_url = false;
    let mut have_method = false;
    let mut have_path = false;
    let mut have_len = false;

    for typed in args_iter {
        match typed.val {
            ArgVal::Url(_) if !have_url => {
                args = args.with_url(typed.val);
                have_url = true;
            }
            ArgVal::Bytes(_) if !have_method => {
                args = args.with_method(typed.val);
                have_method = true;
            }
            ArgVal::Path(_) if !have_path => {
                args = args.with_path(typed.val);
                have_path = true;
            }
            ArgVal::Int(_) if !have_len => {
                args = args.with_len(typed.val);
                have_len = true;
            }
            _ => {}
        }
    }

    args
}

/// Bridge a request's raw `in_labels: &[u8]` into a fixed `[abi::Label;
/// MAX_ARGS]` (`abi::Label` is not `repr(transparent)`, so the byte slice
/// cannot simply be reinterpreted as `&[Label]`). Fails closed
/// (`DenyMalformed`) if there are more labels than `MAX_ARGS` slots to
/// hold them. Returns the fixed array plus the number of leading slots
/// actually filled.
fn bridge_labels(in_labels: &[u8]) -> Result<([Label; abi::MAX_ARGS], usize), ReasonCode> {
    if in_labels.len() > abi::MAX_ARGS {
        return Err(ReasonCode::DenyMalformed);
    }
    let mut labels = [Label::default(); abi::MAX_ARGS];
    for (slot, &byte) in labels.iter_mut().zip(in_labels.iter()) {
        *slot = Label(byte);
    }
    Ok((labels, in_labels.len()))
}

/// Stages 2 through 6 of `mediate`, run against an already-parsed request.
/// Runs strictly in order: cap resolve + revocation check (2), tool match
/// (3), argument predicate (4), IFC flow check (5), egress (6). Returns as
/// soon as any stage fails via `?`; `mediate` itself is solely responsible
/// for the single audit append regardless of what this returns.
fn run_stages(
    req: abi::RequestView<'_>,
    sessions: &mut cap::Sessions,
    policy: &Policy,
    sink: &mut dyn egress::EgressSink,
) -> Result<ResponseView, ReasonCode> {
    // Stage 2: do you hold this permission? Session lookup, then handle
    // resolve -- `cap::resolve` itself enforces revocation (epoch compare).
    // The session must be Active (the ONLY state that accepts MEDIATE). A
    // live non-Active session denies: Created/Provisioned -> DenyNoCap
    // (powers not yet in force), Draining -> DenyQuota (no new work),
    // Destroyed -> DenyRevoked.
    let session = sessions.get(req.session_id)?;
    match session.state {
        cap::SessionState::Active => {}
        cap::SessionState::Created | cap::SessionState::Provisioned => {
            return Err(ReasonCode::DenyNoCap)
        }
        cap::SessionState::Draining => return Err(ReasonCode::DenyQuota),
        cap::SessionState::Destroyed => return Err(ReasonCode::DenyRevoked),
    }
    // Request quota: debit 1 per request that reaches mediation. Out of
    // budget -> DenyQuota and Active -> Draining.
    if session.quotas.requests_left == 0 {
        sessions.get_mut(req.session_id)?.state = cap::SessionState::Draining;
        return Err(ReasonCode::DenyQuota);
    }
    let sess = sessions.get_mut(req.session_id)?;
    sess.quotas.requests_left -= 1;
    // `cap` is a Copy: the borrow of the session ends here, so the egress
    // debit below can mutate it.
    let cap = *cap::resolve(sess, req.cap_handle)?;
    let cap = &cap;

    // Stage 3: is this ticket for this tool?
    check_tool(cap, req.tool_id)?;

    let in_labels = req.in_labels;
    let args = bridge_args(req.args);

    // Stage 4: are the arguments allowed? Structured args only, never
    // re-parsed text.
    let clauses = policy.clauses(cap.pred_ref)?;
    predicate::eval(clauses, &args, &policy.pool)?;

    // Stage 5: smuggling data out?
    let (labels, n) = bridge_labels(in_labels)?;
    let flow_rule = policy.flow(cap.flow_ref)?;
    let out_label = flow::flow_check(flow_rule, &labels[..n], cap)?;

    // Stage 6: carry it out. Inject the secret the agent never saw; the
    // egress stage stamps the result with `out_label`.
    let secret = flow_rule.inject.and_then(|sref| policy.secret(sref));
    // Egress quota: the deterministic outbound size (host + path + injected
    // secret) is checked and debited BEFORE the effect is performed, so the
    // debit cannot be bypassed. Over budget -> DenyQuota, Active -> Draining,
    // and the sink is never called.
    let cost = args
        .url_parts()
        .map_or(0, |u| u.host.len() + u.path.len())
        .saturating_add(secret.map_or(0, |s| s.len()));
    let cost = u32::try_from(cost).unwrap_or(u32::MAX);
    let sess = sessions.get_mut(req.session_id)?;
    if cost > sess.quotas.egress_bytes_left {
        sess.state = cap::SessionState::Draining;
        return Err(ReasonCode::DenyQuota);
    }
    sess.quotas.egress_bytes_left -= cost;
    let resp = sink.perform(cap, &args, secret)?;

    Ok(ResponseView::from_sink(&resp, out_label))
}

/// The six-stage decision pipeline every agent tool call flows through
/// (manual Ch 9 §9.7 / the task-14 brief). Runs the checks in strict
/// order and appends EXACTLY ONE audit entry before returning, regardless
/// of which stage decided the outcome -- including a stage-1 malformed
/// request, which never reaches `run_stages` at all.
///
/// `mediate` owns its `scratch` buffer as a stack local (never anywhere
/// that persists across calls).
///
/// # Audit entry on every path
/// This function computes its full outcome (via `parse::parse_into` and,
/// if that succeeds, `run_stages`) into one `(ReasonCode, u16, u16,
/// ResponseView)` tuple FIRST, and only THEN builds and appends the
/// `Entry` on the final lines below -- there is no `return` anywhere in
/// this function, so nothing can skip the append. Fields:
/// - `session_id` / `tool_id`: the parsed request's, or `0` / `0` if
///   stage 1 never parsed the request.
/// - `req_hash`: `Blake2s256` of the request bytes actually considered --
///   `scratch[..len]` if `parse::parse_into` got far enough to copy them
///   (regardless of whether decoding then accepted or rejected the
///   content), or the fixed `[0u8; 32]` if `(ptr, len)` was never even a
///   valid in-bounds slice of `shared` (a stage-1 bounds failure).
// The 8-argument signature is exact and load-bearing (task-14 brief: "Task
// 15 consumes it") -- splitting it into a struct would just move the
// arity problem to a constructor, not fix it, so the lint is silenced
// here rather than reshaping a contractually fixed public signature.
#[allow(clippy::too_many_arguments)]
pub fn mediate(
    shared: &[u8],
    ptr: usize,
    len: usize,
    region: Range<usize>,
    sessions: &mut cap::Sessions,
    policy: &Policy,
    sink: &mut dyn egress::EgressSink,
    audit: &mut Audit,
) -> (ReasonCode, ResponseView) {
    let mut scratch = [0u8; MAX_REQ];
    let copied = request_bytes_were_copied(shared, ptr, len, &region);

    let outcome = match parse::parse_into(shared, ptr, len, region, &mut scratch) {
        Ok(req) => {
            let session_id = req.session_id;
            let tool_id = req.tool_id;
            match run_stages(req, sessions, policy, sink) {
                Ok(resp) => (ReasonCode::Allow, session_id, tool_id, resp),
                Err(rc) => (rc, session_id, tool_id, ResponseView::empty()),
            }
        }
        Err(rc) => (rc, 0u16, 0u16, ResponseView::empty()),
    };

    let (rc, session_id, tool_id, resp) = outcome;

    let req_hash = if copied {
        let mut hasher = Blake2s256::new();
        hasher.update(&scratch[..len]);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    } else {
        [0u8; 32]
    };

    audit.append(Entry { seq: 0, session_id, tool_id, reason: rc as u8, req_hash });

    (rc, resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Create a capability with tool_id 0x1000 for testing
    fn cap_http() -> cap::Cap {
        cap::Cap {
            ctype: cap::CapType::Tool as u8,
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

    #[test]
    fn mismatched_tool_denies() {
        assert_eq!(check_tool(&cap_http(), 0x2000).unwrap_err(), ReasonCode::DenyTool);
    }

    #[test]
    fn matched_tool_ok() {
        assert!(check_tool(&cap_http(), 0x1000).is_ok());
    }

    // -----------------------------------------------------------------
    // Pipeline tests (`mediate`). Test-only: build wire-format request
    // bytes with `Vec`/`std::vec!` (the module under test remains
    // no_std/no-alloc; this only affects the host test harness).
    // -----------------------------------------------------------------
    extern crate std;
    use std::vec::Vec;

    const HEADER_LEN: usize = 16;
    const TOOL_ID: u16 = 0x1000;
    const API_HOSTS: &[&[u8]] = &[b"api.example.com"];
    const POOL_API_HOSTS: u16 = 0;
    const SECRET: &[u8] = b"API_KEY_SECRET_VALUE";

    static CLAUSES_HOST_ONLY: [predicate::Clause; 1] = [predicate::Clause {
        field: predicate::FieldSel::URL_HOST,
        op: predicate::Op::HostInSet,
        operand: POOL_API_HOSTS,
    }];
    static PRED_SETS: [&[predicate::Clause]; 1] = [&CLAUSES_HOST_ONLY];
    static FLOWS_PUBLIC_DENY_SECRET: [flow::FlowRule; 1] = [flow::FlowRule {
        inject: Some(0),
        deny_secret_to_public: true,
        result_label: Label::UNTRUSTED,
    }];
    static SECRETS: [&[u8]; 1] = [SECRET];

    /// The Phase-1 hand-built policy fixture shared by the pipeline tests:
    /// one tool whose predicate requires `host in {api.example.com}`, and
    /// whose flow rule denies a SECRET-labeled input to this (public) sink
    /// unless the cap carries declassify clearance, injecting `SECRET` on
    /// success.
    fn policy_fixture() -> Policy<'static> {
        let pool =
            predicate::ConstPool::new().with(POOL_API_HOSTS, predicate::PoolEntry::StrSet(API_HOSTS));
        Policy {
            preds: &PRED_SETS,
            flows: &FLOWS_PUBLIC_DENY_SECRET,
            secrets: &SECRETS,
            pool,
            caps: &[],
            quotas: cap::Quotas::UNLIMITED,
        }
    }

    fn cap_net_ok() -> cap::Cap {
        cap::Cap {
            ctype: cap::CapType::Net as u8,
            rights: 0,
            tool_id: TOOL_ID,
            pred_ref: 0,
            flow_ref: 0,
            secret_ref: 0,
            aux: 0,
            epoch: 1,
            _pad: 0,
        }
    }

    /// A session whose cspace has `cap` installed at `handle`, everywhere
    /// else Empty, all at epoch 1.
    fn session_with_cap(cap: cap::Cap, handle: usize) -> cap::Session {
        let empty = cap::Cap {
            ctype: cap::CapType::Empty as u8,
            rights: 0,
            tool_id: 0,
            pred_ref: 0,
            flow_ref: 0,
            secret_ref: 0,
            aux: 0,
            epoch: 1,
            _pad: 0,
        };
        let mut cspace = [empty; cap::CSPACE_LEN];
        cspace[handle] = cap;
        cap::Session::active(1, cspace)
    }

    fn sessions_with(session_id: u16, session: cap::Session) -> cap::Sessions {
        let mut s = cap::Sessions::default();
        s.install(session_id, session).unwrap();
        s
    }

    /// Records the exact outbound bytes a real HTTP sink would transmit
    /// (host + path + any injected secret), and whether it was invoked at
    /// all. A LOCAL test double implementing the public `EgressSink`
    /// trait -- `egress::tests::MockSink` is `cfg(test)`-private to
    /// `egress.rs` and not reusable here (per the task-14 brief).
    struct RecordingSink {
        outbound: [u8; 256],
        outbound_len: usize,
        called: bool,
        fail_with: Option<ReasonCode>,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self { outbound: [0u8; 256], outbound_len: 0, called: false, fail_with: None }
        }

        fn failing(rc: ReasonCode) -> Self {
            let mut s = Self::new();
            s.fail_with = Some(rc);
            s
        }

        fn last_outbound(&self) -> &[u8] {
            &self.outbound[..self.outbound_len]
        }

        fn last_outbound_has_auth_header(&self) -> bool {
            self.last_outbound().windows(SECRET.len()).any(|w| w == SECRET)
        }

        fn was_called(&self) -> bool {
            self.called
        }

        fn record(&mut self, bytes: &[u8]) {
            let start = self.outbound_len;
            let remaining = self.outbound.len() - start;
            let n = core::cmp::min(bytes.len(), remaining);
            self.outbound[start..start + n].copy_from_slice(&bytes[..n]);
            self.outbound_len += n;
        }
    }

    impl egress::EgressSink for RecordingSink {
        fn perform(
            &mut self,
            _cap: &cap::Cap,
            args: &predicate::Args,
            secret: Option<&[u8]>,
        ) -> Result<egress::Response, ReasonCode> {
            self.called = true;
            if let Some(rc) = self.fail_with {
                return Err(rc);
            }
            let parts = args.url_parts().ok_or(ReasonCode::ErrInternal)?;
            self.outbound_len = 0;
            self.record(parts.host);
            self.record(parts.path);
            if let Some(s) = secret {
                self.record(s);
            }
            Ok(egress::Response::with_body(ReasonCode::Allow, Label::UNTRUSTED, b"OK-RESPONSE-BODY"))
        }
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

    struct ReqSpec<'a> {
        session: u16,
        req_id: u16,
        cap: u16,
        tool: u16,
        args: &'a [(u8, &'a [u8])],
        labels: &'a [u8],
    }

    fn build_request(spec: &ReqSpec) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN);
        v.extend_from_slice(&abi::MAGIC.to_le_bytes());
        v.extend_from_slice(&spec.session.to_le_bytes());
        v.extend_from_slice(&spec.req_id.to_le_bytes());
        v.extend_from_slice(&spec.cap.to_le_bytes());
        v.extend_from_slice(&spec.tool.to_le_bytes());
        v.push(spec.args.len() as u8);
        v.push(0); // reserved
        v.extend_from_slice(&(spec.labels.len() as u16).to_le_bytes());
        for (tag, val) in spec.args {
            v.push(*tag);
            v.extend_from_slice(&(val.len() as u16).to_le_bytes());
            v.extend_from_slice(val);
        }
        v.extend_from_slice(spec.labels);
        v
    }

    /// Place `req_bytes` at the front of a fixed `MAX_REQ`-sized `shared`
    /// buffer, spanning the whole buffer as the SHARED_REQ region.
    fn shared_with(req_bytes: &[u8]) -> (Vec<u8>, Range<usize>, usize, usize) {
        let region = 0usize..MAX_REQ;
        let mut shared = std::vec![0u8; MAX_REQ];
        let ptr = 0usize;
        let len = req_bytes.len();
        shared[ptr..ptr + len].copy_from_slice(req_bytes);
        (shared, region, ptr, len)
    }

    // -- required demo scenarios (verbatim intent from the brief) --------

    #[test]
    fn demo_benign_allows_and_injects() {
        let policy = policy_fixture();
        let mut sessions = sessions_with(1, session_with_cap(cap_net_ok(), 3));
        let mut sink = RecordingSink::new();
        let mut audit = Audit::default();

        let url_val = encode_url_value(1, b"api.example.com", 443, b"/x");
        let req_bytes = build_request(&ReqSpec {
            session: 1,
            req_id: 1,
            cap: 3,
            tool: TOOL_ID,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let (shared, region, ptr, len) = shared_with(&req_bytes);

        let (rc, resp) = mediate(&shared, ptr, len, region, &mut sessions, &policy, &mut sink, &mut audit);

        assert_eq!(rc, ReasonCode::Allow);
        assert!(sink.last_outbound_has_auth_header()); // secret injected outbound
        assert!(!resp.bytes().windows(SECRET.len()).any(|w| w == SECRET)); // never in the response
    }

    #[test]
    fn demo_attack_wrong_host_denies_arg() {
        let policy = policy_fixture();
        let mut sessions = sessions_with(1, session_with_cap(cap_net_ok(), 3));
        let mut sink = RecordingSink::new();
        let mut audit = Audit::default();

        // POST to evil.tld: the predicate only allows api.example.com.
        let url_val = encode_url_value(1, b"evil.tld", 443, b"/steal");
        let method_val: &[u8] = b"POST";
        let req_bytes = build_request(&ReqSpec {
            session: 1,
            req_id: 1,
            cap: 3,
            tool: TOOL_ID,
            args: &[(0x01, &url_val), (0x05, method_val)],
            labels: &[],
        });
        let (shared, region, ptr, len) = shared_with(&req_bytes);

        let (rc, resp) = mediate(&shared, ptr, len, region, &mut sessions, &policy, &mut sink, &mut audit);

        assert_eq!(rc, ReasonCode::DenyArg);
        assert!(!sink.was_called());
        assert!(resp.bytes().is_empty());
    }

    #[test]
    fn demo_flow_secret_in_body_denies_flow() {
        let policy = policy_fixture();
        let mut sessions = sessions_with(1, session_with_cap(cap_net_ok(), 3));
        let mut sink = RecordingSink::new();
        let mut audit = Audit::default();

        // Allowed host, but a SECRET-labeled input into a
        // deny_secret_to_public sink, and the cap carries no declassify
        // clearance.
        let url_val = encode_url_value(1, b"api.example.com", 443, b"/x");
        let req_bytes = build_request(&ReqSpec {
            session: 1,
            req_id: 1,
            cap: 3,
            tool: TOOL_ID,
            args: &[(0x01, &url_val)],
            labels: &[Label::SECRET.0],
        });
        let (shared, region, ptr, len) = shared_with(&req_bytes);

        let (rc, resp) = mediate(&shared, ptr, len, region, &mut sessions, &policy, &mut sink, &mut audit);

        assert_eq!(rc, ReasonCode::DenyFlow);
        assert!(!sink.was_called());
        assert!(resp.bytes().is_empty());
    }

    #[test]
    fn ordering_stage2_before_stage4() {
        let policy = policy_fixture();
        let mut sessions = sessions_with(1, session_with_cap(cap_net_ok(), 3));
        // Revoke: the handle-3 cap is now stale (DenyRevoked at stage 2),
        // even though the request's ARGS (an allowed host) would satisfy
        // stage 4 if stage 2 were skipped or deferred.
        sessions.revoke(1);
        let mut sink = RecordingSink::new();
        let mut audit = Audit::default();

        let url_val = encode_url_value(1, b"api.example.com", 443, b"/x");
        let req_bytes = build_request(&ReqSpec {
            session: 1,
            req_id: 1,
            cap: 3,
            tool: TOOL_ID,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let (shared, region, ptr, len) = shared_with(&req_bytes);

        let (rc, resp) = mediate(&shared, ptr, len, region, &mut sessions, &policy, &mut sink, &mut audit);

        assert_eq!(rc, ReasonCode::DenyRevoked);
        assert!(!sink.was_called());
        assert!(resp.bytes().is_empty());
    }

    // -- additional required coverage -------------------------------------

    #[test]
    fn every_verdict_is_audited_including_malformed() {
        let policy = policy_fixture();
        let mut sessions = sessions_with(1, session_with_cap(cap_net_ok(), 3));
        let mut sink = RecordingSink::new();
        let mut audit = Audit::default();
        let h0 = audit.head();

        // ALLOW.
        let url_val = encode_url_value(1, b"api.example.com", 443, b"/x");
        let req_bytes = build_request(&ReqSpec {
            session: 1,
            req_id: 1,
            cap: 3,
            tool: TOOL_ID,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let (shared, region, ptr, len) = shared_with(&req_bytes);
        let (rc, _resp) = mediate(&shared, ptr, len, region, &mut sessions, &policy, &mut sink, &mut audit);
        assert_eq!(rc, ReasonCode::Allow);
        let h1 = audit.head();
        assert_ne!(h0, h1);

        // DENY (wrong host, stage 4).
        let url_val2 = encode_url_value(1, b"evil.tld", 443, b"/x");
        let req_bytes2 = build_request(&ReqSpec {
            session: 1,
            req_id: 2,
            cap: 3,
            tool: TOOL_ID,
            args: &[(0x01, &url_val2)],
            labels: &[],
        });
        let (shared2, region2, ptr2, len2) = shared_with(&req_bytes2);
        let (rc2, _resp2) =
            mediate(&shared2, ptr2, len2, region2, &mut sessions, &policy, &mut sink, &mut audit);
        assert_eq!(rc2, ReasonCode::DenyArg);
        let h2 = audit.head();
        assert_ne!(h1, h2);

        // Malformed: (ptr, len) overflows usize, so the request never even
        // reaches parse::parse_into's copy step. Still appends and
        // advances the head.
        let (rc3, resp3) =
            mediate(&shared, usize::MAX - 4, 16, 0usize..MAX_REQ, &mut sessions, &policy, &mut sink, &mut audit);
        assert_eq!(rc3, ReasonCode::DenyMalformed);
        assert!(resp3.bytes().is_empty());
        let h3 = audit.head();
        assert_ne!(h2, h3);
    }

    #[test]
    fn deny_tool_stage3_sink_not_called() {
        let policy = policy_fixture();
        let mut sessions = sessions_with(1, session_with_cap(cap_net_ok(), 3)); // cap.tool_id == TOOL_ID
        let mut sink = RecordingSink::new();
        let mut audit = Audit::default();

        let url_val = encode_url_value(1, b"api.example.com", 443, b"/x");
        let req_bytes = build_request(&ReqSpec {
            session: 1,
            req_id: 1,
            cap: 3,
            tool: TOOL_ID + 1, // mismatched tool_id
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let (shared, region, ptr, len) = shared_with(&req_bytes);

        let (rc, resp) = mediate(&shared, ptr, len, region, &mut sessions, &policy, &mut sink, &mut audit);

        assert_eq!(rc, ReasonCode::DenyTool);
        assert!(!sink.was_called());
        assert!(resp.bytes().is_empty());
    }

    #[test]
    fn sink_error_maps_to_err_egress() {
        let policy = policy_fixture();
        let mut sessions = sessions_with(1, session_with_cap(cap_net_ok(), 3));
        let mut sink = RecordingSink::failing(ReasonCode::ErrEgress);
        let mut audit = Audit::default();

        let url_val = encode_url_value(1, b"api.example.com", 443, b"/x");
        let req_bytes = build_request(&ReqSpec {
            session: 1,
            req_id: 1,
            cap: 3,
            tool: TOOL_ID,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let (shared, region, ptr, len) = shared_with(&req_bytes);

        let (rc, resp) = mediate(&shared, ptr, len, region, &mut sessions, &policy, &mut sink, &mut audit);

        assert_eq!(rc, ReasonCode::ErrEgress);
        assert!(sink.was_called());
        assert!(resp.bytes().is_empty());
    }

    // -- W4: session lifecycle + quotas ------------------------------------

    use cap::{session_close, session_open, session_revoke, Quotas, SessionState};

    static OPEN_CAPS: [cap::Cap; 1] = [cap::Cap {
        ctype: cap::CapType::Net as u8,
        rights: 0,
        tool_id: TOOL_ID,
        pred_ref: 0,
        flow_ref: 0,
        secret_ref: 0,
        aux: 0,
        epoch: 0, // stamped by session_open
        _pad: 0,
    }];

    fn open_policy(q: Quotas) -> Policy<'static> {
        let mut p = policy_fixture();
        p.caps = &OPEN_CAPS;
        p.quotas = q;
        p
    }

    // Bytes one benign request costs: host + path + injected secret.
    const BENIGN_COST: u32 = (15 + 2 + SECRET.len()) as u32;

    fn call(sessions: &mut cap::Sessions, id: u16, handle: u16, policy: &Policy) -> ReasonCode {
        let url_val = encode_url_value(1, b"api.example.com", 443, b"/x");
        let req_bytes = build_request(&ReqSpec {
            session: id,
            req_id: 1,
            cap: handle,
            tool: TOOL_ID,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let (shared, region, ptr, len) = shared_with(&req_bytes);
        let mut sink = RecordingSink::new();
        let mut audit = Audit::default();
        mediate(&shared, ptr, len, region, sessions, policy, &mut sink, &mut audit).0
    }

    fn state(s: &cap::Sessions, id: u16) -> SessionState {
        s.get(id).unwrap().state
    }

    #[test]
    fn open_provisions_caps_and_benign_allows() {
        let policy = open_policy(Quotas::UNLIMITED);
        let mut ss = cap::Sessions::default();
        let id = session_open(&mut ss, &policy).unwrap();
        assert_eq!(state(&ss, id), SessionState::Active);
        let sess = ss.get(id).unwrap();
        assert_eq!(cap::resolve(sess, 0).unwrap().epoch, sess.epoch);
        assert_eq!(call(&mut ss, id, 0, &policy), ReasonCode::Allow);
    }

    #[test]
    fn mediate_denies_on_non_active_states() {
        let policy = open_policy(Quotas::UNLIMITED);
        for (st, want) in [
            (SessionState::Created, ReasonCode::DenyNoCap),
            (SessionState::Provisioned, ReasonCode::DenyNoCap),
            (SessionState::Draining, ReasonCode::DenyQuota),
            (SessionState::Destroyed, ReasonCode::DenyRevoked),
        ] {
            let mut ss = cap::Sessions::default();
            let id = session_open(&mut ss, &policy).unwrap();
            ss.get_mut(id).unwrap().state = st;
            assert_eq!(call(&mut ss, id, 0, &policy), want, "{st:?}");
        }
    }

    #[test]
    fn transitions_in_order_close_and_revoke() {
        let policy = open_policy(Quotas::UNLIMITED);
        let mut ss = cap::Sessions::default();
        let id = session_open(&mut ss, &policy).unwrap();
        assert_eq!(state(&ss, id), SessionState::Active);
        session_close(&mut ss, id);
        assert_eq!(state(&ss, id), SessionState::Destroyed);
        // Closed: no new work.
        assert_ne!(call(&mut ss, id, 0, &policy), ReasonCode::Allow);
        // Revoke shortcut: Active -> Destroyed, every old handle stale.
        let id2 = session_open(&mut ss, &policy).unwrap();
        session_revoke(&mut ss, id2);
        assert_eq!(state(&ss, id2), SessionState::Destroyed);
        assert_eq!(cap::resolve(ss.get(id2).unwrap(), 0).unwrap_err(), ReasonCode::DenyRevoked);
        assert_eq!(call(&mut ss, id2, 0, &policy), ReasonCode::DenyRevoked);
    }

    #[test]
    fn reused_slot_gets_fresh_epoch() {
        let policy = open_policy(Quotas::UNLIMITED);
        let mut ss = cap::Sessions::default();
        // Fill the table so the freed slot is the only one available.
        let mut ids = [0u16; cap::MAX_SESSIONS];
        for id in ids.iter_mut() {
            *id = session_open(&mut ss, &policy).unwrap();
        }
        assert_eq!(session_open(&mut ss, &policy).unwrap_err(), ReasonCode::DenyQuota);
        let old_epoch = ss.get(ids[3]).unwrap().epoch;
        session_revoke(&mut ss, ids[3]);
        let again = session_open(&mut ss, &policy).unwrap();
        assert_eq!(again, ids[3]);
        assert_ne!(ss.get(again).unwrap().epoch, old_epoch);
        // A handle minted at the old epoch never resolves.
        let mut stale = OPEN_CAPS[0];
        stale.epoch = old_epoch;
        ss.get_mut(again).unwrap().cspace[5] = stale;
        assert_eq!(cap::resolve(ss.get(again).unwrap(), 5).unwrap_err(), ReasonCode::DenyRevoked);
        assert_eq!(call(&mut ss, again, 0, &policy), ReasonCode::Allow);
    }

    #[test]
    fn request_quota_crossing_denies_and_drains() {
        let q = Quotas { requests_left: 2, ..Quotas::UNLIMITED };
        let policy = open_policy(q);
        let mut ss = cap::Sessions::default();
        let id = session_open(&mut ss, &policy).unwrap();
        assert_eq!(call(&mut ss, id, 0, &policy), ReasonCode::Allow);
        assert_eq!(call(&mut ss, id, 0, &policy), ReasonCode::Allow);
        assert_eq!(state(&ss, id), SessionState::Active); // in-flight finished
        assert_eq!(call(&mut ss, id, 0, &policy), ReasonCode::DenyQuota);
        assert_eq!(state(&ss, id), SessionState::Draining);
        assert_eq!(call(&mut ss, id, 0, &policy), ReasonCode::DenyQuota); // refused
    }

    #[test]
    fn egress_quota_crossing_denies_without_performing() {
        let q = Quotas { egress_bytes_left: BENIGN_COST + BENIGN_COST / 2, ..Quotas::UNLIMITED };
        let policy = open_policy(q);
        let mut ss = cap::Sessions::default();
        let id = session_open(&mut ss, &policy).unwrap();
        assert_eq!(call(&mut ss, id, 0, &policy), ReasonCode::Allow);
        assert_eq!(ss.get(id).unwrap().quotas.egress_bytes_left, BENIGN_COST / 2);
        // Second request would cross the ceiling: sink never called.
        let url_val = encode_url_value(1, b"api.example.com", 443, b"/x");
        let rb = build_request(&ReqSpec {
            session: id,
            req_id: 2,
            cap: 0,
            tool: TOOL_ID,
            args: &[(0x01, &url_val)],
            labels: &[],
        });
        let (shared, region, ptr, len) = shared_with(&rb);
        let mut sink = RecordingSink::new();
        let mut audit = Audit::default();
        let (rc, _) = mediate(&shared, ptr, len, region, &mut ss, &policy, &mut sink, &mut audit);
        assert_eq!(rc, ReasonCode::DenyQuota);
        assert!(!sink.was_called());
        assert_eq!(state(&ss, id), SessionState::Draining);
        assert_eq!(call(&mut ss, id, 0, &policy), ReasonCode::DenyQuota);
    }

    #[test]
    fn denied_effect_does_not_debit_egress_but_performed_does() {
        let q = Quotas { egress_bytes_left: 1000, ..Quotas::UNLIMITED };
        let policy = open_policy(q);
        let mut ss = cap::Sessions::default();
        let id = session_open(&mut ss, &policy).unwrap();
        assert_eq!(call(&mut ss, id, 7, &policy), ReasonCode::DenyNoCap); // empty handle
        assert_eq!(ss.get(id).unwrap().quotas.egress_bytes_left, 1000);
        assert_eq!(call(&mut ss, id, 0, &policy), ReasonCode::Allow);
        assert_eq!(ss.get(id).unwrap().quotas.egress_bytes_left, 1000 - BENIGN_COST);
    }
}
