//! Kani harnesses (bounded model checking via CBMC). `cfg(kani)` only.
use super::*;

#[kani::proof]
fn toolchain_smoke() {
    let t: u16 = kani::any();
    let c = cap::Cap {
        ctype: cap::CapType::Tool as u8,
        rights: 0,
        tool_id: 0x1000,
        pred_ref: 0,
        flow_ref: 0,
        secret_ref: 0,
        aux: 0,
        epoch: 1,
        _pad: 0,
    };
    kani::assume(t != 0x1000);
    assert_eq!(check_tool(&c, t), Err(ReasonCode::DenyTool));
}

// ---------------------------------------------------------------------
// Fixtures (mirror the Phase-1 hand-built fixture in lib.rs tests).
// ---------------------------------------------------------------------
const TOOL_ID: u16 = 0x1000;
const API_HOSTS: &[&[u8]] = &[b"ex.io"];
const SECRET: &[u8] = b"API_KEY_SECRET_VALUE";

static CLAUSES_HOST_ONLY: [predicate::Clause; 1] = [predicate::Clause {
    field: predicate::FieldSel::URL_HOST,
    op: predicate::Op::HostInSet,
    operand: 0,
}];
static PRED_SETS: [&[predicate::Clause]; 1] = [&CLAUSES_HOST_ONLY];
static FLOWS: [flow::FlowRule; 1] = [flow::FlowRule {
    inject: Some(0),
    deny_secret_to_public: true,
    result_label: Label::UNTRUSTED,
}];
static SECRETS: [&[u8]; 1] = [SECRET];

fn policy_fixture() -> Policy<'static> {
    let pool = predicate::ConstPool::new().with(0, predicate::PoolEntry::StrSet(API_HOSTS));
    Policy {
        preds: &PRED_SETS,
        flows: &FLOWS,
        secrets: &SECRETS,
        pool,
        caps: &[],
        quotas: cap::Quotas::UNLIMITED,
    }
}

const EMPTY_CAP: cap::Cap = cap::Cap {
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

fn net_cap() -> cap::Cap {
    cap::Cap { ctype: cap::CapType::Net as u8, tool_id: TOOL_ID, ..EMPTY_CAP }
}

/// Session 1, epoch 1, one live Net cap at handle 3, unlimited quotas.
fn sessions_fixture() -> cap::Sessions {
    let mut cspace = [EMPTY_CAP; cap::CSPACE_LEN];
    cspace[3] = net_cap();
    let mut s = cap::Sessions::default();
    s.install(1, cap::Session::active(1, cspace)).unwrap();
    s
}

/// Recording `EgressSink`: the observation seam. Records whether `perform`
/// was ever invoked. `fail` (nondeterministic) models a sink that errors
/// after being invoked; the body of a successful response is a fixed
/// non-secret string (inject-only is the sink's own contract, see egress.rs).
struct RecordingSink {
    performed: bool,
    fail: bool,
}

impl egress::EgressSink for RecordingSink {
    fn perform(
        &mut self,
        _cap: &cap::Cap,
        _args: &predicate::Args,
        _secret: Option<&[u8]>,
    ) -> Result<egress::Response, ReasonCode> {
        self.performed = true;
        if self.fail {
            return Err(ReasonCode::ErrEgress);
        }
        Ok(egress::Response::with_body(ReasonCode::Allow, Label::UNTRUSTED, b"OK"))
    }
}

/// Bound on the shared-memory buffer (bytes).
const SHARED_N: usize = 48;
const HOST: usize = 5; // len("ex.io") = len of the fixture's allowlisted host: fixed host LENGTH, symbolic host BYTES (a short host keeps the CBMC slice-iterator loops small)
const HDR: usize = 16;
const TLV_VAL: usize = 1 + 2 + HOST + 2 + 2 + 2; // scheme, host_len, host, port, path_len, path(2)
const TLV: usize = 3 + TLV_VAL;

fn put16(b: &mut [u8; SHARED_N], off: usize, v: u16) {
    let le = v.to_le_bytes();
    b[off] = le[0];
    b[off + 1] = le[1];
}

/// Number of trailing label bytes in the fixed request layouts.
const N_LABELS: usize = 2;

/// A STRUCTURED-nondeterministic request in a `SHARED_N`-byte buffer.
///
/// Fully raw symbolic bytes make CBMC intractable (measured: >10 min for
/// `abi::decode_request` alone; symbolic arg COUNT / TLV lengths over
/// symbolic slices, and a large unwind bound), so the wire LAYOUT is
/// fixed per harness (`one_arg` is a compile-time-concrete argument) while
/// every field VALUE is nondeterministic (`kani::any()`):
///  * `one_arg == true`:  header 16 | one URL-shaped TLV 17 | 2 label bytes
///    (35 bytes): session_id, req_id, cap_handle, tool_id, the TLV tag
///    byte, URL scheme byte, the 5 host BYTES (length fixed), port,
///    path_len (0..=2), 2 path bytes, 2 label bytes.
///  * `one_arg == false`: header 16 | 2 label bytes (18 bytes), same
///    nondeterministic header fields and label bytes.
/// The magic is the real one. Returns the buffer and the layout's length.
/// Callers truncate / offset it via (ptr, len, region) for stage-1 paths.
fn any_request(one_arg: bool) -> ([u8; SHARED_N], usize) {
    let mut b = [0u8; SHARED_N];
    b[0..4].copy_from_slice(&abi::MAGIC.to_le_bytes());
    put16(&mut b, 4, kani::any());
    put16(&mut b, 6, kani::any());
    put16(&mut b, 8, kani::any());
    put16(&mut b, 10, kani::any());
    b[12] = one_arg as u8;
    b[13] = 0;
    put16(&mut b, 14, N_LABELS as u16);
    let mut off = HDR;
    if one_arg {
        b[off] = kani::any(); // tag
        put16(&mut b, off + 1, TLV_VAL as u16);
        let v = off + 3;
        b[v] = kani::any(); // scheme
        put16(&mut b, v + 1, HOST as u16);
        let mut k = 0;
        while k < HOST {
            b[v + 3 + k] = kani::any();
            k += 1;
        }
        let p = v + 3 + HOST;
        put16(&mut b, p, kani::any()); // port
        let path_len: u16 = kani::any();
        kani::assume(path_len <= 2);
        put16(&mut b, p + 2, path_len);
        b[p + 4] = kani::any();
        b[p + 5] = kani::any();
        off += TLV;
    }
    b[off] = kani::any();
    b[off + 1] = kani::any();
    (b, off + N_LABELS)
}

/// Stub for `Audit::append`: the audit hash chain (Blake2s over the request
/// bytes) is irrelevant to the decision/egress property and intractable
/// for CBMC over symbolic input. `mediate` only WRITES to the audit log; it
/// never reads it back to decide anything, so stubbing it does not alter
/// the rc / sink / response behaviour under test.
fn stub_append(_a: &mut Audit, _e: Entry) {}

/// Stub for `request_bytes_were_copied`: this helper ONLY selects whether
/// the audit `req_hash` is Blake2s(request bytes) or the zero hash (see its
/// doc comment: "never influences the actual admission decision"). Forcing
/// `false` skips the Blake2s call, which is intractable for CBMC over
/// symbolic bytes. rc / sink / response are unaffected.
fn stub_eval(
    _c: &[predicate::Clause],
    _a: &predicate::Args,
    _p: &predicate::ConstPool,
) -> Result<(), ReasonCode> {
    // Assume-guarantee abstraction of stage 4: the predicate may return Ok
    // or either deny code. The egress-ordering property must hold for ANY
    // outcome; `predicate::eval`'s own correctness is covered by its unit
    // tests, not by these harnesses.
    if kani::any() {
        Ok(())
    } else if kani::any() {
        Err(ReasonCode::DenyArg)
    } else {
        Err(ReasonCode::DenyMalformed)
    }
}

fn stub_not_copied(_s: &[u8], _p: usize, _l: usize, _r: &Range<usize>) -> bool {
    false
}

/// MAIN PROPERTY (manual Ch 13 sec 13.2). For nondeterministic request
/// field values (see `any_request`), nondeterministic truncation `len`,
/// offset `ptr` and `region`:
///   (a) rc != Allow  =>  the response is empty (no body bytes, PUBLIC label);
///   (b) the sink is invoked only when rc == Allow, or the sink itself
///       reported failure (then rc == ErrEgress): so every parse failure and
///       every pre-egress stage denial performs NO egress;
///   (c) rc == Allow  =>  the sink was invoked (Allow is never silent).
fn check_main_property(one_arg: bool) {
    let (shared, _total) = any_request(one_arg);
    let ptr: usize = 0; // fixed: keeps n_args concrete; ptr/len/region are fully symbolic in the stage-1 harness
    let len: usize = kani::any();
    kani::assume(len <= SHARED_N); // len > shared.len() is a stage-1 reject (see PROOFS.md)
    let region: Range<usize> = kani::any::<usize>()..kani::any::<usize>();
    let mut sessions = sessions_fixture();
    let policy = policy_fixture();
    let mut sink = RecordingSink { performed: false, fail: kani::any() };
    let mut audit = Audit::default();

    let (rc, resp) = mediate(&shared, ptr, len, region, &mut sessions, &policy, &mut sink, &mut audit);

    // Vacuity guards: the interesting outcomes are reachable in this model.
    kani::cover!(rc == ReasonCode::Allow);
    kani::cover!(rc == ReasonCode::DenyMalformed);
    kani::cover!(rc == ReasonCode::DenyNoCap);
    kani::cover!(rc == ReasonCode::DenyTool);
    kani::cover!(rc == ReasonCode::DenyArg);
    kani::cover!(rc == ReasonCode::ErrEgress);
    if rc != ReasonCode::Allow {
        assert!(resp.bytes().is_empty());
        assert!(resp.label() == Label::PUBLIC);
        assert!(!sink.performed || (sink.fail && rc == ReasonCode::ErrEgress));
    } else {
        assert!(sink.performed);
    }
}

#[kani::proof]
#[kani::stub(audit::Audit::append, stub_append)]
#[kani::stub(request_bytes_were_copied, stub_not_copied)]
#[kani::stub(predicate::eval, stub_eval)]
#[kani::unwind(8)]
fn mediate_non_allow_no_egress_one_arg() {
    check_main_property(true);
}

#[kani::proof]
#[kani::stub(audit::Audit::append, stub_append)]
#[kani::stub(request_bytes_were_copied, stub_not_copied)]
#[kani::stub(predicate::eval, stub_eval)]
#[kani::unwind(8)]
fn mediate_non_allow_no_egress_no_args() {
    check_main_property(false);
}

/// `cap::resolve` revocation: for ANY handle, ANY epoch and ANY contents
/// of one cspace slot (the rest Empty), a slot whose epoch differs from the
/// session epoch never resolves; an Ok result is always an in-range,
/// non-Empty, current-epoch cap.
#[kani::proof]
#[kani::unwind(40)]
fn resolve_stale_epoch_never_resolves() {
    let handle: u16 = kani::any();
    let idx: usize = kani::any();
    kani::assume(idx < cap::CSPACE_LEN);
    let epoch: u16 = kani::any();
    let slot_epoch: u16 = kani::any();
    let ctype: u8 = kani::any();
    let mut cspace = [EMPTY_CAP; cap::CSPACE_LEN];
    cspace[idx] = cap::Cap { ctype, epoch: slot_epoch, ..EMPTY_CAP };
    let s = cap::Session::active(epoch, cspace);
    let r = cap::resolve(&s, handle);
    if let Ok(c) = r {
        assert!((handle as usize) < cap::CSPACE_LEN);
        assert!(c.epoch == epoch);
        assert!(c.ctype != cap::CapType::Empty as u8);
    }
    if (handle as usize) == idx && ctype != cap::CapType::Empty as u8 && slot_epoch != epoch {
        assert!(r.is_err());
    }
}

/// End-to-end revocation through the session table: after `Sessions::revoke`
/// bumps the epoch, the previously-live cap no longer resolves (ANY handle).
#[kani::proof]
#[kani::unwind(40)]
fn revoked_session_cap_never_resolves() {
    let handle: u16 = kani::any();
    let mut sessions = sessions_fixture();
    assert!(cap::resolve(sessions.get(1).unwrap(), 3).is_ok());
    sessions.revoke(1);
    assert!(cap::resolve(sessions.get(1).unwrap(), handle).is_err());
}

/// Stage 1: for ANY (ptr, len, region) whose span is NOT a valid in-region,
/// in-bounds, <= MAX_REQ slice of `shared`, and ANY `shared` contents,
/// `mediate` rejects with DenyMalformed, returns an EMPTY response, and the
/// sink is never invoked.
#[kani::proof]
#[kani::stub(audit::Audit::append, stub_append)]
#[kani::stub(request_bytes_were_copied, stub_not_copied)]
#[kani::stub(predicate::eval, stub_eval)]
#[kani::unwind(8)]
fn mediate_stage1_reject_never_reaches_sink() {
    let shared: [u8; SHARED_N] = kani::any();
    let ptr: usize = kani::any();
    let len: usize = kani::any();
    let region: Range<usize> = kani::any::<usize>()..kani::any::<usize>();
    let valid = len <= MAX_REQ
        && ptr.checked_add(len).is_some()
        && ptr >= region.start
        && ptr.wrapping_add(len) <= region.end
        && ptr.wrapping_add(len) <= SHARED_N;
    kani::assume(!valid);
    let mut sessions = sessions_fixture();
    let policy = policy_fixture();
    let mut sink = RecordingSink { performed: false, fail: kani::any() };
    let mut audit = Audit::default();
    let (rc, resp) = mediate(&shared, ptr, len, region, &mut sessions, &policy, &mut sink, &mut audit);
    assert!(rc == ReasonCode::DenyMalformed);
    assert!(resp.bytes().is_empty());
    assert!(resp.label() == Label::PUBLIC);
    assert!(!sink.performed);
}
