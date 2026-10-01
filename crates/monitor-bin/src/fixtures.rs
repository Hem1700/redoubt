//! The Phase-1 `mediate` fixtures, shared by BOTH images (ruling P2-1 / Task V4).
//!
//! The QEMU image (`arch.rs`, sink = `ImageSink`) and the Verilated-SoC image
//! (`simtrap.rs`, sink = `EgressMmioSink`) drive `monitor::mediate` against the
//! SAME Policy, the SAME session table and the SAME three canonical request
//! wire images, so their verdicts are parity-by-construction with the host
//! `mediate` tests. The ONLY thing that differs between the two paths is the
//! `EgressSink`. Everything here is 100% safe code.

use abi::ReasonCode;
use monitor::cap::{self, Cap, CapType, Session, Sessions};
use monitor::flow::FlowRule;
use monitor::parse::MAX_REQ;
use monitor::predicate::{Clause, ConstPool, FieldSel, Op, PoolEntry};
use monitor::Policy;

/// The secret the Policy injects on the egress leg (never in a response body).
pub const SECRET: &[u8] = b"API_KEY_SECRET_VALUE";

/// The fixed body every sink returns on ALLOW (the non-leaking response).
pub const RESPONSE_BODY: &[u8] = b"OK-RESPONSE-BODY";

static API_HOSTS: [&[u8]; 1] = [b"api.example.com"];
static CLAUSES_HOST_ONLY: [Clause; 1] =
    [Clause { field: FieldSel::URL_HOST, op: Op::HostInSet, operand: 0 }];
static PRED_SETS: [&[Clause]; 1] = [&CLAUSES_HOST_ONLY];
static FLOWS: [FlowRule; 1] = [FlowRule {
    inject: Some(0),
    deny_secret_to_public: true,
    result_label: abi::Label::UNTRUSTED,
}];
static SECRETS: [&[u8]; 1] = [SECRET];

pub fn build_policy() -> Policy<'static> {
    let pool = ConstPool::new().with(0, PoolEntry::StrSet(&API_HOSTS));
    Policy { preds: &PRED_SETS, flows: &FLOWS, secrets: &SECRETS, pool }
}

pub fn build_sessions() -> Sessions {
    let empty = Cap {
        ctype: CapType::Empty as u8,
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
    // Live Net cap at handle 3, tool_id 0x1000 (matches the host demo).
    cspace[3] = Cap {
        ctype: CapType::Net as u8,
        rights: 0,
        tool_id: 0x1000,
        pred_ref: 0,
        flow_ref: 0,
        secret_ref: 0,
        aux: 0,
        epoch: 1,
        _pad: 0,
    };
    let mut sessions = Sessions::default();
    let _ = sessions.install(1, Session { epoch: 1, cspace });
    sessions
}

/// A wire-format request image (`bytes[..len]`).
pub struct ReqBuf {
    pub bytes: [u8; MAX_REQ],
    pub len: usize,
}

impl ReqBuf {
    fn push(&mut self, b: u8) {
        if self.len < MAX_REQ {
            self.bytes[self.len] = b;
            self.len += 1;
        }
    }
    fn extend(&mut self, s: &[u8]) {
        for &b in s {
            self.push(b);
        }
    }
    fn u16(&mut self, v: u16) {
        self.extend(&v.to_le_bytes());
    }
}

/// Build one request. `url` is `(scheme, host, port, path)`; `method` is an
/// optional BYTES arg; `secret_label` adds a one-byte SECRET in_label.
pub fn build_request(
    session: u16,
    cap_handle: u16,
    tool: u16,
    url: (u8, &[u8], u16, &[u8]),
    method: Option<&[u8]>,
    secret_label: bool,
) -> ReqBuf {
    let mut r = ReqBuf { bytes: [0; MAX_REQ], len: 0 };
    let n_args: u8 = 1 + method.is_some() as u8;
    let labels_len: u16 = secret_label as u16;

    // Header (16 bytes).
    r.extend(&abi::MAGIC.to_le_bytes());
    r.u16(session);
    r.u16(1); // req_id
    r.u16(cap_handle);
    r.u16(tool);
    r.push(n_args);
    r.push(0); // reserved
    r.u16(labels_len);

    // URL TLV (tag 0x01): scheme, host_len, host, port, path_len, path.
    let (scheme, host, port, path) = url;
    let url_val_len = 1 + 2 + host.len() + 2 + 2 + path.len();
    r.push(0x01);
    r.u16(url_val_len as u16);
    r.push(scheme);
    r.u16(host.len() as u16);
    r.extend(host);
    r.u16(port);
    r.u16(path.len() as u16);
    r.extend(path);

    // Optional METHOD arg (tag 0x05, BYTES).
    if let Some(m) = method {
        r.push(0x05);
        r.u16(m.len() as u16);
        r.extend(m);
    }

    // Trailing in_labels blob.
    if secret_label {
        r.push(abi::Label::SECRET.0);
    }
    r
}

/// The three canonical containment scenarios (index order is the demo order).
#[cfg(feature = "sim")]
pub const N_CASES: u32 = 3;
pub const CASE_BENIGN: u32 = 0;
pub const CASE_ATTACK: u32 = 1;
#[allow(dead_code)] // used by the QEMU image (arch.rs) and the sim case table
pub const CASE_FLOW: u32 = 2;

/// Scenario name printed as `mediate: <name>=<verdict>` (sim image).
#[cfg(feature = "sim")]
pub fn case_name(case: u32) -> &'static str {
    match case {
        CASE_BENIGN => "benign",
        CASE_ATTACK => "attack",
        _ => "flow",
    }
}

/// The verdict each canonical case must produce (sim image).
#[cfg(feature = "sim")]
pub fn case_expected(case: u32) -> u8 {
    match case {
        CASE_BENIGN => ReasonCode::Allow as u8,
        CASE_ATTACK => ReasonCode::DenyArg as u8,
        _ => ReasonCode::DenyFlow as u8,
    }
}

/// The wire image of canonical case `case`.
///  * benign : allowed host           -> ALLOW (secret injected outbound)
///  * attack : wrong host, POST       -> DENY_ARG (dies at stage 4)
///  * flow   : SECRET input to public -> DENY_FLOW (stage 5)
pub fn case_request(case: u32) -> ReqBuf {
    match case {
        CASE_BENIGN => {
            build_request(1, 3, 0x1000, (1, b"api.example.com", 443, b"/x"), None, false)
        }
        CASE_ATTACK => {
            build_request(1, 3, 0x1000, (1, b"evil.tld", 443, b"/steal"), Some(b"POST"), false)
        }
        _ => build_request(1, 3, 0x1000, (1, b"api.example.com", 443, b"/x"), None, true),
    }
}

pub fn verdict_name(status: u8) -> &'static str {
    match status {
        x if x == ReasonCode::Allow as u8 => "ALLOW",
        x if x == ReasonCode::DenyArg as u8 => "DENY_ARG",
        x if x == ReasonCode::DenyFlow as u8 => "DENY_FLOW",
        x if x == ReasonCode::DenyMalformed as u8 => "DENY_MALFORMED",
        x if x == ReasonCode::DenyRevoked as u8 => "DENY_REVOKED",
        x if x == ReasonCode::DenyTool as u8 => "DENY_TOOL",
        x if x == ReasonCode::DenyNoCap as u8 => "DENY_NOCAP",
        x if x == ReasonCode::ErrEgress as u8 => "ERR_EGRESS",
        x if x == ReasonCode::ErrInternal as u8 => "ERR_INTERNAL",
        _ => "UNKNOWN",
    }
}
