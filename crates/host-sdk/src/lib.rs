//! Host-side SDK: build an `abi` request, frame it for the wire, parse a response.
pub use wire::DropReason;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TypedArgOwned {
    Url { https: bool, host: Vec<u8>, port: u16, path: Vec<u8> },
    Path(Vec<u8>),
    Enum(u16),
    Int(i64),
    Bytes(Vec<u8>),
    LabelSet(abi::Label),
}

fn tlv(out: &mut Vec<u8>, tag: u8, val: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(val.len() as u16).to_le_bytes());
    out.extend_from_slice(val);
}

impl TypedArgOwned {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            TypedArgOwned::Url { https, host, port, path } => {
                let mut v = vec![*https as u8];
                v.extend_from_slice(&(host.len() as u16).to_le_bytes());
                v.extend_from_slice(host);
                v.extend_from_slice(&port.to_le_bytes());
                v.extend_from_slice(&(path.len() as u16).to_le_bytes());
                v.extend_from_slice(path);
                tlv(out, 0x01, &v);
            }
            TypedArgOwned::Path(p) => tlv(out, 0x02, p),
            TypedArgOwned::Enum(e) => tlv(out, 0x03, &e.to_le_bytes()),
            TypedArgOwned::Int(i) => tlv(out, 0x04, &i.to_le_bytes()),
            TypedArgOwned::Bytes(b) => tlv(out, 0x05, b),
            TypedArgOwned::LabelSet(l) => tlv(out, 0x06, &[l.0]),
        }
    }
}

/// Build the inner request bytes (the Phase-1 `abi` format).
pub fn build_request(
    session_id: u16,
    req_id: u16,
    cap_handle: u16,
    tool_id: u16,
    args: &[TypedArgOwned],
    labels: &[abi::Label],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&abi::MAGIC.to_le_bytes());
    v.extend_from_slice(&session_id.to_le_bytes());
    v.extend_from_slice(&req_id.to_le_bytes());
    v.extend_from_slice(&cap_handle.to_le_bytes());
    v.extend_from_slice(&tool_id.to_le_bytes());
    v.push(args.len() as u8);
    v.push(0);
    v.extend_from_slice(&(labels.len() as u16).to_le_bytes());
    for a in args {
        a.encode(&mut v);
    }
    v.extend(labels.iter().map(|l| l.0));
    v
}

/// Build + frame a request. Err(TooLong) if it exceeds the wire payload bound.
pub fn frame_request(
    session_id: u16,
    req_id: u16,
    cap_handle: u16,
    tool_id: u16,
    args: &[TypedArgOwned],
    labels: &[abi::Label],
) -> Result<Vec<u8>, DropReason> {
    let req = build_request(session_id, req_id, cap_handle, tool_id, args, labels);
    let mut out = vec![0u8; wire::MAX_FRAME];
    let n = wire::frame(&req, &mut out)?;
    out.truncate(n);
    Ok(out)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResponseView {
    pub status: u8,
    pub req_id: u16,
    /// Present only when `status == ReasonCode::Allow`.
    pub result: Vec<u8>,
}

/// Deframe + split `status:u8 . req_id:u16 . result`. A payload shorter than 3
/// bytes is `Empty`; a denial carrying a body is rejected (`TooLong`).
pub fn parse_response(frame: &[u8]) -> Result<ResponseView, DropReason> {
    let mut scratch = vec![0u8; wire::MAX_FRAME];
    let p = wire::deframe(frame, &mut scratch)?;
    if p.len() < 3 {
        return Err(DropReason::Empty);
    }
    let status = p[0];
    let req_id = u16::from_le_bytes([p[1], p[2]]);
    let result = p[3..].to_vec();
    if status != abi::ReasonCode::Allow as u8 && !result.is_empty() {
        return Err(DropReason::TooLong);
    }
    Ok(ResponseView { status, req_id, result })
}
