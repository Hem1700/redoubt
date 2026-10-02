use abi::{ArgVal, Label, ReasonCode, Scheme};
use host_sdk::*;

fn rt(arg: TypedArgOwned, check: impl Fn(&ArgVal)) {
    let labels = [Label::SECRET, Label::TRUSTED];
    let f = frame_request(1, 2, 3, 4, &[arg], &labels).unwrap();
    let mut s = [0u8; wire::MAX_FRAME];
    let p = wire::deframe(&f, &mut s).unwrap();
    let r = abi::decode_request(p).unwrap();
    assert_eq!((r.session_id, r.req_id, r.cap_handle, r.tool_id), (1, 2, 3, 4));
    assert_eq!(r.in_labels, &[Label::SECRET.0, Label::TRUSTED.0]);
    let a: Vec<_> = r.args.collect();
    assert_eq!(a.len(), 1);
    check(&a[0].val);
}

#[test]
fn url() {
    rt(
        TypedArgOwned::Url { https: true, host: b"example.com".to_vec(), port: 443, path: b"/x".to_vec() },
        |v| match v {
            ArgVal::Url(u) => {
                assert_eq!((u.scheme, u.host, u.port, u.path), (Scheme::Https, &b"example.com"[..], 443, &b"/x"[..]))
            }
            _ => panic!(),
        },
    );
}
#[test]
fn path() {
    rt(TypedArgOwned::Path(b"/a\0b".to_vec()), |v| assert_eq!(*v, ArgVal::Path(b"/a\0b")));
}
#[test]
fn enum_() {
    rt(TypedArgOwned::Enum(0x1234), |v| assert_eq!(*v, ArgVal::Enum(0x1234)));
}
#[test]
fn int() {
    rt(TypedArgOwned::Int(-42), |v| assert_eq!(*v, ArgVal::Int(-42)));
}
#[test]
fn bytes() {
    rt(TypedArgOwned::Bytes(vec![0, 0, 1, 0]), |v| assert_eq!(*v, ArgVal::Bytes(&[0, 0, 1, 0])));
}
#[test]
fn labelset() {
    rt(TypedArgOwned::LabelSet(Label::SECRET), |v| assert_eq!(*v, ArgVal::LabelSet(Label::SECRET)));
}

fn resp(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; wire::MAX_FRAME];
    let n = wire::frame(payload, &mut f).unwrap();
    f.truncate(n);
    f
}

#[test]
fn response_allow_and_denial() {
    let r = parse_response(&resp(&[0x00, 0x34, 0x12, b'o', b'k'])).unwrap();
    assert_eq!((r.status, r.req_id, r.result.as_slice()), (0, 0x1234, &b"ok"[..]));
    let d = parse_response(&resp(&[ReasonCode::DenyArg as u8, 0x07, 0x00])).unwrap();
    assert_eq!((d.status, d.req_id), (0x12, 7));
    assert!(d.result.is_empty());
    // a denial with a body is rejected; corrupt/short frames are dropped
    assert!(parse_response(&resp(&[0x12, 7, 0, 0xAA])).is_err());
    assert!(parse_response(&resp(&[0x00, 1])).is_err());
    let mut bad = resp(&[0, 1, 0]);
    bad[1] ^= 0x10;
    assert!(parse_response(&bad).is_err());
}
