#![forbid(unsafe_code)]

use abi::ReasonCode;

/// Capability type enumeration.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CapType {
    Empty = 0,
    Net = 1,
    File = 2,
    Secret = 3,
    Tool = 4,
}

/// A single capability slot. Exactly 16 bytes.
/// Layout: ctype(u8) + rights(u8) + tool_id(u16) + pred_ref(u16) + flow_ref(u16)
///         + secret_ref(u16) + aux(u16) + epoch(u16) = 14 bytes + 2-byte padding = 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Cap {
    pub ctype: u8,
    pub rights: u8,
    pub tool_id: u16,
    pub pred_ref: u16,
    pub flow_ref: u16,
    pub secret_ref: u16,
    pub aux: u16,
    pub epoch: u16,
    pub _pad: u16, // Explicit padding to reach 16 bytes.
}

/// A session holds an epoch and a capability space of 32 slots.
pub const CSPACE_LEN: usize = 32;

#[derive(Copy, Clone, Debug)]
pub struct Session {
    pub epoch: u16,
    pub cspace: [Cap; CSPACE_LEN],
}

/// Resolve a capability handle within a session.
/// - Returns `DenyNoCap` if the handle is out of range or points to an Empty slot.
/// - Returns `DenyRevoked` if the slot's epoch != session's epoch.
/// - Otherwise returns a reference to the Cap.
pub fn resolve(s: &Session, handle: u16) -> Result<&Cap, ReasonCode> {
    let idx = handle as usize;

    // Check bounds
    if idx >= CSPACE_LEN {
        return Err(ReasonCode::DenyNoCap);
    }

    let cap = &s.cspace[idx];

    // Check if slot is empty
    if cap.ctype == CapType::Empty as u8 {
        return Err(ReasonCode::DenyNoCap);
    }

    // Check epoch
    if cap.epoch != s.epoch {
        return Err(ReasonCode::DenyRevoked);
    }

    Ok(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> Session {
        let mut s = Session {
            epoch: 1,
            cspace: [Cap {
                ctype: CapType::Empty as u8,
                rights: 0,
                tool_id: 0,
                pred_ref: 0,
                flow_ref: 0,
                secret_ref: 0,
                aux: 0,
                epoch: 1,
                _pad: 0,
            }; CSPACE_LEN],
        };

        // Put a live cap at index 3 with tool_id 0x1000
        s.cspace[3] = Cap {
            ctype: CapType::Tool as u8,
            rights: 0,
            tool_id: 0x1000,
            pred_ref: 0,
            flow_ref: 0,
            secret_ref: 0,
            aux: 0,
            epoch: 1,
            _pad: 0,
        };

        s
    }

    #[test]
    fn empty_slot_denies() {
        let s = make_session();
        assert_eq!(resolve(&s, 0).unwrap_err(), ReasonCode::DenyNoCap);
    }

    #[test]
    fn out_of_range_denies() {
        let s = make_session();
        assert_eq!(resolve(&s, 99).unwrap_err(), ReasonCode::DenyNoCap);
    }

    #[test]
    fn stale_epoch_denies() {
        let mut s = make_session();
        s.cspace[3].epoch = s.epoch.wrapping_sub(1);
        assert_eq!(resolve(&s, 3).unwrap_err(), ReasonCode::DenyRevoked);
    }

    #[test]
    fn live_cap_resolves() {
        let s = make_session();
        assert_eq!(resolve(&s, 3).unwrap().tool_id, 0x1000);
    }

    #[test]
    fn size_is_16_bytes() {
        assert_eq!(core::mem::size_of::<Cap>(), 16);
    }
}
