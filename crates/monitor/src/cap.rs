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

/// The system-wide bound on concurrent agent sessions the monitor holds.
pub const MAX_SESSIONS: usize = 8;

/// The session table: owns every live `Session`, indexed by session id.
///
/// `tbl` is private; the only access is through `get`/`get_mut`/`revoke`, so
/// every lookup goes through the same fail-closed bounds check in one place.
pub struct Sessions {
    tbl: [Option<Session>; MAX_SESSIONS],
}

impl Default for Sessions {
    fn default() -> Self {
        Sessions {
            tbl: [None; MAX_SESSIONS],
        }
    }
}

impl Sessions {
    /// Look up a session by id. `DenyNoCap` if id is out of range or empty.
    pub fn get(&self, id: u16) -> Result<&Session, ReasonCode> {
        let idx = id as usize;
        if idx >= MAX_SESSIONS {
            return Err(ReasonCode::DenyNoCap);
        }
        self.tbl[idx].as_ref().ok_or(ReasonCode::DenyNoCap)
    }

    /// Mutable lookup (needed to install caps / bump epoch). Same error contract.
    pub fn get_mut(&mut self, id: u16) -> Result<&mut Session, ReasonCode> {
        let idx = id as usize;
        if idx >= MAX_SESSIONS {
            return Err(ReasonCode::DenyNoCap);
        }
        self.tbl[idx].as_mut().ok_or(ReasonCode::DenyNoCap)
    }

    /// Install a session at `id`, replacing whatever (if anything) was
    /// there. `DenyNoCap` if `id` is out of range. This is the path
    /// `SESSION_OPEN` will use to seed a fresh session (Task 11 deferred
    /// it); overwriting an existing slot is allowed -- callers that want
    /// "must not already exist" semantics check `get` first themselves.
    pub fn install(&mut self, id: u16, session: Session) -> Result<(), ReasonCode> {
        let idx = id as usize;
        if idx >= MAX_SESSIONS {
            return Err(ReasonCode::DenyNoCap);
        }
        self.tbl[idx] = Some(session);
        Ok(())
    }

    /// Revoke every capability in a session by advancing its epoch. After
    /// this, `resolve()` on any handle installed at the old epoch returns
    /// `DenyRevoked`. No-op if `id` is out of range or the slot is empty.
    ///
    /// The cspace is intentionally left untouched: the stale caps must stay
    /// in place so `resolve` reports `DenyRevoked` (not `DenyNoCap`) for
    /// handles installed at the previous epoch. Caps installed after this
    /// call are written at the session's new epoch and resolve normally.
    ///
    /// RULING (epoch-wrap bound): `epoch` is a `u16` and cannot widen — it is
    /// pinned by the 16-byte `Cap` ABI layout — so after 2^16 revocations of
    /// a single session the epoch wraps around and aliases a value a
    /// still-resident stale cap may hold, and that cap would wrongly resolve
    /// as live again. This is a known, documented bound, not a bug to
    /// over-engineer around here: a session should be torn down and
    /// re-seeded (its slot set to `None`, then re-created) well before it
    /// accumulates anywhere near 2^16 revocations, rather than relied on
    /// past that many. `wrapping_add(1)` is used deliberately, matching how
    /// `resolve`'s existing stale-epoch tests already construct epochs.
    pub fn revoke(&mut self, id: u16) {
        let idx = id as usize;
        if idx >= MAX_SESSIONS {
            return;
        }
        if let Some(session) = self.tbl[idx].as_mut() {
            session.epoch = session.epoch.wrapping_add(1);
        }
    }
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

    // Build a Sessions with a session at id 1 that has a resolvable cap at
    // handle 3 (installed at the session's current epoch, ctype != Empty).
    fn one_session_with_caps() -> Sessions {
        let mut tbl = [None; MAX_SESSIONS];
        tbl[1] = Some(make_session());
        Sessions { tbl }
    }

    #[test]
    fn revoke_stales_all_handles() {
        let mut ss = one_session_with_caps();
        ss.revoke(1);
        assert_eq!(
            resolve(ss.get(1).unwrap(), 3).unwrap_err(),
            ReasonCode::DenyRevoked
        );
    }

    #[test]
    fn unknown_session_denies() {
        assert_eq!(
            Sessions::default().get(5).unwrap_err(),
            ReasonCode::DenyNoCap
        );
    }

    #[test]
    fn get_out_of_range_denies() {
        let ss = Sessions::default();
        assert_eq!(
            ss.get(MAX_SESSIONS as u16).unwrap_err(),
            ReasonCode::DenyNoCap
        );
        assert_eq!(ss.get(u16::MAX).unwrap_err(), ReasonCode::DenyNoCap);
    }

    #[test]
    fn get_mut_out_of_range_denies() {
        let mut ss = Sessions::default();
        assert_eq!(
            ss.get_mut(MAX_SESSIONS as u16).unwrap_err(),
            ReasonCode::DenyNoCap
        );
        assert_eq!(ss.get_mut(u16::MAX).unwrap_err(), ReasonCode::DenyNoCap);
    }

    #[test]
    fn revoke_then_freshly_installed_cap_resolves_ok() {
        let mut ss = one_session_with_caps();
        ss.revoke(1);
        let new_epoch = ss.get(1).unwrap().epoch;

        // Install a fresh cap at handle 5, written at the session's NEW epoch.
        let session = ss.get_mut(1).unwrap();
        session.cspace[5] = Cap {
            ctype: CapType::Tool as u8,
            rights: 0,
            tool_id: 0x2000,
            pred_ref: 0,
            flow_ref: 0,
            secret_ref: 0,
            aux: 0,
            epoch: new_epoch,
            _pad: 0,
        };

        assert_eq!(resolve(ss.get(1).unwrap(), 5).unwrap().tool_id, 0x2000);
        // The stale handle from before the revoke remains revoked.
        assert_eq!(
            resolve(ss.get(1).unwrap(), 3).unwrap_err(),
            ReasonCode::DenyRevoked
        );
    }

    #[test]
    fn revoke_out_of_range_is_noop() {
        let mut ss = one_session_with_caps();
        ss.revoke(MAX_SESSIONS as u16);
        ss.revoke(u16::MAX);
        assert!(resolve(ss.get(1).unwrap(), 3).is_ok());
    }

    #[test]
    fn revoke_on_empty_slot_is_noop() {
        let mut ss = one_session_with_caps();
        ss.revoke(2); // id 2 has no session installed
        assert_eq!(ss.get(2).unwrap_err(), ReasonCode::DenyNoCap);
        // Unrelated session at id 1 is unaffected.
        assert!(resolve(ss.get(1).unwrap(), 3).is_ok());
    }

    #[test]
    fn install_out_of_range_denies() {
        let mut ss = Sessions::default();
        assert_eq!(
            ss.install(MAX_SESSIONS as u16, make_session()).unwrap_err(),
            ReasonCode::DenyNoCap
        );
    }

    #[test]
    fn install_then_get_resolves() {
        let mut ss = Sessions::default();
        ss.install(2, make_session()).unwrap();
        assert_eq!(resolve(ss.get(2).unwrap(), 3).unwrap().tool_id, 0x1000);
    }

    #[test]
    fn install_overwrites_existing_slot() {
        let mut ss = Sessions::default();
        ss.install(2, make_session()).unwrap();
        let mut fresh = make_session();
        fresh.cspace[3].tool_id = 0x9999;
        ss.install(2, fresh).unwrap();
        assert_eq!(resolve(ss.get(2).unwrap(), 3).unwrap().tool_id, 0x9999);
    }

    #[test]
    fn empty_slot_denies_before_revoke() {
        let ss = one_session_with_caps();
        // Handle 0 in make_session() points at an Empty-ctype slot, at the
        // same epoch as the session: must deny as DenyNoCap, not DenyRevoked.
        assert_eq!(
            resolve(ss.get(1).unwrap(), 0).unwrap_err(),
            ReasonCode::DenyNoCap
        );
    }
}
