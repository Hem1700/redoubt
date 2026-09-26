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
