#![no_std]
#![forbid(unsafe_code)]

use abi::ReasonCode;

pub mod cap;
pub mod parse;
pub mod predicate;

/// Check if a capability's tool_id matches the expected tool_id.
/// Returns `Ok(())` if they match, `Err(ReasonCode::DenyTool)` if they don't.
pub fn check_tool(cap: &cap::Cap, tool_id: u16) -> Result<(), ReasonCode> {
    if cap.tool_id == tool_id {
        Ok(())
    } else {
        Err(ReasonCode::DenyTool)
    }
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
}
