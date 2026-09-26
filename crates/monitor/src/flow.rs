//! Information-flow control (IFC) stage.
//!
//! Given the confidentiality/integrity labels of a request's already-typed
//! arguments and the capability in hand, decide whether the flow into the
//! tool's sink is permitted, and compute the label attached to the tool's
//! result. This is a pure function: no I/O, no allocation, no clock, no
//! RNG. It never reads or moves any secret payload — `FlowRule::inject`
//! only names a `secret_ref` for the egress stage (a later task) to
//! consume; this stage passes it through untouched.
//!
//! # Confidentiality vs integrity
//!
//! `abi::Label` packs two independent lattice axes into one `u8`:
//! - bit0 (confidentiality): `PUBLIC (0) ⊑ SECRET (1)`. Public data may
//!   flow into a secret context; secret data may not flow to a public
//!   sink without clearance. This is the load-bearing check here.
//! - bit1 (integrity): `UNTRUSTED (0) ⊑ TRUSTED (1)`. This module does not
//!   compute a join over input integrity — the result's integrity is
//!   policy-supplied via `FlowRule::result_label` (e.g. a network fetch's
//!   rule sets it to `UNTRUSTED` because the fetched bytes are unverified
//!   regardless of the caller's own trust level).
//!
//! # Declassification
//!
//! A sink marked `deny_secret_to_public` normally rejects any request
//! carrying a `SECRET`-labeled argument. A capability holding
//! `RIGHT_DECLASSIFY` is cleared to push secret data to that sink anyway
//! (e.g. a capability scoped to a specific, audited egress path). Without
//! that right, the flow is denied with `ReasonCode::DenyFlow` — fail
//! closed.

#![forbid(unsafe_code)]

use abi::{Label, ReasonCode};
use crate::cap::Cap;

/// Right bit granting declassification (SECRET input -> public sink).
pub const RIGHT_DECLASSIFY: u8 = 0b0000_0001;

/// Bit mask selecting the confidentiality axis of a `Label`.
const CONFIDENTIALITY_MASK: u8 = 0b0000_0001;

/// A compiled information-flow rule for one tool/sink.
///
/// `flow_ref` on a `Cap` (see `crate::cap::Cap`) indexes into a table of
/// these, compiled ahead of time from the tool's manifest (later task);
/// this module only defines the shape and evaluates it.
pub struct FlowRule {
    /// `secret_ref` to inject into the outbound request (inject-only,
    /// never returned to the caller). The egress stage (a later task)
    /// consumes this; `flow_check` itself never reads or moves the
    /// secret behind it.
    pub inject: Option<u16>,
    /// `true` if this sink is a public/egress sink: `SECRET`-labeled
    /// inputs are a confidentiality violation unless the cap carries
    /// `RIGHT_DECLASSIFY` clearance.
    pub deny_secret_to_public: bool,
    /// Label assigned to the tool's result on success.
    pub result_label: Label,
}

/// Decide whether `in_labels` may flow into the sink described by `rule`
/// under the authority of `cap`, and if so, the label of the tool's
/// result.
///
/// Returns `Ok(rule.result_label)` on success, or
/// `Err(ReasonCode::DenyFlow)` if a `SECRET`-labeled input would reach a
/// `deny_secret_to_public` sink without `RIGHT_DECLASSIFY` clearance.
pub fn flow_check(rule: &FlowRule, in_labels: &[Label], cap: &Cap) -> Result<Label, ReasonCode> {
    let any_secret = in_labels
        .iter()
        .any(|l| l.0 & CONFIDENTIALITY_MASK != 0);

    if rule.deny_secret_to_public && any_secret {
        let has_clearance = cap.rights & RIGHT_DECLASSIFY != 0;
        if !has_clearance {
            return Err(ReasonCode::DenyFlow);
        }
    }

    Ok(rule.result_label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::CapType;

    fn cap_net() -> Cap {
        Cap {
            ctype: CapType::Net as u8,
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

    fn cap_net_declassify() -> Cap {
        let mut c = cap_net();
        c.rights |= RIGHT_DECLASSIFY;
        c
    }

    fn rule_public_net() -> FlowRule {
        FlowRule {
            inject: None,
            deny_secret_to_public: true,
            result_label: Label::UNTRUSTED,
        }
    }

    fn rule_non_public(result_label: Label) -> FlowRule {
        FlowRule {
            inject: None,
            deny_secret_to_public: false,
            result_label,
        }
    }

    #[test]
    fn secret_arg_to_public_sink_denies() {
        assert_eq!(
            flow_check(&rule_public_net(), &[Label::SECRET], &cap_net()).unwrap_err(),
            ReasonCode::DenyFlow
        );
    }

    #[test]
    fn public_args_ok_and_result_untrusted() {
        assert_eq!(
            flow_check(&rule_public_net(), &[Label::PUBLIC], &cap_net()).unwrap(),
            Label::UNTRUSTED
        );
    }

    #[test]
    fn declassify_requires_cap() {
        // Without clearance: denied.
        assert_eq!(
            flow_check(&rule_public_net(), &[Label::SECRET], &cap_net()).unwrap_err(),
            ReasonCode::DenyFlow
        );
        // With clearance: allowed, result label returned.
        assert_eq!(
            flow_check(&rule_public_net(), &[Label::SECRET], &cap_net_declassify()).unwrap(),
            Label::UNTRUSTED
        );
    }

    #[test]
    fn non_public_sink_accepts_secret_and_returns_result_label() {
        assert_eq!(
            flow_check(&rule_non_public(Label::TRUSTED), &[Label::SECRET], &cap_net()).unwrap(),
            Label::TRUSTED
        );
    }

    #[test]
    fn mixed_inputs_with_any_secret_deny_without_clearance() {
        assert_eq!(
            flow_check(
                &rule_public_net(),
                &[Label::PUBLIC, Label::SECRET],
                &cap_net()
            )
            .unwrap_err(),
            ReasonCode::DenyFlow
        );
    }

    #[test]
    fn empty_inputs_on_public_sink_ok() {
        assert_eq!(
            flow_check(&rule_public_net(), &[], &cap_net()).unwrap(),
            Label::UNTRUSTED
        );
    }
}
