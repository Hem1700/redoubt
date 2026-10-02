//! The compiled allow-policy type (ruling P3-1: the ONE `Policy`).
//!
//! Moved verbatim from the crate root. It is filled either by hand (Phase-1
//! fixtures) or by the `policyc` manifest compiler; `mediate` evaluates it
//! identically either way.
#![forbid(unsafe_code)]

use abi::ReasonCode;

use crate::{flow, predicate};

/// The compiled allow-policy for a tenant. On real hardware the `secrets`
/// table lives in the machine-only SECRETS region, loaded once at boot;
/// modeling it as a `Policy` field here is a convenience.
pub struct Policy<'a> {
    /// Compiled predicate clauses, indexed by `Cap.pred_ref`.
    pub preds: &'a [&'a [predicate::Clause]],
    /// Compiled IFC flow rules, indexed by `Cap.flow_ref`.
    pub flows: &'a [flow::FlowRule],
    /// Interned secret bytes, indexed by a `FlowRule.inject` secret_ref.
    pub secrets: &'a [&'a [u8]],
    /// Interned predicate constants (allowlists, ranges, ...), shared by
    /// every clause in `preds`.
    pub pool: predicate::ConstPool<'a>,
}

impl<'a> Policy<'a> {
    /// Resolve a `Cap.pred_ref` to its compiled clause slice. Out-of-range
    /// => `DenyMalformed` (fail closed): an unresolvable policy reference
    /// is a policy-construction bug, never treated as "no clauses to
    /// check".
    pub(crate) fn clauses(&self, pred_ref: u16) -> Result<&'a [predicate::Clause], ReasonCode> {
        self.preds
            .get(pred_ref as usize)
            .copied()
            .ok_or(ReasonCode::DenyMalformed)
    }

    /// Resolve a `Cap.flow_ref` to its compiled `FlowRule`. Out-of-range =>
    /// `DenyMalformed` (fail closed).
    pub(crate) fn flow(&self, flow_ref: u16) -> Result<&'a flow::FlowRule, ReasonCode> {
        self.flows
            .get(flow_ref as usize)
            .ok_or(ReasonCode::DenyMalformed)
    }

    /// Resolve a secret reference to its bytes. `None` if out of range --
    /// callers treat "no secret configured" and "bad ref" identically: no
    /// secret is injected.
    pub(crate) fn secret(&self, sref: u16) -> Option<&'a [u8]> {
        self.secrets.get(sref as usize).copied()
    }
}
