# Machine-checked properties of the mediation chain (Kani / CBMC)

This note turns the Chapter 13 section 13.2 proof sketch into properties that
a tool actually checks. It is **bounded model checking** (Kani 0.68 driving
CBMC), **strictly weaker than a full functional-correctness proof**. We say
"machine-checked under these bounds", never "formally verified". The VexRiscv
RTL, the Rust compiler/LLVM, the Warden, the host crypto, and the
hand-written unit-tested stage logic noted below remain trusted, not proven.

Run it (separate, slower than the normal suite; it is NOT part of
`cargo test` or `cargo clippy`):

    cargo xtask kani                       # all harnesses
    cargo xtask kani -- --harness NAME     # one harness

Prerequisite: `cargo install --locked kani-verifier && cargo kani setup`.
Every harness lives in `crates/monitor/src/proofs.rs` behind `#[cfg(kani)]`
(`mod proofs;` in `lib.rs`), so a normal build, `cargo test` and
`cargo clippy -- -D warnings` never see it. `crates/monitor/Cargo.toml`
declares `cfg(kani)` via `[lints.rust] unexpected_cfgs` so those builds stay
warning-free.

## What is checked

| Harness | Property | Wall time |
|---|---|---|
| `mediate_non_allow_no_egress_one_arg` | Main property (below), request shape with one URL arg | about 8 min |
| `mediate_non_allow_no_egress_no_args` | Main property, request shape with no args | about 7 min |
| `mediate_stage1_reject_never_reaches_sink` | For ANY `ptr`, `len`, `region` whose span is not a valid in-region, in-bounds, `<= MAX_REQ` slice, and ANY shared bytes: `DenyMalformed`, empty response, sink never invoked | about 2.5 min |
| `resolve_stale_epoch_never_resolves` | `cap::resolve`: for ANY handle, epoch and slot contents, a stale-epoch slot never resolves; an `Ok` is in range, non-Empty, current-epoch | seconds |
| `revoked_session_cap_never_resolves` | After `Sessions::revoke`, the previously live cap resolves for NO handle | seconds |
| `toolchain_smoke` | `check_tool` mismatch is `DenyTool` (confirms the `no_std` crate builds under Kani) | seconds |

### The main property (Ch 13 section 13.2)

`check_main_property` runs the real `mediate` with a recording `EgressSink`
(the observation seam; no production code is changed for it) and asserts:

- (a) `rc != Allow` implies the returned `ResponseView` is empty (zero body
  bytes, `Label::PUBLIC`): no secret can be in a non-Allow response;
- (b) the sink is invoked only if `rc == Allow`, or the sink itself reported
  failure (then `rc == ErrEgress`): every parse failure and every pre-egress
  stage denial performs no egress;
- (c) `rc == Allow` implies the sink was invoked.

Vacuity guards (`kani::cover!`): Allow, DenyMalformed, DenyNoCap, DenyTool,
DenyArg and ErrEgress are each reachable inside the bounded model (6 of 6
cover properties satisfied).

## Bounds and assumptions (exactly what is NOT free)

CBMC could not discharge `mediate` over fully symbolic request bytes within
hours (measured: more than 10 minutes for `abi::decode_request` alone), so the
model is bounded as follows. A proof here says nothing outside these bounds.

1. **Structured request.** The wire layout is fixed per harness (header 16 | one
   URL-shaped TLV 17 | 2 label bytes, or header | 2 label bytes); every field
   VALUE is nondeterministic: `session_id`, `req_id`, `cap_handle`, `tool_id`,
   TLV tag, URL scheme byte, the 5 host bytes, port, `path_len` (0..=2), path
   bytes, label bytes. The request length handed to `mediate` (`len`) and the
   `region` are fully symbolic (`len <= 48`); `ptr` is 0 in the main harnesses
   and fully symbolic in the stage-1 harness. Request shapes with several
   args, other TLV layouts, or host lengths other than 5 are not explored.
2. **Fixed policy and session table.** One hand-built policy (the Phase-1
   fixture shape: one `HostInSet` clause, one flow rule that denies SECRET to a
   public sink and injects one secret) and one installed session (id 1,
   epoch 1, one live Net cap at handle 3, unlimited quotas). The allowlisted
   host is `ex.io` (5 bytes, to keep CBMC slice-iterator loops small). Policy
   and quota variations are not explored.
3. **Model-size constants under `cfg(kani)` only.** `parse::MAX_REQ` is 64 and
   `egress::RESP_BODY_MAX` is 16 under `cfg(kani)` (production: 512 and 512,
   unchanged; `abi::decode_request` keeps its own 512 limit). Large by-value
   buffers make CBMC intractable. These are `#[cfg(kani)]` constants in
   `parse.rs` and `egress.rs`; no decision logic differs.
4. **Stubs (proof-only, `-Z stubbing`).**
   - `Audit::append` and `request_bytes_were_copied` are stubbed. They only
     decide the contents of the audit `req_hash` (Blake2s of the request, or
     zeros); `mediate` writes the audit log and never reads it back to
     decide. So the Blake2s hash and the audit chain are NOT covered by these
     proofs.
   - **`predicate::eval` (stage 4) is replaced by a nondeterministic
     Ok / `DenyArg` / `DenyMalformed`.** The main property is therefore an
     assume-guarantee statement: it holds for ANY outcome of the predicate
     stage, which is exactly the ordering/fail-closed claim (perform only
     after every stage returned Ok). The predicate's own semantics (host
     matching, case folding, ranges) are covered by its unit tests in
     `predicate.rs`, not by Kani. The stage-3 `check_tool`, stage-5
     `flow_check`, stage-2 session/cap/quota logic, `bridge_args`,
     `bridge_labels` and the real decoder all run unstubbed.
5. **Sink model.** The recording sink either succeeds with a fixed non-secret
   body or fails with `ErrEgress` (nondeterministic). The inject-only
   guarantee (secret never in a returned body) is the sink contract in
   `egress.rs`; the proof shows that nothing in `mediate` copies the secret
   into the response on any path other than the sink's returned body.
6. **Unwind bounds.** Harnesses use `#[kani::unwind(8)]` (40 for the tiny
   `resolve` ones). Kani's unwinding assertions are enabled and pass, so the
   bound is checked, not assumed.

## Not covered

Full functional correctness of any stage; the predicate engine; the audit
chain and its hashing; multi-arg or other-shaped requests; policy and quota
variation; concurrency and the shared-memory TOCTOU window (the copy-before-
decode design is argued in `parse.rs`, not checked here); the VexRiscv RTL;
rustc/LLVM; the Warden and board bring-up.
