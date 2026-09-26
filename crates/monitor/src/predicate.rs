//! Typed-argument predicate engine.
//!
//! This is the check where most attacks die (the SSRF / host-confusion
//! class): it decides whether a request's already-decoded `TypedArg`s
//! satisfy a compiled policy's clauses. It never re-parses raw bytes and
//! never coerces between argument types — every clause reads exactly one
//! structured field (`abi::ArgVal`) and either that field is present with
//! the expected shape, or the whole evaluation fails closed.
//!
//! # DenyMalformed vs DenyArg
//!
//! - A clause whose selected field is **absent**, or present but holding
//!   the **wrong `ArgVal` variant** for that clause's `Op` (e.g.
//!   `HostInSet` pointed at a `BYTES` arg) -> `ReasonCode::DenyMalformed`.
//!   This is a type-confusion / policy-construction bug, not a value the
//!   predicate rejected, so it is never treated as a silent pass.
//! - A clause whose field resolves cleanly but whose predicate is
//!   **false** -> `ReasonCode::DenyArg`.
//! - All clauses true -> `Ok(())`.
//!
//! # Host matching reads only the structured field
//!
//! `HostInSet` (and every other op) reads `UrlParts.host` as decoded by
//! `abi::decode_request` — never raw URL text. A `%2e`-style trick, an
//! embedded-credential host (`user@evil.tld@api.example.com`), or a
//! port-confusion string only matters here in terms of *what ends up in
//! the structured `host` field*; whatever that value is, it is compared
//! verbatim (case-folded — see below) against the allowlist, with no
//! separate re-parse of anything resembling a URL. See the
//! `smuggled_credential_host_denies` / `port_confusion_host_denies` tests.
//!
//! `HostInSet` matching is case-insensitive (ASCII lower-fold on
//! comparison) as defense in depth, even though `abi::decode_request`
//! already rejects any host containing an uppercase ASCII letter — belt
//! and suspenders, per the brief.
#![forbid(unsafe_code)]

use abi::{ArgVal, ReasonCode, Scheme};

/// Fixed upper bound on the number of clauses `eval` will ever process for
/// one policy. `eval` rejects (fails closed, `DenyMalformed`) any clause
/// slice longer than this rather than silently evaluating only a prefix —
/// silently truncating would mean a clause past the cutoff (which might
/// have denied) is never consulted, which is exactly the kind of
/// fail-open bug this engine exists to prevent.
pub const MAX_CLAUSES: usize = 64;

/// Fixed capacity of a `ConstPool`. Not specified by the brief; chosen to
/// match `MAX_CLAUSES` (a policy realistically interns at most one pool
/// entry per clause).
pub const MAX_POOL: usize = 64;

// ---------------------------------------------------------------------------
// Compiled-policy types (Ruling R2): Op, Clause, FieldSel, ConstPool. The
// manifest compiler that fills these from a tool's declared schema is
// Phase 3 — this module only defines the shapes and evaluates them.
// ---------------------------------------------------------------------------

/// Which comparison a `Clause` performs.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Op {
    /// Exact byte-for-byte match against a single pooled string.
    Eq = 0,
    /// Membership in a pooled set of byte strings (case-sensitive).
    InSet = 1,
    /// Byte-string prefix match against a single pooled string.
    Prefix = 2,
    /// Byte-string suffix match against a single pooled string.
    Suffix = 3,
    /// Membership in a pooled set of byte strings, case-insensitive
    /// (ASCII fold) — the dedicated, defense-in-depth host matcher.
    HostInSet = 4,
    /// Exact match of `UrlParts.scheme` against a pooled `Scheme`.
    SchemeEq = 5,
    /// Inclusive numeric range membership against a pooled `(lo, hi)`.
    Range = 6,
    /// Length of a byte-shaped field <= a pooled limit.
    LenLe = 7,
}

/// Which logical field of a request's typed args a `Clause` inspects.
///
/// A compiled policy binds each `FieldSel` to one of the fixed slots on
/// `Args` below; `eval` never infers a field's position from content.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FieldSel(pub u8);

impl FieldSel {
    pub const URL_HOST: FieldSel = FieldSel(0);
    pub const URL_SCHEME: FieldSel = FieldSel(1);
    pub const METHOD: FieldSel = FieldSel(2);
    pub const PATH: FieldSel = FieldSel(3);
    pub const LEN: FieldSel = FieldSel(4);
}

/// One predicate clause: "field `field`, compared via `op`, against the
/// constant(s) at `pool[operand]`".
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Clause {
    pub field: FieldSel,
    pub op: Op,
    pub operand: u16,
}

/// One interned constant. `operand` in a `Clause` always indexes a
/// `ConstPool` uniformly, regardless of `Op` — including `SchemeEq`, whose
/// two possible values are still looked up via `PoolEntry::Scheme` rather
/// than being packed directly into `operand`, so every clause's operand
/// means the same thing.
#[derive(Copy, Clone, Debug)]
pub enum PoolEntry<'a> {
    /// A single byte string, for `Eq` / `Prefix` / `Suffix`.
    Str(&'a [u8]),
    /// A fixed set of byte strings, for `InSet` / `HostInSet`.
    StrSet(&'a [&'a [u8]]),
    /// A single scheme, for `SchemeEq`.
    Scheme(Scheme),
    /// An inclusive numeric range `(lo, hi)`, for `Range`.
    Range(i64, i64),
    /// A maximum length, for `LenLe`.
    Len(u16),
}

/// A fixed-capacity table of interned policy constants (allowlists,
/// ranges, ...). Built once by the manifest compiler (Phase 3) and shared
/// read-only across every `eval` call for a policy.
#[derive(Copy, Clone, Debug)]
pub struct ConstPool<'a> {
    entries: [Option<PoolEntry<'a>>; MAX_POOL],
}

impl<'a> ConstPool<'a> {
    pub const fn new() -> Self {
        Self { entries: [None; MAX_POOL] }
    }

    /// Set `pool[index]`. Out-of-range indices are silently ignored: this
    /// is a policy-construction-time builder, not part of the per-request
    /// decision path, so there is nothing to fail closed against here —
    /// an index a real policy never uses simply stays absent, and any
    /// clause that (incorrectly) references it will get `DenyMalformed`
    /// from `eval` at evaluation time.
    pub fn with(mut self, index: u16, entry: PoolEntry<'a>) -> Self {
        if let Some(slot) = self.entries.get_mut(index as usize) {
            *slot = Some(entry);
        }
        self
    }

    fn get(&self, index: u16) -> Result<PoolEntry<'a>, ReasonCode> {
        self.entries
            .get(index as usize)
            .copied()
            .flatten()
            .ok_or(ReasonCode::DenyMalformed)
    }

    fn str(&self, index: u16) -> Result<&'a [u8], ReasonCode> {
        match self.get(index)? {
            PoolEntry::Str(s) => Ok(s),
            _ => Err(ReasonCode::DenyMalformed),
        }
    }

    fn str_set(&self, index: u16) -> Result<&'a [&'a [u8]], ReasonCode> {
        match self.get(index)? {
            PoolEntry::StrSet(s) => Ok(s),
            _ => Err(ReasonCode::DenyMalformed),
        }
    }

    fn scheme(&self, index: u16) -> Result<Scheme, ReasonCode> {
        match self.get(index)? {
            PoolEntry::Scheme(s) => Ok(s),
            _ => Err(ReasonCode::DenyMalformed),
        }
    }

    fn range(&self, index: u16) -> Result<(i64, i64), ReasonCode> {
        match self.get(index)? {
            PoolEntry::Range(lo, hi) => Ok((lo, hi)),
            _ => Err(ReasonCode::DenyMalformed),
        }
    }

    fn len_limit(&self, index: u16) -> Result<u16, ReasonCode> {
        match self.get(index)? {
            PoolEntry::Len(n) => Ok(n),
            _ => Err(ReasonCode::DenyMalformed),
        }
    }
}

impl<'a> Default for ConstPool<'a> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Args: a field-addressable view over the subset of a request's typed args
// that predicate clauses can inspect.
//
// Building a real `Args` from a decoded `RequestView` (binding a specific
// tool's declared argument schema onto these named fields) is the manifest
// compiler's / `mediate()`'s job (Phase 3 / Task 14) — out of scope here.
// This module only defines the shape and lets callers (today: tests only)
// construct one directly via the `with_*` builders, which is why the
// fields themselves stay private.
// ---------------------------------------------------------------------------

/// A field-addressable view over one request's typed args, as consumed by
/// `eval`. Each field is independently optional: a tool call that did not
/// supply a given field leaves it absent, which `eval` treats identically
/// to a present-but-wrong-type field (`DenyMalformed`), never as a pass.
#[derive(Copy, Clone, Debug)]
pub struct Args<'a> {
    url: Option<ArgVal<'a>>,
    method: Option<ArgVal<'a>>,
    path: Option<ArgVal<'a>>,
    len: Option<ArgVal<'a>>,
}

impl<'a> Args<'a> {
    pub const fn new() -> Self {
        Self { url: None, method: None, path: None, len: None }
    }

    pub fn with_url(mut self, v: ArgVal<'a>) -> Self {
        self.url = Some(v);
        self
    }

    pub fn with_method(mut self, v: ArgVal<'a>) -> Self {
        self.method = Some(v);
        self
    }

    pub fn with_path(mut self, v: ArgVal<'a>) -> Self {
        self.path = Some(v);
        self
    }

    pub fn with_len(mut self, v: ArgVal<'a>) -> Self {
        self.len = Some(v);
        self
    }

    /// Resolve a `FieldSel` to the `ArgVal` occupying that slot, or
    /// `DenyMalformed` if the slot is absent. Callers still must check
    /// the returned `ArgVal`'s variant matches what their `Op` expects —
    /// this only proves the slot is *populated*, not well-typed for the
    /// caller's purpose.
    fn slot(&self, field: FieldSel) -> Result<ArgVal<'a>, ReasonCode> {
        let opt = match field {
            FieldSel::URL_HOST | FieldSel::URL_SCHEME => self.url,
            FieldSel::METHOD => self.method,
            FieldSel::PATH => self.path,
            FieldSel::LEN => self.len,
            _ => None,
        };
        opt.ok_or(ReasonCode::DenyMalformed)
    }
}

impl<'a> Default for Args<'a> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// eval
// ---------------------------------------------------------------------------

/// ASCII case-insensitive membership test. `[u8]::eq_ignore_ascii_case`
/// already requires equal lengths before comparing bytes, so e.g. a
/// trailing dot (which changes length) never matches.
fn set_contains_ci(set: &[&[u8]], needle: &[u8]) -> bool {
    set.iter().any(|s| s.eq_ignore_ascii_case(needle))
}

/// Evaluate a compiled policy's clauses against one request's typed args.
///
/// Returns `Ok(())` iff every clause holds. Returns
/// `ReasonCode::DenyMalformed` the moment any clause's selected field is
/// absent or of the wrong `ArgVal` type for that clause's `Op` (including
/// a pool lookup that misses or resolves to the wrong `PoolEntry` kind).
/// Returns `ReasonCode::DenyArg` the moment a well-typed clause's
/// predicate is false. Never panics, never does unbounded work: the loop
/// is bounded by `MAX_CLAUSES` and every field/pool access is a checked
/// lookup, never a direct index or a re-parse of raw bytes.
pub fn eval(clauses: &[Clause], args: &Args, pool: &ConstPool) -> Result<(), ReasonCode> {
    if clauses.len() > MAX_CLAUSES {
        return Err(ReasonCode::DenyMalformed);
    }

    for clause in clauses {
        match clause.op {
            Op::HostInSet => {
                let val = args.slot(clause.field)?;
                let ArgVal::Url(parts) = val else {
                    return Err(ReasonCode::DenyMalformed);
                };
                let set = pool.str_set(clause.operand)?;
                if !set_contains_ci(set, parts.host) {
                    return Err(ReasonCode::DenyArg);
                }
            }
            Op::SchemeEq => {
                let val = args.slot(clause.field)?;
                let ArgVal::Url(parts) = val else {
                    return Err(ReasonCode::DenyMalformed);
                };
                let want = pool.scheme(clause.operand)?;
                if parts.scheme != want {
                    return Err(ReasonCode::DenyArg);
                }
            }
            Op::Eq | Op::InSet | Op::Prefix | Op::Suffix => {
                let val = args.slot(clause.field)?;
                let bytes = match val {
                    ArgVal::Bytes(b) => b,
                    ArgVal::Path(b) => b,
                    _ => return Err(ReasonCode::DenyMalformed),
                };
                let ok = match clause.op {
                    Op::Eq => bytes == pool.str(clause.operand)?,
                    Op::Prefix => bytes.starts_with(pool.str(clause.operand)?),
                    Op::Suffix => bytes.ends_with(pool.str(clause.operand)?),
                    Op::InSet => pool.str_set(clause.operand)?.contains(&bytes),
                    _ => unreachable!(),
                };
                if !ok {
                    return Err(ReasonCode::DenyArg);
                }
            }
            Op::Range => {
                let val = args.slot(clause.field)?;
                let ArgVal::Int(n) = val else {
                    return Err(ReasonCode::DenyMalformed);
                };
                let (lo, hi) = pool.range(clause.operand)?;
                if n < lo || n > hi {
                    return Err(ReasonCode::DenyArg);
                }
            }
            Op::LenLe => {
                let val = args.slot(clause.field)?;
                let len = match val {
                    ArgVal::Bytes(b) => b.len(),
                    ArgVal::Path(b) => b.len(),
                    ArgVal::Url(parts) => parts.host.len(),
                    ArgVal::Int(n) if n >= 0 => n as usize,
                    _ => return Err(ReasonCode::DenyMalformed),
                };
                let limit = pool.len_limit(clause.operand)?;
                if len > limit as usize {
                    return Err(ReasonCode::DenyArg);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::UrlParts;

    // -- pool fixture ------------------------------------------------------

    const API_HOSTS: &[&[u8]] = &[b"api.example.com"];
    const GET_METHODS: &[&[u8]] = &[b"GET"];
    const CORPUS_PREFIX: &[u8] = b"/corpus/";

    const POOL_API_HOSTS: u16 = 0;
    const POOL_HTTPS: u16 = 1;
    const POOL_GET_METHODS: u16 = 2;
    const POOL_CORPUS_PREFIX: u16 = 3;
    const POOL_LEN_8: u16 = 4;
    const POOL_RANGE_1_10: u16 = 5;
    const POOL_METHOD_EQ_GET: u16 = 6;
    const POOL_SUFFIX_JSON: u16 = 7;

    fn pool() -> ConstPool<'static> {
        ConstPool::new()
            .with(POOL_API_HOSTS, PoolEntry::StrSet(API_HOSTS))
            .with(POOL_HTTPS, PoolEntry::Scheme(Scheme::Https))
            .with(POOL_GET_METHODS, PoolEntry::StrSet(GET_METHODS))
            .with(POOL_CORPUS_PREFIX, PoolEntry::Str(CORPUS_PREFIX))
            .with(POOL_LEN_8, PoolEntry::Len(8))
            .with(POOL_RANGE_1_10, PoolEntry::Range(1, 10))
            .with(POOL_METHOD_EQ_GET, PoolEntry::Str(b"GET"))
            .with(POOL_SUFFIX_JSON, PoolEntry::Str(b".json"))
    }

    // -- clause fixtures -----------------------------------------------------

    fn host_in(operand: u16) -> Clause {
        Clause { field: FieldSel::URL_HOST, op: Op::HostInSet, operand }
    }

    fn scheme_eq_https() -> Clause {
        Clause { field: FieldSel::URL_SCHEME, op: Op::SchemeEq, operand: POOL_HTTPS }
    }

    fn method_in(operand: u16) -> Clause {
        Clause { field: FieldSel::METHOD, op: Op::InSet, operand }
    }

    fn path_prefix(operand: u16) -> Clause {
        Clause { field: FieldSel::PATH, op: Op::Prefix, operand }
    }

    // -- args fixtures --------------------------------------------------------

    fn args_url(scheme: Scheme, host: &'static [u8], port: u16, path: &'static [u8]) -> Args<'static> {
        Args::new().with_url(ArgVal::Url(UrlParts { scheme, host, port, path }))
    }

    /// An `Args` whose "url" slot is populated with a `BYTES` arg instead
    /// of a `URL` arg — models a tool call where the argument at the
    /// position a policy expects to be a URL is, in fact, some other
    /// typed arg (the type-confusion case `eval` must catch).
    fn args_bytes(b: &'static [u8]) -> Args<'static> {
        Args::new().with_url(ArgVal::Bytes(b))
    }

    fn args_method(m: &'static [u8]) -> Args<'static> {
        Args::new().with_method(ArgVal::Bytes(m))
    }

    fn args_path(p: &'static [u8]) -> Args<'static> {
        Args::new().with_path(ArgVal::Path(p))
    }

    // -- required tests (brief) ------------------------------------------------

    #[test]
    fn host_in_set_passes_exact() {
        let p = pool();
        let a = args_url(Scheme::Https, b"api.example.com", 443, b"/x");
        assert!(eval(&[host_in(POOL_API_HOSTS)], &a, &p).is_ok());
    }

    #[test]
    fn host_in_set_rejects_other() {
        let p = pool();
        let a = args_url(Scheme::Https, b"evil.tld", 443, b"/");
        assert_eq!(eval(&[host_in(POOL_API_HOSTS)], &a, &p).unwrap_err(), ReasonCode::DenyArg);
    }

    #[test]
    fn host_match_is_case_insensitive() {
        let p = pool();
        let a = args_url(Scheme::Https, b"API.EXAMPLE.COM", 443, b"/");
        assert!(eval(&[host_in(POOL_API_HOSTS)], &a, &p).is_ok());
    }

    #[test]
    fn trailing_dot_does_not_match() {
        let p = pool();
        let a = args_url(Scheme::Https, b"api.example.com.", 443, b"/");
        assert_eq!(eval(&[host_in(POOL_API_HOSTS)], &a, &p).unwrap_err(), ReasonCode::DenyArg);
    }

    #[test]
    fn scheme_eq_https_rejects_http() {
        let p = pool();
        let a = args_url(Scheme::Http, b"api.example.com", 80, b"/");
        assert_eq!(eval(&[scheme_eq_https()], &a, &p).unwrap_err(), ReasonCode::DenyArg);
    }

    #[test]
    fn wrong_arg_type_is_malformed() {
        let p = pool();
        let a = args_bytes(b"x");
        assert_eq!(eval(&[host_in(POOL_API_HOSTS)], &a, &p).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn absent_field_is_malformed() {
        let p = pool();
        let a = Args::new(); // no url slot at all
        assert_eq!(eval(&[host_in(POOL_API_HOSTS)], &a, &p).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn method_in_set_get_only() {
        let p = pool();
        let a = args_method(b"POST");
        assert_eq!(eval(&[method_in(POOL_GET_METHODS)], &a, &p).unwrap_err(), ReasonCode::DenyArg);
    }

    #[test]
    fn method_in_set_get_passes() {
        let p = pool();
        let a = args_method(b"GET");
        assert!(eval(&[method_in(POOL_GET_METHODS)], &a, &p).is_ok());
    }

    #[test]
    fn path_prefix_boundary() {
        let p = pool();
        assert!(eval(&[path_prefix(POOL_CORPUS_PREFIX)], &args_path(b"/corpus/a"), &p).is_ok());
        assert_eq!(
            eval(&[path_prefix(POOL_CORPUS_PREFIX)], &args_path(b"/corpusX"), &p).unwrap_err(),
            ReasonCode::DenyArg
        );
    }

    // -- SSRF-class: structured-field-only reads (Review Focus 4) -----------

    #[test]
    fn smuggled_credential_host_denies() {
        // Models a sender-supplied URL like
        // `https://user@evil.tld@api.example.com/...`. Whatever the
        // decoder places in the structured `host` field is exactly what
        // `eval` checks — no separate re-parse of any credential-looking
        // prefix happens here, so a smuggled allowlisted host in the
        // userinfo/path never becomes the matched host: only the actual
        // decoded `host` (here, the attacker's own host) is compared.
        let p = pool();
        let a = args_url(Scheme::Https, b"evil.tld", 443, b"/");
        assert_eq!(eval(&[host_in(POOL_API_HOSTS)], &a, &p).unwrap_err(), ReasonCode::DenyArg);
    }

    #[test]
    fn port_confusion_host_denies() {
        // Models a sender-supplied URL like `api.example.com:80@evil` —
        // if that whole string ends up in the structured `host` field
        // (rather than being split into host/port by the decoder), it is
        // still just bytes compared verbatim against the allowlist: it is
        // not equal to `api.example.com`, so it is denied. There is no
        // secondary parse step here that could be tricked into stripping
        // the `:80@evil` suffix and matching on the prefix alone.
        let p = pool();
        let a = args_url(Scheme::Https, b"api.example.com:80@evil", 443, b"/");
        assert_eq!(eval(&[host_in(POOL_API_HOSTS)], &a, &p).unwrap_err(), ReasonCode::DenyArg);
    }

    // -- remaining Op coverage (not required by the brief, added for
    //    completeness since the full Op enum must be implemented) --------

    #[test]
    fn eq_matches_exact_method() {
        let p = pool();
        let clause = Clause { field: FieldSel::METHOD, op: Op::Eq, operand: POOL_METHOD_EQ_GET };
        assert!(eval(&[clause], &args_method(b"GET"), &p).is_ok());
        assert_eq!(eval(&[clause], &args_method(b"get"), &p).unwrap_err(), ReasonCode::DenyArg);
    }

    #[test]
    fn suffix_matches_path_extension() {
        let p = pool();
        let clause = Clause { field: FieldSel::PATH, op: Op::Suffix, operand: POOL_SUFFIX_JSON };
        assert!(eval(&[clause], &args_path(b"/corpus/a.json"), &p).is_ok());
        assert_eq!(
            eval(&[clause], &args_path(b"/corpus/a.xml"), &p).unwrap_err(),
            ReasonCode::DenyArg
        );
    }

    #[test]
    fn range_bounds_int_field() {
        let p = pool();
        let clause = Clause { field: FieldSel::LEN, op: Op::Range, operand: POOL_RANGE_1_10 };
        assert!(eval(&[clause], &Args::new().with_len(ArgVal::Int(5)), &p).is_ok());
        assert_eq!(
            eval(&[clause], &Args::new().with_len(ArgVal::Int(11)), &p).unwrap_err(),
            ReasonCode::DenyArg
        );
    }

    #[test]
    fn len_le_bounds_byte_field() {
        let p = pool();
        let clause = Clause { field: FieldSel::PATH, op: Op::LenLe, operand: POOL_LEN_8 };
        assert!(eval(&[clause], &args_path(b"/short"), &p).is_ok());
        assert_eq!(
            eval(&[clause], &args_path(b"/way/too/long"), &p).unwrap_err(),
            ReasonCode::DenyArg
        );
    }

    // -- fail-closed / bounded-work guarantees -------------------------------

    #[test]
    fn too_many_clauses_denies_malformed() {
        let p = pool();
        let a = args_path(b"/x");
        let clause = path_prefix(POOL_CORPUS_PREFIX);
        let clauses = [clause; MAX_CLAUSES + 1];
        assert_eq!(eval(&clauses, &a, &p).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn exactly_max_clauses_is_allowed() {
        let p = pool();
        // MAX_CLAUSES copies of a clause that always passes for this arg.
        let a = args_path(b"/corpus/ok");
        let clause = path_prefix(POOL_CORPUS_PREFIX);
        let clauses = [clause; MAX_CLAUSES];
        assert!(eval(&clauses, &a, &p).is_ok());
    }

    #[test]
    fn pool_index_out_of_range_is_malformed() {
        let p = pool();
        let a = args_path(b"/corpus/a");
        let clause = Clause { field: FieldSel::PATH, op: Op::Prefix, operand: (MAX_POOL as u16) + 5 };
        assert_eq!(eval(&[clause], &a, &p).unwrap_err(), ReasonCode::DenyMalformed);
    }

    #[test]
    fn pool_entry_kind_mismatch_is_malformed() {
        let p = pool();
        // POOL_HTTPS holds a `Scheme`, not a `StrSet`; a clause that reads
        // it as a `StrSet` must fail closed, not read garbage.
        let a = args_method(b"GET");
        let clause = method_in(POOL_HTTPS);
        assert_eq!(eval(&[clause], &a, &p).unwrap_err(), ReasonCode::DenyMalformed);
    }
}
