//! Redoubt policy manifest compiler (Phase 3, Task W5).
//!
//! A manifest (Ch 8 grammar) is parsed and compiled ahead of time into the
//! exact fixed tables the Monitor already evaluates: `monitor::cap::Cap`,
//! `monitor::predicate::{Clause, ConstPool}` and `monitor::flow::FlowRule`,
//! lent out as the ONE `monitor::policy::Policy`.
//!
//! The grammar is deliberately TOTAL: there are no loops, recursion,
//! callbacks, variables or expressions. Every clause is `field op operand`
//! with a literal operand, so the compiler is a single linear pass that
//! always terminates, and anything outside the grammar is a `CompileError`
//! (never a silently widened capability).
//!
//! ```text
//! manifest    = "session" STRING "{" { capability } "}" ;
//! capability  = "capability" IDENT "=" captype "{" { clause } "}" ;
//! captype     = "net" | "file" | "secret" | "tool" ;
//! clause      = "tool" "=" INT
//!             | field predicate
//!             | "inject" "secret" INT
//!             | "result" "=" label
//!             | "deny" "secret" "to" "public"
//!             | "quota" ("calls"|"bytes"|"seconds") "=" INT ;
//! field       = "url.host" | "url.scheme" | "method" | "path" | "len" ;
//! predicate   = "in" "{" str {"," str} "}"   (url.host: HostInSet; method/path: InSet)
//!             | "==" operand                 (url.scheme: SchemeEq; method/path: Eq)
//!             | "prefix" str | "suffix" str  (method/path)
//!             | "range" INT INT              (len: Range, inclusive)
//!             | "<=" INT                     (len: LenLe)
//! label       = "PUBLIC" | "SECRET" | "TRUSTED" | "UNTRUSTED" ;
//! ```
#![forbid(unsafe_code)]

use std::fmt;

use abi::{Label, Scheme};
use monitor::cap::{Cap, CapType, CSPACE_LEN};
use monitor::flow::FlowRule;
use monitor::predicate::{Clause, ConstPool, FieldSel, Op, PoolEntry, MAX_CLAUSES, MAX_POOL};
use monitor::Policy;

/// Maximum length of any string operand.
pub const MAX_STR: usize = 255;
/// Maximum members of an `in { ... }` set.
pub const MAX_SET: usize = 16;
/// Initial epoch stamped on every compiled `Cap` (matches a fresh session).
pub const INITIAL_EPOCH: u16 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A manifest rejected by the compiler. `line` is 1-based.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for CompileError {}

fn err<T>(line: usize, msg: impl Into<String>) -> Result<T, CompileError> {
    Err(CompileError { line, msg: msg.into() })
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// An owned interned constant (the owning twin of `PoolEntry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnedPool {
    Str(Vec<u8>),
    StrSet(Vec<Vec<u8>>),
    Scheme(Scheme),
    Range(i64, i64),
    Len(u16),
}

/// Quota kinds carried for W4 (parsed and carried; not evaluated here).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QuotaKind {
    Calls,
    Bytes,
    Seconds,
}

/// One compiled capability: the `Cap` slot plus its name and quotas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledCap {
    pub name: String,
    pub cap: Cap,
    pub quotas: Vec<(QuotaKind, u64)>,
}

/// The compiled tables. Owns everything; `lend` produces the Monitor's view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub session: String,
    /// Capabilities in declaration order; `Cap.pred_ref`/`flow_ref` index
    /// `preds`/`flows`.
    pub caps: Vec<CompiledCap>,
    pub preds: Vec<Vec<Clause>>,
    pub flows: Vec<FlowRule>,
    /// Deduplicated constant pool; `Clause.operand` indexes this.
    pub pool: Vec<OwnedPool>,
}

/// Borrowed scaffolding needed to hand the Monitor a `Policy<'_>`.
pub struct Lent<'a> {
    owner: &'a CompiledPolicy,
    secrets: &'a [&'a [u8]],
    pred_slices: Vec<&'a [Clause]>,
    sets: Vec<Vec<&'a [u8]>>,
    caps: Vec<Cap>,
    quotas: monitor::cap::Quotas,
}

impl CompiledPolicy {
    /// Session quota budget: the most restrictive (minimum) value declared
    /// across caps for each kind; absent => unlimited. `seconds` is carried
    /// only (enforced off the decision path by the Warden/timer).
    fn session_quotas(&self) -> monitor::cap::Quotas {
        let mut q = monitor::cap::Quotas::UNLIMITED;
        for c in &self.caps {
            for (k, v) in &c.quotas {
                let v = u32::try_from(*v).unwrap_or(u32::MAX);
                let f = match k {
                    QuotaKind::Calls => &mut q.requests_left,
                    QuotaKind::Bytes => &mut q.egress_bytes_left,
                    QuotaKind::Seconds => &mut q.seconds,
                };
                *f = (*f).min(v);
            }
        }
        q
    }

    /// Prepare a lendable view. `secrets` is the secret table indexed by
    /// `inject secret N` (secret bytes are never part of a manifest).
    pub fn lend<'a>(&'a self, secrets: &'a [&'a [u8]]) -> Lent<'a> {
        Lent {
            owner: self,
            secrets,
            caps: self.caps.iter().map(|c| c.cap).collect(),
            quotas: self.session_quotas(),
            pred_slices: self.preds.iter().map(|v| v.as_slice()).collect(),
            sets: self
                .pool
                .iter()
                .map(|e| match e {
                    OwnedPool::StrSet(s) => s.iter().map(|b| b.as_slice()).collect(),
                    _ => Vec::new(),
                })
                .collect(),
        }
    }
}

impl<'a> Lent<'a> {
    /// The Monitor's `Policy` over the compiled tables.
    pub fn policy(&self) -> Policy<'_> {
        let mut pool = ConstPool::new();
        for (i, e) in self.owner.pool.iter().enumerate() {
            let entry = match e {
                OwnedPool::Str(s) => PoolEntry::Str(s),
                OwnedPool::StrSet(_) => PoolEntry::StrSet(&self.sets[i]),
                OwnedPool::Scheme(s) => PoolEntry::Scheme(*s),
                OwnedPool::Range(lo, hi) => PoolEntry::Range(*lo, *hi),
                OwnedPool::Len(n) => PoolEntry::Len(*n),
            };
            pool = pool.with(i as u16, entry);
        }
        Policy {
            preds: &self.pred_slices,
            flows: &self.owner.flows,
            secrets: self.secrets,
            pool,
            caps: &self.caps,
            quotas: self.quotas,
        }
    }
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Word(String),
    Str(String),
    LBrace,
    RBrace,
    Comma,
    Assign,
    EqEq,
    Le,
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Word(w) => format!("`{w}`"),
        Tok::Str(s) => format!("string \"{s}\""),
        Tok::LBrace => "`{`".into(),
        Tok::RBrace => "`}`".into(),
        Tok::Comma => "`,`".into(),
        Tok::Assign => "`=`".into(),
        Tok::EqEq => "`==`".into(),
        Tok::Le => "`<=`".into(),
    }
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | ':' | '-')
}

fn lex(src: &str) -> Result<Vec<(Tok, usize)>, CompileError> {
    let mut out = Vec::new();
    let mut line = 1usize;
    let mut it = src.chars().peekable();
    while let Some(&c) = it.peek() {
        match c {
            '\n' => {
                line += 1;
                it.next();
            }
            c if c.is_whitespace() => {
                it.next();
            }
            '#' => {
                while let Some(&c) = it.peek() {
                    if c == '\n' {
                        break;
                    }
                    it.next();
                }
            }
            '{' => {
                out.push((Tok::LBrace, line));
                it.next();
            }
            '}' => {
                out.push((Tok::RBrace, line));
                it.next();
            }
            ',' => {
                out.push((Tok::Comma, line));
                it.next();
            }
            '=' => {
                it.next();
                if it.peek() == Some(&'=') {
                    it.next();
                    out.push((Tok::EqEq, line));
                } else {
                    out.push((Tok::Assign, line));
                }
            }
            '<' => {
                it.next();
                if it.peek() == Some(&'=') {
                    it.next();
                    out.push((Tok::Le, line));
                } else {
                    return err(line, "unexpected `<` (only `<=` is allowed)");
                }
            }
            '"' => {
                it.next();
                let start = line;
                let mut s = String::new();
                loop {
                    match it.next() {
                        None | Some('\n') => return err(start, "unterminated string"),
                        Some('"') => break,
                        Some(ch) => s.push(ch),
                    }
                }
                out.push((Tok::Str(s), start));
            }
            c if is_word_char(c) => {
                let mut w = String::new();
                while let Some(&c) = it.peek() {
                    if is_word_char(c) {
                        w.push(c);
                        it.next();
                    } else {
                        break;
                    }
                }
                out.push((Tok::Word(w), line));
            }
            other => return err(line, format!("unexpected character `{other}`")),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parser / compiler
// ---------------------------------------------------------------------------

struct P {
    toks: Vec<(Tok, usize)>,
    pos: usize,
    last_line: usize,
}

impl P {
    fn line(&self) -> usize {
        self.toks.get(self.pos).map(|t| t.1).unwrap_or(self.last_line)
    }
    fn next(&mut self) -> Result<Tok, CompileError> {
        match self.toks.get(self.pos) {
            Some((t, _)) => {
                self.pos += 1;
                Ok(t.clone())
            }
            None => err(self.last_line, "unexpected end of manifest"),
        }
    }
    fn expect(&mut self, want: Tok) -> Result<(), CompileError> {
        let line = self.line();
        let got = self.next()?;
        if got == want {
            Ok(())
        } else {
            err(line, format!("expected {}, found {}", describe(&want), describe(&got)))
        }
    }
    fn word(&mut self) -> Result<String, CompileError> {
        let line = self.line();
        match self.next()? {
            Tok::Word(w) => Ok(w),
            t => err(line, format!("expected a word, found {}", describe(&t))),
        }
    }
    fn keyword(&mut self, kw: &str) -> Result<(), CompileError> {
        let line = self.line();
        let w = self.word()?;
        if w == kw {
            Ok(())
        } else {
            err(line, format!("expected `{kw}`, found `{w}`"))
        }
    }
    fn int(&mut self) -> Result<i64, CompileError> {
        let line = self.line();
        let w = self.word()?;
        parse_int(&w).ok_or(CompileError { line, msg: format!("expected an integer, found `{w}`") })
    }
    fn uint<T: TryFrom<i64>>(&mut self, what: &str) -> Result<T, CompileError> {
        let line = self.line();
        let n = self.int()?;
        T::try_from(n).map_err(|_| CompileError { line, msg: format!("{what} out of range: {n}") })
    }
    /// A string operand: a quoted string or a bare word.
    fn string(&mut self) -> Result<Vec<u8>, CompileError> {
        let line = self.line();
        let s = match self.next()? {
            Tok::Str(s) | Tok::Word(s) => s,
            t => return err(line, format!("expected a string operand, found {}", describe(&t))),
        };
        if s.is_empty() {
            return err(line, "empty string operand");
        }
        if s.len() > MAX_STR {
            return err(line, format!("string operand longer than {MAX_STR} bytes"));
        }
        Ok(s.into_bytes())
    }
    fn string_set(&mut self) -> Result<Vec<Vec<u8>>, CompileError> {
        let line = self.line();
        self.expect(Tok::LBrace)?;
        let mut set: Vec<Vec<u8>> = Vec::new();
        loop {
            let l = self.line();
            let s = self.string()?;
            if set.contains(&s) {
                return err(l, "duplicate member in set");
            }
            set.push(s);
            if set.len() > MAX_SET {
                return err(line, format!("set has more than {MAX_SET} members"));
            }
            match self.next()? {
                Tok::Comma => continue,
                Tok::RBrace => break,
                t => return err(self.line(), format!("expected `,` or `}}`, found {}", describe(&t))),
            }
        }
        Ok(set)
    }
}

fn parse_int(w: &str) -> Option<i64> {
    let (neg, body) = match w.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, w),
    };
    let v = if let Some(h) = body.strip_prefix("0x") {
        i64::from_str_radix(h, 16).ok()?
    } else {
        if body.is_empty() || !body.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        body.parse::<i64>().ok()?
    };
    Some(if neg { -v } else { v })
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum CT {
    Net,
    File,
    Secret,
    Tool,
}

impl CT {
    fn cap_type(self) -> CapType {
        match self {
            CT::Net => CapType::Net,
            CT::File => CapType::File,
            CT::Secret => CapType::Secret,
            CT::Tool => CapType::Tool,
        }
    }
    /// Fields a capability type may constrain (captype/field mismatch is
    /// rejected rather than silently compiled).
    fn allows(self, f: FieldSel) -> bool {
        match self {
            CT::Net => matches!(f, FieldSel::URL_HOST | FieldSel::URL_SCHEME | FieldSel::METHOD | FieldSel::LEN),
            CT::File => matches!(f, FieldSel::PATH | FieldSel::LEN),
            CT::Secret => matches!(f, FieldSel::LEN),
            CT::Tool => matches!(f, FieldSel::METHOD | FieldSel::PATH | FieldSel::LEN),
        }
    }
}

#[derive(Default)]
struct Interner {
    pool: Vec<OwnedPool>,
}

impl Interner {
    fn intern(&mut self, e: OwnedPool, line: usize) -> Result<u16, CompileError> {
        if let Some(i) = self.pool.iter().position(|x| *x == e) {
            return Ok(i as u16);
        }
        if self.pool.len() >= MAX_POOL {
            return err(line, format!("constant pool full (max {MAX_POOL} entries)"));
        }
        self.pool.push(e);
        Ok((self.pool.len() - 1) as u16)
    }
}

fn parse_label(line: usize, w: &str) -> Result<Label, CompileError> {
    match w {
        "PUBLIC" => Ok(Label::PUBLIC),
        "SECRET" => Ok(Label::SECRET),
        "TRUSTED" => Ok(Label::TRUSTED),
        "UNTRUSTED" => Ok(Label::UNTRUSTED),
        _ => err(line, format!("unknown label `{w}`")),
    }
}

/// Parse and compile a manifest. Total: one linear pass, no evaluation.
pub fn compile(src: &str) -> Result<CompiledPolicy, CompileError> {
    let toks = lex(src)?;
    let last_line = toks.last().map(|t| t.1).unwrap_or(1);
    let mut p = P { toks, pos: 0, last_line };

    p.keyword("session")?;
    let line = p.line();
    let session = match p.next()? {
        Tok::Str(s) => s,
        t => return err(line, format!("expected session name string, found {}", describe(&t))),
    };
    p.expect(Tok::LBrace)?;

    let mut interner = Interner::default();
    let mut out = CompiledPolicy {
        session,
        caps: Vec::new(),
        preds: Vec::new(),
        flows: Vec::new(),
        pool: Vec::new(),
    };

    loop {
        let line = p.line();
        match p.next()? {
            Tok::RBrace => break,
            Tok::Word(w) if w == "capability" => {}
            t => return err(line, format!("expected `capability` or `}}`, found {}", describe(&t))),
        }
        if out.caps.len() >= CSPACE_LEN {
            return err(line, format!("more than {CSPACE_LEN} capabilities"));
        }
        let name = p.word()?;
        if out.caps.iter().any(|c| c.name == name) {
            return err(line, format!("duplicate capability `{name}`"));
        }
        p.expect(Tok::Assign)?;
        let cl = p.line();
        let ct = match p.word()?.as_str() {
            "net" => CT::Net,
            "file" => CT::File,
            "secret" => CT::Secret,
            "tool" => CT::Tool,
            other => return err(cl, format!("unknown capability type `{other}`")),
        };
        p.expect(Tok::LBrace)?;

        let mut tool: Option<u16> = None;
        let mut inject: Option<u16> = None;
        let mut result: Option<Label> = None;
        let mut deny = false;
        let mut quotas: Vec<(QuotaKind, u64)> = Vec::new();
        let mut clauses: Vec<Clause> = Vec::new();
        let mut has_host = false;
        let mut has_path = false;

        loop {
            let line = p.line();
            let w = match p.next()? {
                Tok::RBrace => break,
                Tok::Word(w) => w,
                t => return err(line, format!("expected a clause, found {}", describe(&t))),
            };
            match w.as_str() {
                "tool" => {
                    p.expect(Tok::Assign)?;
                    let v: u16 = p.uint("tool id")?;
                    if tool.replace(v).is_some() {
                        return err(line, "duplicate `tool` clause");
                    }
                }
                "inject" => {
                    p.keyword("secret")?;
                    let v: u16 = p.uint("secret ref")?;
                    if inject.replace(v).is_some() {
                        return err(line, "duplicate `inject` clause");
                    }
                }
                "result" => {
                    p.expect(Tok::Assign)?;
                    let ll = p.line();
                    let lw = p.word()?;
                    let l = parse_label(ll, &lw)?;
                    if result.replace(l).is_some() {
                        return err(line, "duplicate `result` clause");
                    }
                }
                "deny" => {
                    p.keyword("secret")?;
                    p.keyword("to")?;
                    p.keyword("public")?;
                    if deny {
                        return err(line, "duplicate `deny secret to public` clause");
                    }
                    deny = true;
                }
                "quota" => {
                    let kl = p.line();
                    let kind = match p.word()?.as_str() {
                        "calls" => QuotaKind::Calls,
                        "bytes" => QuotaKind::Bytes,
                        "seconds" => QuotaKind::Seconds,
                        other => return err(kl, format!("unknown quota kind `{other}`")),
                    };
                    p.expect(Tok::Assign)?;
                    let v: u64 = p.uint("quota")?;
                    if quotas.iter().any(|(k, _)| *k == kind) {
                        return err(line, "duplicate quota kind");
                    }
                    quotas.push((kind, v));
                }
                "url.host" | "url.scheme" | "method" | "path" | "len" => {
                    let field = match w.as_str() {
                        "url.host" => FieldSel::URL_HOST,
                        "url.scheme" => FieldSel::URL_SCHEME,
                        "method" => FieldSel::METHOD,
                        "path" => FieldSel::PATH,
                        _ => FieldSel::LEN,
                    };
                    if !ct.allows(field) {
                        return err(line, format!("field `{w}` is not allowed in this capability type"));
                    }
                    let ol = p.line();
                    let optok = p.next()?;
                    let (op, entry) = match (field, optok) {
                        (FieldSel::URL_HOST, Tok::Word(k)) if k == "in" => {
                            let set = p.string_set()?;
                            for h in &set {
                                if !h.iter().all(|b| {
                                    b.is_ascii_lowercase()
                                        || b.is_ascii_digit()
                                        || matches!(b, b'.' | b'-')
                                }) {
                                    return err(
                                        ol,
                                        "host must be lowercase ASCII letters, digits, `.` or `-`",
                                    );
                                }
                            }
                            has_host = true;
                            (Op::HostInSet, OwnedPool::StrSet(set))
                        }
                        (FieldSel::URL_SCHEME, Tok::EqEq) => {
                            let sl = p.line();
                            let sc = match p.word()?.as_str() {
                                "http" => Scheme::Http,
                                "https" => Scheme::Https,
                                other => return err(sl, format!("unknown scheme `{other}`")),
                            };
                            (Op::SchemeEq, OwnedPool::Scheme(sc))
                        }
                        (FieldSel::METHOD | FieldSel::PATH, Tok::Word(k)) if k == "in" => {
                            (Op::InSet, OwnedPool::StrSet(p.string_set()?))
                        }
                        (FieldSel::METHOD | FieldSel::PATH, Tok::EqEq) => {
                            (Op::Eq, OwnedPool::Str(p.string()?))
                        }
                        (FieldSel::METHOD | FieldSel::PATH, Tok::Word(k)) if k == "prefix" => {
                            (Op::Prefix, OwnedPool::Str(p.string()?))
                        }
                        (FieldSel::METHOD | FieldSel::PATH, Tok::Word(k)) if k == "suffix" => {
                            (Op::Suffix, OwnedPool::Str(p.string()?))
                        }
                        (FieldSel::LEN, Tok::Le) => (Op::LenLe, OwnedPool::Len(p.uint("length limit")?)),
                        (FieldSel::LEN, Tok::Word(k)) if k == "range" => {
                            let lo = p.int()?;
                            let hi = p.int()?;
                            if lo > hi {
                                return err(ol, "range lower bound exceeds upper bound");
                            }
                            (Op::Range, OwnedPool::Range(lo, hi))
                        }
                        (_, t) => {
                            return err(
                                ol,
                                format!("operator {} is not valid for field `{w}`", describe(&t)),
                            )
                        }
                    };
                    let operand = interner.intern(entry, line)?;
                    if clauses.len() >= MAX_CLAUSES {
                        return err(line, format!("more than {MAX_CLAUSES} clauses in one capability"));
                    }
                    if field == FieldSel::PATH {
                        has_path = true;
                    }
                    clauses.push(Clause { field, op, operand });
                }
                other => return err(line, format!("unknown clause `{other}`")),
            }
        }

        let tool_id = tool.ok_or(CompileError { line, msg: format!("capability `{name}` has no `tool =`") })?;
        let result_label = result
            .ok_or(CompileError { line, msg: format!("capability `{name}` has no `result =`") })?;
        if ct == CT::Net && !has_host {
            return err(
                line,
                format!("net capability `{name}` must constrain `url.host` (refusing an open net cap)"),
            );
        }

        // An empty arg-clause list is legitimate for `tool` (binds a tool_id)
        // and `secret` (grants a secret_ref) caps, but `file` must constrain
        // `path`: otherwise it would be an unrestricted file capability.
        if ct == CT::File && !has_path {
            return err(
                line,
                format!("file capability `{name}` must constrain `path` (refusing an unrestricted file cap)"),
            );
        }
        // A secret-bearing cap must state its flow disposition; omitting
        // `deny secret to public` must never silently allow a secret to a
        // public sink.
        if inject.is_some() && !deny {
            return err(
                line,
                format!("capability `{name}` injects a secret and must state `deny secret to public`"),
            );
        }

        let rule = FlowRule { inject, deny_secret_to_public: deny, result_label };
        let flow_ref = match out.flows.iter().position(|f| *f == rule) {
            Some(i) => i,
            None => {
                out.flows.push(rule);
                out.flows.len() - 1
            }
        };
        out.preds.push(clauses);
        let pred_ref = (out.preds.len() - 1) as u16;
        out.caps.push(CompiledCap {
            name,
            cap: Cap {
                ctype: ct.cap_type() as u8,
                rights: 0,
                tool_id,
                pred_ref,
                flow_ref: flow_ref as u16,
                secret_ref: inject.unwrap_or(0),
                aux: 0,
                epoch: INITIAL_EPOCH,
                _pad: 0,
            },
            quotas,
        });
    }

    if let Some((_, line)) = p.toks.get(p.pos) {
        return err(*line, "trailing tokens after manifest");
    }
    out.pool = interner.pool;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{ArgVal, ReasonCode, UrlParts};
    use monitor::predicate::{eval, Args};

    // The Phase-1 hand fixture (identical to the `policy_fixture` in
    // monitor's `mediate` tests and `monitor-bin/src/fixtures.rs`).
    const TOOL_ID: u16 = 0x1000;
    const SECRET: &[u8] = b"API_KEY_SECRET_VALUE";
    static API_HOSTS: [&[u8]; 1] = [b"api.example.com"];
    static CLAUSES_HOST_ONLY: [Clause; 1] =
        [Clause { field: FieldSel::URL_HOST, op: Op::HostInSet, operand: 0 }];
    static PRED_SETS: [&[Clause]; 1] = [&CLAUSES_HOST_ONLY];
    static FLOWS: [FlowRule; 1] = [FlowRule {
        inject: Some(0),
        deny_secret_to_public: true,
        result_label: Label::UNTRUSTED,
    }];
    static SECRETS: [&[u8]; 1] = [SECRET];

    fn fixture_cap() -> Cap {
        Cap {
            ctype: CapType::Net as u8,
            rights: 0,
            tool_id: TOOL_ID,
            pred_ref: 0,
            flow_ref: 0,
            secret_ref: 0,
            aux: 0,
            epoch: 1,
            _pad: 0,
        }
    }

    const HOST_ONLY: &str = r#"
        session "demo" {
          capability http = net {
            tool = 0x1000
            url.host in { api.example.com }
            inject secret 0
            deny secret to public
            result = UNTRUSTED
          }
        }
    "#;

    /// GOLDEN: the manifest reproduces the hand-built Phase-1 fixture exactly.
    #[test]
    fn golden_reproduces_phase1_fixture() {
        let c = compile(HOST_ONLY).unwrap();
        assert_eq!(c.caps.len(), 1);
        assert_eq!(c.caps[0].cap, fixture_cap());
        assert_eq!(c.preds.len(), 1);
        assert_eq!(c.preds[0].as_slice(), &CLAUSES_HOST_ONLY[..]);
        assert_eq!(c.flows.as_slice(), &FLOWS[..]);

        let lent = c.lend(&SECRETS);
        let got = lent.policy();
        let want_pool = ConstPool::new().with(0, PoolEntry::StrSet(&API_HOSTS));
        assert_eq!(got.pool, want_pool);
        assert_eq!(got.preds.len(), PRED_SETS.len());
        assert_eq!(got.preds[0], PRED_SETS[0]);
        assert_eq!(got.flows, &FLOWS[..]);
        assert_eq!(got.secrets, &SECRETS[..]);
    }

    const CH8: &str = r#"
        # Ch 8 worked example
        session "agent-7" {
          capability http = net {
            tool = 0x1000
            url.scheme == https
            url.host in { api.example.com }
            method in { GET }
            inject secret 0
            deny secret to public
            result = UNTRUSTED
            quota calls = 100
          }
        }
    "#;

    #[test]
    fn ch8_example_compiles_and_interns() {
        let c = compile(CH8).unwrap();
        assert_eq!(c.session, "agent-7");
        assert_eq!(c.caps[0].cap, fixture_cap());
        assert_eq!(c.caps[0].quotas, vec![(QuotaKind::Calls, 100)]);
        assert_eq!(
            c.preds[0],
            vec![
                Clause { field: FieldSel::URL_SCHEME, op: Op::SchemeEq, operand: 0 },
                Clause { field: FieldSel::URL_HOST, op: Op::HostInSet, operand: 1 },
                Clause { field: FieldSel::METHOD, op: Op::InSet, operand: 2 },
            ]
        );
        assert_eq!(
            c.pool,
            vec![
                OwnedPool::Scheme(Scheme::Https),
                OwnedPool::StrSet(vec![b"api.example.com".to_vec()]),
                OwnedPool::StrSet(vec![b"GET".to_vec()]),
            ]
        );
        assert_eq!(c.flows.as_slice(), &FLOWS[..]);

        // The compiled tables drive the Monitor's own evaluator.
        let lent = c.lend(&SECRETS);
        let pol = lent.policy();
        let ok = Args::new()
            .with_url(ArgVal::Url(UrlParts {
                scheme: Scheme::Https,
                host: b"api.example.com",
                port: 443,
                path: b"/x",
            }))
            .with_method(ArgVal::Bytes(b"GET"));
        assert_eq!(eval(pol.preds[0], &ok, &pol.pool), Ok(()));
        let bad = Args::new()
            .with_url(ArgVal::Url(UrlParts {
                scheme: Scheme::Http,
                host: b"api.example.com",
                port: 80,
                path: b"/x",
            }))
            .with_method(ArgVal::Bytes(b"GET"));
        assert_eq!(eval(pol.preds[0], &bad, &pol.pool), Err(ReasonCode::DenyArg));
    }

    #[test]
    fn constants_are_deduplicated_across_caps() {
        let src = r#"
            session "s" {
              capability a = net { tool = 1 url.host in { api.example.com } result = UNTRUSTED }
              capability b = net { tool = 2 url.host in { api.example.com } result = UNTRUSTED
                                   url.scheme == https }
            }
        "#;
        let c = compile(src).unwrap();
        assert_eq!(c.pool.len(), 2);
        assert_eq!(c.preds[0][0].operand, c.preds[1][0].operand);
        // identical flow rules share one entry
        assert_eq!(c.flows.len(), 1);
        assert_eq!(c.caps[1].cap.pred_ref, 1);
    }

    #[test]
    fn all_eight_ops_map() {
        let src = r#"
            session "s" {
              capability n = net { tool = 1 url.host in { a.b } url.scheme == http
                                   method == GET method in { GET, PUT } len <= 8 len range -1 10
                                   result = PUBLIC }
              capability f = file { tool = 2 path prefix "/corpus/" path suffix ".json"
                                    result = TRUSTED }
            }
        "#;
        let c = compile(src).unwrap();
        let ops: Vec<Op> = c.preds.iter().flatten().map(|c| c.op).collect();
        assert_eq!(
            ops,
            vec![
                Op::HostInSet, Op::SchemeEq, Op::Eq, Op::InSet, Op::LenLe, Op::Range,
                Op::Prefix, Op::Suffix
            ]
        );
        // Eq "GET" and the set {GET,PUT} are distinct pool entries.
        assert!(c.pool.contains(&OwnedPool::Str(b"GET".to_vec())));
        assert!(c.pool.contains(&OwnedPool::Range(-1, 10)));
    }

    fn rejected(src: &str) -> CompileError {
        compile(src).expect_err(src)
    }

    fn wrap(body: &str) -> String {
        format!("session \"s\" {{ capability c = net {{ tool = 1 url.host in {{ a.b }} result = PUBLIC {body} }} }}")
    }

    #[test]
    fn rejects_non_total_and_illegal_manifests() {
        // loop / unknown tokens
        rejected(&wrap("while true { }"));
        rejected(&wrap("for x in { a } { }"));
        rejected(&wrap("let x = 1"));
        // unknown op / bad syntax
        rejected(&wrap("url.host matches { a.b }"));
        rejected(&wrap("len < 3"));
        rejected(&wrap("len <= foo"));
        rejected(&wrap("method in { GET"));
        rejected(&wrap("method in { }"));
        rejected(&wrap("method in { GET, GET }"));
        // captype / field mismatch
        rejected("session \"s\" { capability c = file { tool = 1 url.host in { a.b } result = PUBLIC } }");
        rejected("session \"s\" { capability c = net { tool = 1 path prefix x url.host in { a } result = PUBLIC } }");
        // field / op mismatch
        rejected(&wrap("url.host == a.b"));
        rejected(&wrap("url.scheme in { https }"));
        rejected(&wrap("len prefix x"));
        // bad operands
        rejected(&wrap("url.scheme == ftp"));
        rejected(&wrap("url.host in { API.Example.com }"));
        rejected(&wrap("len <= 70000"));
        rejected(&wrap("len range 5 1"));
        // unbounded: oversized string / set
        let long = "x".repeat(MAX_STR + 1);
        rejected(&wrap(&format!("method == \"{long}\"")));
        let big: Vec<String> = (0..=MAX_SET).map(|i| format!("m{i}")).collect();
        rejected(&wrap(&format!("method in {{ {} }}", big.join(","))));
        // duplicates / unknown labels / unknown quota
        rejected(&wrap("result = TRUSTED"));
        rejected(&wrap("tool = 2"));
        rejected(&wrap("result = TOP_SECRET").replace("result = PUBLIC", ""));
        rejected(&wrap("quota flops = 3"));
        // structure
        rejected("");
        rejected("session \"s\" {");
        rejected("session \"s\" { } trailing");
        rejected("session \"s\" { capability c = bogus { } }");
        rejected("session \"s\" { capability c = net { tool = 1 } }"); // no result, no host
        rejected("session \"s\" { capability c = net { tool = 1 result = PUBLIC } }"); // open net cap
        rejected("session \"s\" { capability c = tool { result = PUBLIC } }"); // no tool
        rejected("session \"s\" { capability c = tool { tool = 1 } }"); // no result
        rejected("session \"s\" { capability c = tool { tool = 1 result = PUBLIC } capability c = tool { tool = 2 result = PUBLIC } }");
        rejected("session \"s\" { capability c = tool { tool = 99999 result = PUBLIC } }");
        rejected("session \"s\" { capability c = tool { tool = 1 result = PUBLIC ; } }");
        rejected("session \"s\" { capability c = tool { tool = 1 result = PUBLIC \"unterminated } }");
    }

    #[test]
    fn inject_without_deny_is_rejected() {
        let src = "session \"s\" { capability c = net { tool = 1 url.host in { a.b } inject secret 0 result = PUBLIC } }";
        rejected(src);
        let ok = src.replace("inject secret 0", "inject secret 0 deny secret to public");
        assert!(compile(&ok).unwrap().flows.iter().all(|f| f.deny_secret_to_public));
    }

    #[test]
    fn file_cap_needs_path_but_tool_and_secret_do_not() {
        rejected("session \"s\" { capability f = file { tool = 1 result = PUBLIC } }");
        rejected("session \"s\" { capability f = file { tool = 1 len <= 8 result = PUBLIC } }");
        assert!(compile("session \"s\" { capability f = file { tool = 1 path prefix \"/c/\" result = PUBLIC } }").is_ok());
        assert!(compile("session \"s\" { capability t = tool { tool = 1 result = PUBLIC } }").is_ok());
        assert!(compile("session \"s\" { capability k = secret { tool = 2 inject secret 0 deny secret to public result = PUBLIC } }").is_ok());
    }

    #[test]
    fn rejection_carries_line_number() {
        let e = rejected("session \"s\" {\n capability c = net {\n tool = 1\n bogus\n }\n}");
        assert_eq!(e.line, 4);
    }

    #[test]
    fn too_many_caps_rejected() {
        let mut s = String::from("session \"s\" {");
        for i in 0..=CSPACE_LEN {
            s.push_str(&format!(" capability c{i} = tool {{ tool = {i} result = PUBLIC }}"));
        }
        s.push('}');
        rejected(&s);
    }
}
