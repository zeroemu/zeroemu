//! Android's SELinux policy, read from the CIL it ships (the files init's
//! first stage would hand to secilc): classes and permissions with their
//! kernel numbering, booleans, initial SIDs, policy capabilities, types and
//! attributes, roles, users, and type transitions. Access rules (allow,
//! neverallow, …) are skipped without being parsed: zeroemu allows everything.

use std::collections::HashMap;

pub struct Class {
    pub name: String,
    /// Permission names; bit = position (the common's permissions come first).
    pub perms: Vec<String>,
}

/// A set of types, as a bitmap over type ids.
#[derive(Clone, Default)]
struct Set(Vec<u64>);

impl Set {
    fn with(n: usize) -> Set {
        Set(vec![0; n.div_ceil(64)])
    }
    fn insert(&mut self, i: u32) {
        self.0[i as usize / 64] |= 1 << (i % 64);
    }
    fn has(&self, i: u32) -> bool {
        self.0.get(i as usize / 64).is_some_and(|w| w >> (i % 64) & 1 != 0)
    }
    fn or(&mut self, o: &Set) {
        if self.0.len() < o.0.len() {
            self.0.resize(o.0.len(), 0);
        }
        self.0.iter_mut().zip(&o.0).for_each(|(a, b)| *a |= b);
    }
}

/// A rule's source or target: one type or an attribute's members.
enum Who {
    Type(u32),
    Attr(usize),
}

struct Transition {
    src: Who,
    tgt: Who,
    class: u16,
    name: Option<String>,
    new: u32,
}

#[derive(Default)]
pub struct Policy {
    /// In kernel order: a class's index is its position + 1.
    pub classes: Vec<Class>,
    class_ix: HashMap<String, u16>,
    /// (name, default value), sorted by name.
    pub bools: Vec<(String, bool)>,
    /// Initial SIDs in sidorder: (name, context).
    pub sids: Vec<(String, String)>,
    pub caps: Vec<String>,
    /// Type and alias names -> type id.
    types: HashMap<String, u32>,
    type_names: Vec<String>,
    attr_sets: Vec<Set>,
    /// role -> the types it may hold (object_r holds every type).
    roles: HashMap<String, Set>,
    users: HashMap<String, Vec<String>>,
    transitions: Vec<Transition>,
}

/// An s-expression borrowed from the policy text.
enum Sx<'a> {
    Atom(&'a str),
    Str(&'a str),
    List(Vec<Sx<'a>>),
}

impl<'a> Sx<'a> {
    fn atom(&self) -> Option<&'a str> {
        match self {
            Sx::Atom(a) => Some(a),
            _ => None,
        }
    }
    fn list(&self) -> &[Sx<'a>] {
        match self {
            Sx::List(l) => l,
            _ => &[],
        }
    }
    /// The atoms of a list (permission lists, orders).
    fn atoms(&self) -> Vec<&'a str> {
        self.list().iter().filter_map(Sx::atom).collect()
    }
}

/// Statements the model needs; everything else is skipped by paren matching.
/// (Attributes need no declaration here: a name with members is one.)
fn wanted(keyword: &str) -> bool {
    matches!(
        keyword,
        "class" | "common" | "classcommon" | "classorder" | "boolean" | "sid" | "sidcontext" | "sidorder" | "policycap" | "type"
            | "typealiasactual" | "typeattributeset" | "typetransition" | "role" | "roletype" | "user" | "userrole"
    )
}

/// The keyword and first argument of a statement's text.
fn head(stmt: &str) -> (&str, &str) {
    let mut w = stmt[1..].split([' ', '\t', '\n', '(', ')']).filter(|w| !w.is_empty());
    (w.next().unwrap_or(""), w.next().unwrap_or(""))
}

/// The texts of a CIL file's top-level statements that the model uses; the
/// rest (mostly allow rules) are only paren-matched.
fn statements<'a>(text: &'a str, out: &mut Vec<&'a str>) {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' => {
                let kw = b[i + 1..].iter().take_while(|c| c.is_ascii_lowercase() || **c == b'_').count();
                let end = skip(b, i);
                if wanted(&text[i + 1..i + 1 + kw]) {
                    out.push(&text[i..end]);
                }
                i = end;
            }
            b';' => i = text[i..].find('\n').map_or(b.len(), |p| i + p),
            _ => i += 1,
        }
    }
}

/// Bytes the paren matcher stops at.
const SPECIAL: [bool; 256] = {
    let mut t = [false; 256];
    t[b'(' as usize] = true;
    t[b')' as usize] = true;
    t[b'"' as usize] = true;
    t[b';' as usize] = true;
    t
};

/// The index just past the expression starting with '(' at `i`.
fn skip(b: &[u8], mut i: usize) -> usize {
    let mut depth = 0;
    while i < b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            b'"' => i += b[i + 1..].iter().position(|&c| c == b'"').map_or(b.len(), |p| p + 1),
            b';' => i += b[i..].iter().position(|&c| c == b'\n').unwrap_or(b.len() - i),
            _ => {}
        }
        i += 1;
        while i < b.len() && !SPECIAL[b[i] as usize] {
            i += 1;
        }
    }
    b.len()
}

/// Parses one expression at `i` (just past leading whitespace); returns it
/// and the index after it.
fn parse(text: &str, mut i: usize) -> (Sx<'_>, usize) {
    let b = text.as_bytes();
    match b[i] {
        b'(' => {
            let mut items = Vec::new();
            i += 1;
            loop {
                while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b';') {
                    if b[i] == b';' {
                        i += b[i..].iter().position(|&c| c == b'\n').unwrap_or(b.len() - i);
                    } else {
                        i += 1;
                    }
                }
                if i >= b.len() {
                    return (Sx::List(items), i);
                }
                if b[i] == b')' {
                    return (Sx::List(items), i + 1);
                }
                let (sx, next) = parse(text, i);
                items.push(sx);
                i = next;
            }
        }
        b'"' => {
            let end = b[i + 1..].iter().position(|&c| c == b'"').map_or(b.len(), |p| i + 1 + p);
            (Sx::Str(&text[i + 1..end]), (end + 1).min(b.len()))
        }
        _ => {
            let end = b[i..].iter().position(|c| c.is_ascii_whitespace() || matches!(c, b'(' | b')' | b'"' | b';')).map_or(b.len(), |p| i + p);
            (Sx::Atom(&text[i..end]), end.max(i + 1))
        }
    }
}

/// A CIL level `(s0)`, `(s0 (c0 c1))` or `(s0 (range c0 c1023))` as text.
fn level(sx: &Sx) -> String {
    let l = sx.list();
    let mut s = l.first().and_then(Sx::atom).unwrap_or("s0").to_string();
    if let Some(cats) = l.get(1) {
        let c = cats.list();
        let parts: Vec<String> = if c.first().and_then(Sx::atom) == Some("range") {
            vec![format!("{}.{}", c.get(1).and_then(Sx::atom).unwrap_or(""), c.get(2).and_then(Sx::atom).unwrap_or(""))]
        } else {
            c.iter().filter_map(Sx::atom).map(String::from).collect()
        };
        if !parts.is_empty() {
            s += &format!(":{}", parts.join(","));
        }
    }
    s
}

/// A CIL context `(user role type ((low) (high)))` as "user:role:type:level".
fn context(sx: &Sx) -> Option<String> {
    let l = sx.list();
    let (u, r, t) = (l.first()?.atom()?, l.get(1)?.atom()?, l.get(2)?.atom()?);
    let range = l.get(3).map(Sx::list).unwrap_or(&[]);
    let lo = range.first().map(level).unwrap_or_else(|| "s0".into());
    let hi = range.get(1).map(level).unwrap_or_else(|| lo.clone());
    Some(if lo == hi { format!("{u}:{r}:{t}:{lo}") } else { format!("{u}:{r}:{t}:{lo}-{hi}") })
}

/// Merges CIL order statements (classorder, sidorder) into one order;
/// members of "unordered" lists that no ordered list places go last.
fn merge_order<'a>(orders: &[Vec<&'a str>]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for unordered in [false, true] {
        for o in orders.iter().filter(|o| (o.first() == Some(&"unordered")) == unordered) {
            for &n in o.iter().filter(|&&n| n != "unordered") {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
    }
    out
}

impl Policy {
    /// Builds the model from CIL files, in secilc's order.
    pub fn parse(texts: &[&str]) -> Policy {
        let mut raw = Vec::new();
        for t in texts {
            statements(t, &mut raw);
        }
        // Attribute members are only evaluated for the attributes rules use.
        let mut attr_raw: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut stmts: Vec<Vec<Sx>> = Vec::new();
        for s in raw {
            match head(s) {
                ("typeattributeset", name) => attr_raw.entry(name).or_default().push(s),
                ("roletype", "object_r") => {} // object_r holds every type anyway
                _ => {
                    if let (Sx::List(l), _) = parse(s, 0) {
                        stmts.push(l);
                    }
                }
            }
        }
        let mut p = Policy::default();
        let (mut commons, mut class_perms, mut class_common) = (HashMap::new(), HashMap::new(), HashMap::new());
        let (mut class_orders, mut sid_orders, mut sid_ctx) = (Vec::new(), Vec::new(), HashMap::new());
        let mut aliases = Vec::new();
        let (mut roletypes, mut transitions) = (Vec::new(), Vec::new());
        fn atom<'a>(s: &[Sx<'a>], i: usize) -> &'a str {
            s.get(i).and_then(Sx::atom).unwrap_or("")
        }
        for s in &stmts {
            match atom(s, 0) {
                "common" => {
                    commons.insert(atom(s, 1), s.get(2).map(Sx::atoms).unwrap_or_default());
                }
                "class" => {
                    class_perms.insert(atom(s, 1), s.get(2).map(Sx::atoms).unwrap_or_default());
                }
                "classcommon" => {
                    class_common.insert(atom(s, 1), atom(s, 2));
                }
                "classorder" => class_orders.push(s.get(1).map(Sx::atoms).unwrap_or_default()),
                "sidorder" => sid_orders.push(s.get(1).map(Sx::atoms).unwrap_or_default()),
                "sidcontext" => {
                    sid_ctx.insert(atom(s, 1), s.get(2).and_then(context));
                }
                "sid" => sid_orders.push(vec!["unordered", atom(s, 1)]),
                "boolean" => p.bools.push((atom(s, 1).to_string(), atom(s, 2) == "true")),
                "policycap" => p.caps.push(atom(s, 1).to_string()),
                "type" => {
                    let n = p.type_names.len() as u32;
                    if !p.types.contains_key(atom(s, 1)) {
                        p.types.insert(atom(s, 1).to_string(), n);
                        p.type_names.push(atom(s, 1).to_string());
                    }
                }
                "typealiasactual" => aliases.push((atom(s, 1), atom(s, 2))),
                "typetransition" => transitions.push(s),
                "role" => {
                    p.roles.entry(atom(s, 1).to_string()).or_default();
                }
                "roletype" => roletypes.push((atom(s, 1), atom(s, 2))),
                "user" => {
                    p.users.entry(atom(s, 1).to_string()).or_default();
                }
                "userrole" => p.users.entry(atom(s, 1).to_string()).or_default().push(atom(s, 2).to_string()),
                _ => {}
            }
        }
        for (alias, actual) in aliases {
            if let Some(&id) = p.types.get(actual) {
                p.types.insert(alias.to_string(), id);
            }
        }
        // Classes in classorder: a class's own permissions follow its common's.
        let mut declared: Vec<&str> = class_perms.keys().copied().collect();
        declared.sort();
        class_orders.push([&["unordered"][..], &declared].concat());
        for name in merge_order(&class_orders) {
            let Some(own) = class_perms.get(name) else { continue };
            let mut perms: Vec<String> = class_common.get(name).and_then(|c| commons.get(c)).map(|c: &Vec<&str>| c.iter().map(|s| s.to_string()).collect()).unwrap_or_default();
            perms.extend(own.iter().map(|s| s.to_string()));
            p.class_ix.insert(name.to_string(), p.classes.len() as u16 + 1);
            p.classes.push(Class { name: name.to_string(), perms });
        }
        for name in merge_order(&sid_orders) {
            if let Some(Some(ctx)) = sid_ctx.get(name) {
                p.sids.push((name.to_string(), ctx.clone()));
            }
        }
        p.bools.sort();
        p.bools.dedup_by(|a, b| a.0 == b.0);
        // A rule's source or target, with attributes evaluated (through
        // nested attributes and expressions) when first used.
        let n = p.type_names.len();
        let mut ev = Eval { types: &p.types, n, raw: &attr_raw, memo: HashMap::new() };
        let mut used: HashMap<String, usize> = HashMap::new();
        let mut sets = Vec::new();
        let mut who = |name: &str| -> Option<Who> {
            if let Some(&t) = ev.types.get(name) {
                return Some(Who::Type(t));
            }
            if !ev.raw.contains_key(name) {
                return None; // an unknown name, or an attribute without members
            }
            let i = *used.entry(name.to_string()).or_insert_with(|| {
                sets.push(ev.attr(name));
                sets.len() - 1
            });
            Some(Who::Attr(i))
        };
        let mut roles: Vec<(&str, Who)> = Vec::new();
        for (role, name) in roletypes {
            roles.extend(who(name).map(|w| (role, w)));
        }
        let mut rules = Vec::new();
        for s in transitions {
            // (typetransition src tgt class ["name"] new)
            let (name, new) = match s.get(4) {
                Some(Sx::Str(name)) => (Some(name.to_string()), atom(s, 5)),
                _ => (None, atom(s, 4)),
            };
            let (Some(src), Some(tgt), Some(&class), Some(&new)) = (who(atom(s, 1)), who(atom(s, 2)), p.class_ix.get(atom(s, 3)), p.types.get(new)) else { continue };
            rules.push(Transition { src, tgt, class, name, new });
        }
        p.attr_sets = sets;
        p.transitions = rules;
        for (role, w) in roles {
            let mut add = Set::with(n);
            match w {
                Who::Type(t) => add.insert(t),
                Who::Attr(a) => add.or(&p.attr_sets[a]),
            }
            p.roles.entry(role.to_string()).or_default().or(&add);
        }
        p
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.types.is_empty()
    }

    /// A class's kernel index (1-based), as selinuxfs class/<name>/index says.
    pub fn class_index(&self, name: &str) -> Option<u16> {
        self.class_ix.get(name).copied()
    }

    pub fn class(&self, index: u16) -> Option<&Class> {
        self.classes.get((index as usize).checked_sub(1)?)
    }

    /// The canonical name of a type or alias.
    pub fn type_name(&self, name: &str) -> Option<&str> {
        self.types.get(name).map(|&t| self.type_names[t as usize].as_str())
    }

    fn has(&self, w: &Who, t: u32) -> bool {
        match w {
            Who::Type(x) => *x == t,
            Who::Attr(a) => self.attr_sets[*a].has(t),
        }
    }

    /// The type a `typetransition` rule gives an object of `class` created
    /// by `src` in `tgt` (an executable for class process). A rule naming the
    /// object wins over an unnamed one.
    pub fn transition(&self, src: &str, tgt: &str, class: u16, name: Option<&str>) -> Option<&str> {
        let (s, t) = (*self.types.get(src)?, *self.types.get(tgt)?);
        let hit = |r: &&Transition| r.class == class && self.has(&r.src, s) && self.has(&r.tgt, t);
        let named = name.and_then(|n| self.transitions.iter().filter(|r| r.name.as_deref() == Some(n)).find(hit));
        let r = named.or_else(|| self.transitions.iter().filter(|r| r.name.is_none()).find(hit))?;
        Some(&self.type_names[r.new as usize])
    }

    /// Whether user:role:type names an existing combination (object_r takes
    /// any type). Unknown names fail.
    pub fn valid(&self, user: &str, role: &str, ty: &str) -> bool {
        let Some(&t) = self.types.get(ty) else { return false };
        let Some(roles) = self.users.get(user) else { return false };
        // As the kernel's policydb_context_isvalid: object_r skips the role checks.
        role == "object_r" || roles.iter().any(|r| r == role) && self.roles.get(role).is_some_and(|s| s.has(t))
    }
}

/// Evaluates attributes from their typeattributeset statements.
struct Eval<'p, 'a> {
    types: &'p HashMap<String, u32>,
    n: usize,
    raw: &'p HashMap<&'a str, Vec<&'a str>>,
    /// None while an attribute is being evaluated, so a cycle adds nothing.
    memo: HashMap<String, Option<Set>>,
}

impl Eval<'_, '_> {
    fn attr(&mut self, name: &str) -> Set {
        match self.memo.get(name) {
            Some(Some(s)) => return s.clone(),
            Some(None) => return Set::with(self.n),
            None => {}
        }
        self.memo.insert(name.to_string(), None);
        let mut s = Set::with(self.n);
        for stmt in self.raw.get(name).cloned().unwrap_or_default() {
            // (typeattributeset name expr)
            if let (Sx::List(l), _) = parse(stmt, 0)
                && let Some(e) = l.get(2)
            {
                let m = self.expr(e);
                s.or(&m);
            }
        }
        self.memo.insert(name.to_string(), Some(s.clone()));
        s
    }

    fn name(&mut self, name: &str) -> Set {
        let mut s = Set::with(self.n);
        match self.types.get(name) {
            Some(&t) => s.insert(t),
            None if self.raw.contains_key(name) => s = self.attr(name),
            None => {}
        }
        s
    }

    /// `(a b …)` is a union; `(and E E)`, `(or E E)`, `(xor E E)`, `(not E)`
    /// and `(all)` are operators.
    fn expr(&mut self, e: &Sx) -> Set {
        let n = self.n;
        let all = || {
            let mut s = Set::with(n);
            (0..n as u32).for_each(|t| s.insert(t));
            s
        };
        match e {
            Sx::Atom(a) => self.name(a),
            Sx::Str(_) => Set::with(n),
            Sx::List(l) => {
                let op = l.first().and_then(Sx::atom);
                let arg = |me: &mut Self, i: usize| l.get(i).map_or_else(|| Set::with(n), |x| me.expr(x));
                match op {
                    Some("all") => all(),
                    Some("not") => {
                        let a = arg(self, 1);
                        let mut s = all();
                        s.0.iter_mut().zip(&a.0).for_each(|(x, y)| *x &= !y);
                        s
                    }
                    Some(op @ ("and" | "or" | "xor")) => {
                        let (mut a, b) = (arg(self, 1), arg(self, 2));
                        a.0.iter_mut().zip(&b.0).for_each(|(x, y)| match op {
                            "and" => *x &= y,
                            "or" => *x |= y,
                            _ => *x ^= y,
                        });
                        a
                    }
                    _ => {
                        let mut s = Set::with(n);
                        for x in l {
                            match x.atom().and_then(|a| self.types.get(a)) {
                                Some(&t) => s.insert(t),
                                None => {
                                    let m = self.expr(x);
                                    s.or(&m);
                                }
                            }
                        }
                        s
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Policy;

    const MINI: &str = include_str!("../../../testdata/sepolicy_mini.cil");
    /// A second file, as a vendor policy would be: attributes defined by
    /// expressions over other attributes, used by a transition.
    const EXTRA: &str = "
        ; comment (with parens
        (typeattribute domain)
        (typeattributeset domain (init kernel shell logd toolbox hal_audio_default test_t))
        (typeattributeset not_init (and (domain) (not (init kernel))))
        (type test_exec)
        (type test_t)
        (allow domain test_exec (file (read
            execute)))
        (typetransition not_init test_exec process test_t)
        (boolean test_bool true)
    ";

    #[test]
    fn class_indices_and_permission_bits() {
        let p = Policy::parse(&[MINI]);
        // classorder: security process system capability ... (index = position + 1)
        assert_eq!(p.class_index("security"), Some(1));
        assert_eq!(p.class_index("process"), Some(2));
        assert_eq!(p.class_index("file"), Some(6));
        assert_eq!(p.class_index("property_service"), Some(99));
        assert_eq!(p.classes.len(), 107);
        // A class's own permissions follow its common's.
        let file = p.class(6).unwrap();
        assert_eq!(file.perms[0], "ioctl");
        assert_eq!(file.perms.iter().position(|x| x == "execute_no_trans"), Some(25));
        assert_eq!(p.class(2).unwrap().perms[1], "transition");
        assert_eq!(p.class(99).unwrap().perms, ["set"]);
        assert_eq!(p.class_index("capability").and_then(|c| p.class(c)).map(|c| c.perms.len()), Some(32));
    }

    #[test]
    fn sids_and_caps() {
        let p = Policy::parse(&[MINI]);
        assert_eq!(p.sids[0], ("kernel".to_string(), "u:r:kernel:s0".to_string()));
        assert_eq!(p.sids.last().unwrap(), &("devnull".to_string(), "u:object_r:null_device:s0".to_string()));
        assert!(p.caps.iter().any(|c| c == "open_perms"));
    }

    #[test]
    fn type_transitions() {
        let p = Policy::parse(&[MINI, EXTRA]);
        let process = p.class_index("process").unwrap();
        assert_eq!(p.transition("init", "logd_exec", process, None), Some("logd"));
        assert_eq!(p.transition("kernel", "init_exec", process, None), Some("init"));
        assert_eq!(p.transition("init", "system_file", process, None), None);
        // The source is init_202504, an attribute holding init (the vendor mapping).
        assert_eq!(p.transition("init", "hal_audio_default_exec", process, None), Some("hal_audio_default"));
        assert_eq!(p.transition("shell", "hal_audio_default_exec", process, None), None);
        // An attribute given by (and (domain) (not (init kernel))).
        assert_eq!(p.transition("shell", "test_exec", process, None), Some("test_t"));
        assert_eq!(p.transition("init", "test_exec", process, None), None);
        let file = p.class_index("file").unwrap();
        assert_eq!(p.transition("shell", "tmpfs", file, None), Some("appdomain_tmpfs"));
        assert_eq!(p.transition("shell", "tmpfs", process, None), None);
        // Named transitions apply only to their name.
        let anon = p.class_index("anon_inode").unwrap();
        assert_eq!(p.transition("shell", "shell", anon, Some("[userfaultfd]")), Some("shell_userfaultfd"));
        assert_eq!(p.transition("shell", "shell", anon, Some("[io_uring]")), None);
        assert_eq!(p.bools, [("test_bool".to_string(), true)]);
    }

    #[test]
    fn context_validity() {
        let p = Policy::parse(&[MINI, EXTRA]);
        assert!(p.valid("u", "r", "init"));
        assert!(p.valid("u", "object_r", "system_file"));
        assert!(!p.valid("u", "r", "system_file")); // not a domain
        assert!(!p.valid("u", "r", "no_such_type"));
        assert!(!p.valid("x", "r", "init"));
        assert_eq!(p.type_name("rs_data_file"), Some("app_exec_data_file"));
    }
}
