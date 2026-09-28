//! kexpr grammar and evaluation, independent of drgn so it builds and
//! tests everywhere:
//!
//!     expr   := ['&'] member ( ('.' | '->') member )*
//!     member := C identifier
//!
//! The root object is a pointer, so the first member is always reached
//! through `->`. Evaluation walks a `Walk`: drgn's Object in production,
//! a fake struct tree in tests.

use anyhow::{anyhow, bail, Result};

/// A kernel struct object a kexpr can be walked over.
pub trait Walk: Sized {
    /// `self.member`
    fn member(&self, member: &str) -> Option<Self>;
    /// `self->member`
    fn deref_member(&self, member: &str) -> Option<Self>;
    /// `&self`
    fn address_of(&self) -> Option<Self>;
    fn to_num(&self) -> Result<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `a.b`
    Access,
    /// `a->b`
    Deref,
}

#[derive(Debug, PartialEq, Eq)]
struct Step {
    op: Op,
    member: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Expr {
    /// The text as the user wrote it, for error messages.
    src: String,
    addr_of: bool,
    /// Never empty: parse() rejects an expression without a member.
    steps: Vec<Step>,
}

impl Expr {
    pub fn parse(s: &str) -> Result<Expr> {
        let b = s.as_bytes();
        let mut pos = 0;

        let addr_of = b.first() == Some(&b'&');
        if addr_of {
            pos = 1;
        }

        let mut steps = Vec::new();
        let mut op = Op::Deref;
        loop {
            let start = pos;
            while pos < b.len() && (b[pos].is_ascii_alphanumeric() || b[pos] == b'_') {
                pos += 1;
            }
            if start == pos {
                bail!("kexpr {s:?}: expected member name at {start}");
            }
            if b[start].is_ascii_digit() {
                bail!("kexpr {s:?}: member name can't start with a digit at {start}");
            }
            steps.push(Step {
                op,
                member: s[start..pos].to_string(),
            });

            if pos == b.len() {
                break;
            }
            op = match &b[pos..] {
                [b'.', ..] => {
                    pos += 1;
                    Op::Access
                }
                [b'-', b'>', ..] => {
                    pos += 2;
                    Op::Deref
                }
                _ => bail!("kexpr {s:?}: expected '.' or '->' at {pos}"),
            };
        }

        Ok(Expr {
            src: s.to_string(),
            addr_of,
            steps,
        })
    }

    /// Walk the steps from `root` and read the final value, or its address
    /// when the expression started with `&`.
    pub fn eval<W: Walk>(&self, root: &W) -> Result<u64> {
        let src = &self.src;
        let mut cur: Option<W> = None;
        let mut prev: Option<&str> = None;
        for step in &self.steps {
            let obj = cur.as_ref().unwrap_or(root);
            let next = match step.op {
                Op::Access => obj.member(&step.member),
                Op::Deref => obj.deref_member(&step.member),
            };
            cur = Some(next.ok_or_else(|| match prev {
                Some(prev) => anyhow!(
                    "kexpr {src:?}: member {:?} not found after {prev:?}",
                    step.member
                ),
                None => anyhow!("kexpr {src:?}: member {:?} not found", step.member),
            })?);
            prev = Some(&step.member);
        }

        let cur = cur.expect("Expr::parse never yields an empty expression");
        if self.addr_of {
            cur.address_of()
                .ok_or_else(|| {
                    anyhow!(
                        "kexpr {src:?}: can't take the address of {:?}",
                        prev.unwrap_or("")
                    )
                })?
                .to_num()
        } else {
            cur.to_num()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(op: Op, member: &str) -> Step {
        Step {
            op,
            member: member.to_string(),
        }
    }

    fn expr(src: &str, addr_of: bool, steps: Vec<Step>) -> Expr {
        Expr {
            src: src.to_string(),
            addr_of,
            steps,
        }
    }

    #[test]
    fn parses_readme_examples() -> Result<()> {
        assert_eq!(
            Expr::parse("on_rq")?,
            expr("on_rq", false, vec![step(Op::Deref, "on_rq")])
        );
        assert_eq!(
            Expr::parse("&on_rq")?,
            expr("&on_rq", true, vec![step(Op::Deref, "on_rq")])
        );
        assert_eq!(
            Expr::parse("&se.nr_migrations")?,
            expr(
                "&se.nr_migrations",
                true,
                vec![step(Op::Deref, "se"), step(Op::Access, "nr_migrations")]
            )
        );
        assert_eq!(
            Expr::parse("&mm->task_size")?,
            expr(
                "&mm->task_size",
                true,
                vec![step(Op::Deref, "mm"), step(Op::Deref, "task_size")]
            )
        );
        Ok(())
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "", "&", "&&a", "a-b", "a..b", "a.", "a->", "a b", "a&b", "1a", ".a",
        ] {
            assert!(Expr::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn error_names_position() {
        let err = Expr::parse("&se..nr").unwrap_err().to_string();
        assert!(err.contains("at 4"), "{err}");
    }

    /* A fake struct tree: `struct task { se: struct { nr: 7 }, mm: *struct { size: 9 } }`
     * where `se` is embedded (reached by `.`) and `mm` is a pointer (reached by `->`),
     * and only `nr` has an address. */
    #[derive(Clone, Copy)]
    enum Node {
        Task,
        Se,
        Mm,
        Nr,
        Size,
        Addr(u64),
    }

    impl Walk for Node {
        fn member(&self, m: &str) -> Option<Self> {
            match (self, m) {
                (Node::Se, "nr") => Some(Node::Nr),
                _ => None,
            }
        }
        fn deref_member(&self, m: &str) -> Option<Self> {
            match (self, m) {
                (Node::Task, "se") => Some(Node::Se),
                (Node::Task, "mm") => Some(Node::Mm),
                (Node::Mm, "size") => Some(Node::Size),
                _ => None,
            }
        }
        fn address_of(&self) -> Option<Self> {
            match self {
                Node::Nr => Some(Node::Addr(0x1000)),
                _ => None,
            }
        }
        fn to_num(&self) -> Result<u64> {
            match self {
                Node::Nr => Ok(7),
                Node::Size => Ok(9),
                Node::Addr(a) => Ok(*a),
                _ => Err(anyhow!("not a scalar")),
            }
        }
    }

    #[test]
    fn eval_walks_access_and_deref_distinctly() -> Result<()> {
        assert_eq!(Expr::parse("se.nr")?.eval(&Node::Task)?, 7);
        assert_eq!(Expr::parse("mm->size")?.eval(&Node::Task)?, 9);
        assert_eq!(Expr::parse("&se.nr")?.eval(&Node::Task)?, 0x1000);
        /* Wrong operator for the member must not resolve. */
        assert!(Expr::parse("se->nr")?.eval(&Node::Task).is_err());
        assert!(Expr::parse("mm.size")?.eval(&Node::Task).is_err());
        Ok(())
    }

    #[test]
    fn eval_errors_name_the_kexpr_and_the_member() -> Result<()> {
        let err = Expr::parse("nope")?
            .eval(&Node::Task)
            .unwrap_err()
            .to_string();
        assert_eq!(err, r#"kexpr "nope": member "nope" not found"#);

        let err = Expr::parse("se.nope")?
            .eval(&Node::Task)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            r#"kexpr "se.nope": member "nope" not found after "se""#
        );

        let err = Expr::parse("&mm->size")?
            .eval(&Node::Task)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            r#"kexpr "&mm->size": can't take the address of "size""#
        );
        Ok(())
    }
}
