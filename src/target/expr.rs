//! kexpr grammar, independent of drgn so it builds and tests everywhere:
//!
//!     expr   := ['&'] member ( ('.' | '->') member )*
//!     member := C identifier
//!
//! The root object is a pointer, so the first member is always reached
//! through `->`. `Expr::eval()` lives in kexpr.rs next to drgn.

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `a.b`
    Access,
    /// `a->b`
    Deref,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    pub op: Op,
    pub member: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Expr {
    pub addr_of: bool,
    /// Never empty: parse() rejects an expression without a member.
    pub steps: Vec<Step>,
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

        Ok(Expr { addr_of, steps })
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

    #[test]
    fn parses_readme_examples() -> Result<()> {
        assert_eq!(
            Expr::parse("on_rq")?,
            Expr {
                addr_of: false,
                steps: vec![step(Op::Deref, "on_rq")]
            }
        );
        assert_eq!(
            Expr::parse("&on_rq")?,
            Expr {
                addr_of: true,
                steps: vec![step(Op::Deref, "on_rq")]
            }
        );
        assert_eq!(
            Expr::parse("&se.nr_migrations")?,
            Expr {
                addr_of: true,
                steps: vec![step(Op::Deref, "se"), step(Op::Access, "nr_migrations")]
            }
        );
        assert_eq!(
            Expr::parse("&mm->task_size")?,
            Expr {
                addr_of: true,
                steps: vec![step(Op::Deref, "mm"), step(Op::Deref, "task_size")]
            }
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
}
