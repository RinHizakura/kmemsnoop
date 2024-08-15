use anyhow::{anyhow, Result};

#[cfg(feature = "kexpr")]
use drgn_knight::{Object, Program};

#[cfg(feature = "kexpr")]
enum Token {
    Member(String),
    Access,
    Valof,
    Deref,
}

/* FIXME: This is an ugly lexer for the C structure experssion :( */
#[cfg(feature = "kexpr")]
struct Lexer {
    s: String,
    pos: usize,
    len: usize,
}

#[cfg(feature = "kexpr")]
impl Lexer {
    pub fn new(s: String) -> Self {
        let l = s.len();
        Lexer {
            s: s,
            pos: 0,
            len: l,
        }
    }

    pub fn next_token(&mut self) -> Option<Token> {
        let s = self.s.as_bytes();

        while self.pos < self.len {
            let c = s[self.pos] as u8;
            self.pos += 1;
            match c {
                b'.' => return Some(Token::Access),
                b'*' => return Some(Token::Valof),
                b'-' => {
                    if self.pos >= self.len || s[self.pos] != b'>' {
                        return None;
                    }
                    self.pos += 1;
                    return Some(Token::Deref);
                }
                _ => {
                    let start = self.pos - 1;

                    while self.pos < self.len {
                        let c = s[self.pos];
                        if c == b'.' || c == b'-' {
                            break;
                        }
                        self.pos += 1;
                    }

                    return Some(Token::Member(self.s[start..self.pos].to_string()));
                }
            }
        }

        None
    }
}

#[cfg(feature = "kexpr")]
enum TokenType {
    Access,
    Deref,
    Member,
}

#[cfg(feature = "kexpr")]
fn find_expr_value(obj: &Object, expr: &str) -> Option<u64> {
    let mut lexer = Lexer::new(expr.to_string());
    let mut value_of = false;

    /* The First token should be Token::Member or Token::Valof, and
     * we need the first member here. */
    let mut cur_obj = None;
    while let Some(token) = lexer.next_token() {
        match token {
            Token::Valof => {
                if value_of {
                    return None;
                }
                value_of = true;
            }
            Token::Member(member) => {
                cur_obj = obj.deref_member(&member);
                break;
            }
            _ => return None,
        }
    }

    let mut cur_obj = cur_obj?;
    let mut prev_token = TokenType::Member;
    while let Some(token) = lexer.next_token() {
        match token {
            Token::Member(member) => {
                cur_obj = match prev_token {
                    TokenType::Access => cur_obj.member(&member)?,
                    TokenType::Deref => cur_obj.deref_member(&member)?,
                    _ => return None,
                };

                prev_token = TokenType::Member;
            }
            Token::Access => {
                if !matches!(prev_token, TokenType::Member) {
                    return None;
                }
                prev_token = TokenType::Access;
            }
            Token::Deref => {
                if !matches!(prev_token, TokenType::Member) {
                    return None;
                }
                prev_token = TokenType::Deref;
            }
            _ => return None,
        }
    }

    if value_of {
        cur_obj.to_num().ok()
    } else {
        cur_obj.address_of().ok()
    }
}

#[cfg(feature = "kexpr")]
pub fn task_kexpr2addr(pid: u64, expr: &str) -> Result<usize> {
    let prog = Program::new();
    let task = prog.find_task(pid)?;
    if let Some(value) = find_expr_value(&task, expr) {
        return Ok(value as usize);
    }

    Err(anyhow!("Invalid kexpr {expr}"))
}

#[cfg(not(feature = "kexpr"))]
pub fn task_kexpr2addr(_pid: u64, _expr: &str) -> Result<usize> {
    Err(anyhow!("kexpr is not configured"))
}

#[cfg(feature = "kexpr")]
#[cfg(test)]
mod kexpr_tests {
    use super::*;
    use crate::hexstr2int;
    use anyhow::Result;
    use std::process::{Command, Stdio};

    macro_rules! exec {
        ($args:expr) => {
            hexstr2int(
                &String::from_utf8(
                    Command::new("./tests/kexpr.py")
                        .args($args)
                        .stdout(Stdio::piped())
                        .output()
                        .expect("Fail to execute kexpr")
                        .stdout,
                )
                .expect("Invalid output from kexpr.py")
                .trim()
                .to_string(),
            )
            .expect("Fail to convert kexpr output to usize")
        };
    }

    #[test]
    fn test_task_struct_kexpr() -> Result<()> {
        let expect = exec!(["-p", "1", "on_rq"]);
        assert_eq!(expect, task_kexpr2addr(1, "on_rq")?);
        let expect = exec!(["-p", "1", "*parent"]);
        assert_eq!(expect, task_kexpr2addr(1, "*parent")?);

        Ok(())
    }
}
