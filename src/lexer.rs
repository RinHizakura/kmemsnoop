pub enum Token {
    Member(String),
    Access,
    Valof,
    Deref,
}

/* FIXME: This is an ugly lexer for the C structure experssion :( */
pub struct Lexer {
    s: String,
    pos: usize,
    len: usize,
}

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
