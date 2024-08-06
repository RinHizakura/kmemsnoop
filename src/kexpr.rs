use crate::lexer::*;
use drgn_knight::Object;

enum TokenType {
    Access,
    Deref,
    Member,
}

pub fn find_expr_value(obj: &Object, expr: &str) -> Option<u64> {
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
