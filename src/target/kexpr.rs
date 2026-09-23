use anyhow::{anyhow, Result};
use drgn_knight::*;

use super::Bus;

#[derive(Debug)]
enum Token {
    Member(String),
    Access,
    AddrOf,
    Deref,
}

/* FIXME: This is an ugly lexer for the C structure experssion :( */
struct Lexer {
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
                b'&' => return Some(Token::AddrOf),
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

enum TokenType {
    Access,
    Deref,
    Member,
}

fn find_expr_value(obj: &Object, expr: &str) -> Option<u64> {
    let mut lexer = Lexer::new(expr.to_string());
    let mut addr_of = false;

    /* The First token should be Token::AddrOf or Token::Member, and
     * we need the first member here. */
    let mut cur_obj = None;
    while let Some(token) = lexer.next_token() {
        match token {
            Token::AddrOf => {
                if addr_of {
                    return None;
                }
                addr_of = true;
            }
            Token::Member(member) => {
                cur_obj = obj.deref_member(&member);
                break;
            }
            _ => {
                println!("Invalid token {token:?}");
                return None;
            }
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

    if addr_of {
        cur_obj.address_of()?.to_num().ok()
    } else {
        cur_obj.to_num().ok()
    }
}

pub fn task(pid: u64, expr: &str) -> Result<usize> {
    let prog = Program::new()?;
    let task = prog.find_task(pid)?;
    if let Some(value) = find_expr_value(&task, expr) {
        return Ok(value as usize);
    }

    Err(anyhow!("Invalid kexpr {expr}"))
}

fn bus_to_subsys(prog: &Program, bus: &str) -> Result<Object> {
    let bus_kset = prog.find_object_variable("bus_kset")?;
    let bus_kset_list = bus_kset
        .deref_member("list")
        .ok_or(anyhow!("Fail to find member list"))?;
    let subsys_list = List::new(bus_kset_list, "struct subsys_private", "subsys.kobj.entry")?;

    for subsys in subsys_list {
        let Some(bus_type) = subsys.deref_member("bus") else {
            continue;
        };

        let Some(bus_name) = bus_type.deref_member("name") else {
            continue;
        };

        let Ok(name) = bus_name.to_str() else {
            continue;
        };

        if bus == name {
            return Ok(subsys);
        };
    }

    Err(anyhow!(format!("Bus {bus} is not found")))
}

fn find_busdev(prog: &Program, bus: &str, dev_name: &str) -> Result<Object> {
    let sp = bus_to_subsys(prog, bus)?;
    let sp_k_list = sp
        .deref_member("klist_devices")
        .ok_or(anyhow!("Fail to find member klist_devices"))?
        .member("k_list")
        .ok_or(anyhow!("Fail to find member k_list"))?;

    let dev_list = List::new(sp_k_list, "struct device_private", "knode_bus.n_node")?;

    for dev in dev_list {
        let device = dev
            .deref_member("device")
            .ok_or(anyhow!("Fail to find member device"))?;
        let device_name = device
            .deref_member("kobj")
            .ok_or(anyhow!("Fail to find member kobj"))?
            .member("name")
            .ok_or(anyhow!("Fail to find member name"))?
            .to_str()?;

        if device_name == dev_name {
            return Ok(device);
        }
    }

    Err(anyhow!("Fail to find {dev_name} on bus {bus}"))
}

pub fn busdev(bus: Bus, dev_name: &str, expr: &str) -> Result<usize> {
    let (bus_name, dev_struct) = bus.table();
    let prog = Program::new()?;
    let busdev = find_busdev(&prog, bus_name, dev_name)?;
    let dev = busdev
        .container_of(dev_struct, "dev")
        .ok_or(anyhow!("Fail to get data for device {dev_name}"))?;
    if let Some(value) = find_expr_value(&dev, expr) {
        return Ok(value as usize);
    }

    Err(anyhow!("Invalid {expr} for device {dev_name}"))
}
