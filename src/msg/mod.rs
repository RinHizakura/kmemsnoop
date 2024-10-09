mod stack;

use std::mem::size_of;

use crate::msg::stack::stack_msg_handler;
use crate::utils::cast;

use libc::c_char;
use plain::Plain;

const MSG_TYPE_STACK: u64 = 0;
const TASK_COMM_LEN: usize = 16;

#[repr(C)]
struct MsgEnt {
    id: u64,
    typ: u64,
    pid: u64,
    cmd: [c_char; TASK_COMM_LEN],
}
unsafe impl Plain for MsgEnt {}

pub(super) fn format_cmd(buf: &[u8; TASK_COMM_LEN]) -> String {
    let len = buf.len();
    let mut idx = 0;

    let mut s = String::new();
    s.push('"');
    while idx < len {
        let c = buf[idx];
        if c == 0 {
            break;
        } else {
            s.push(c as char);
        }

        idx += 1;
    }

    /* If we can't find the ended zero in the buffer, this is an incomplete string. */
    let extra = if idx >= len { "..." } else { "" };
    s.push_str(&format!("\"{}", extra));
    s
}

pub fn msg_handler(bytes: &[u8]) -> i32 {
    let ent_size = size_of::<MsgEnt>();
    let ent = &bytes[0..ent_size];
    let inner = &bytes[ent_size..];

    let ent: &MsgEnt = cast(ent);
    let id = ent.id;
    let pid = ent.pid;
    println!("Get message id={id}, pid={pid} ({})", &format_cmd(&ent.cmd));

    match ent.typ {
        MSG_TYPE_STACK => stack_msg_handler(inner),
        _ => panic!("Invalid message with wrong type"),
    }
}
