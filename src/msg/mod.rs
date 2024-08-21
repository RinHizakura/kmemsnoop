mod stack;

use std::mem::size_of;

use crate::msg::stack::stack_msg_handler;
use crate::utils::cast;

use plain::Plain;

const MSG_TYPE_STACK: u64 = 0;

#[repr(C)]
struct MsgEnt {
    id: u64,
    typ: u64,
}
unsafe impl Plain for MsgEnt {}

pub fn msg_handler(bytes: &[u8]) -> i32 {
    let ent_size = size_of::<MsgEnt>();
    let ent = &bytes[0..ent_size];
    let inner = &bytes[ent_size..];

    let ent: &MsgEnt = cast(ent);
    let id = ent.id;
    println!("Get message id={id}");

    match ent.typ {
        MSG_TYPE_STACK => stack_msg_handler(inner),
        _ => panic!("Invalid message with wrong type"),
    }
}
