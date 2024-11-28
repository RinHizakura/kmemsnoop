use crate::utils::cast;
use plain::Plain;

#[repr(C)]
struct DataMsg {
    addr: u64,
    val: u64,
}
unsafe impl Plain for DataMsg {}

pub fn data_msg_handler(bytes: &[u8]) -> i32 {
    let msg: &DataMsg = cast(bytes);
    let addr = msg.addr;
    let val = msg.val;

    println!("data@0x{addr:x} = {val:x}");

    0
}
