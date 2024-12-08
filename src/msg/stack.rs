use crate::utils::cast;

use std::mem::size_of;

use blazesym::symbolize::Sym;
use blazesym::symbolize::{CodeInfo, Input, Kernel, Source, Symbolized, Symbolizer};
use blazesym::Addr;

use plain::Plain;

const PERF_MAX_STACK_DEPTH: usize = 127;
type Stack = [u64; PERF_MAX_STACK_DEPTH];

#[repr(C)]
struct StackMsg {
    kstack_sz: u64,
    kstack: Stack,
}
unsafe impl Plain for StackMsg {}

const ADDR_WIDTH: usize = 16;

fn print_frame(name: &str, addr_info: Option<(Addr, Addr, usize)>, code_info: &Option<CodeInfo>) {
    let code_info = code_info.as_ref().map(|code_info| {
        let path = code_info.to_path();
        let path = path.display();

        match (code_info.line, code_info.column) {
            (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
            (Some(line), None) => format!(" {path}:{line}"),
            (None, _) => format!(" {path}"),
        }
    });

    if let Some((input_addr, addr, offset)) = addr_info {
        println!(
            "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
            width = ADDR_WIDTH,
            code_info = code_info.as_deref().unwrap_or(""),
        )
    } else {
        println!(
            "{:width$}  {name}{code_info} [inlined]",
            " ",
            width = ADDR_WIDTH,
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or(""),
        )
    }
}

pub fn stack_msg_handler(bytes: &[u8]) -> i32 {
    let msg: &StackMsg = cast(bytes);
    let stack_sz = msg.kstack_sz as usize / size_of::<u64>();
    let addrs = &msg.kstack[..stack_sz];

    let src = Source::Kernel(Kernel::default());
    let symbolizer = Symbolizer::new();
    let syms = symbolizer.symbolize(&src, Input::AbsAddr(addrs)).unwrap();

    for (input_addr, sym) in addrs.iter().copied().zip(syms) {
        match sym {
            Symbolized::Sym(Sym {
                name,
                addr,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                print_frame(&name, Some((input_addr, addr, offset)), &code_info);
                for frame in inlined.iter() {
                    print_frame(&frame.name, None, &frame.code_info);
                }
            }
            Symbolized::Unknown(..) => {
                println!("{input_addr:#0width$x}: <no-symbol>", width = ADDR_WIDTH)
            }
        }
    }

    0
}
