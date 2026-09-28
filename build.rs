use std::env;
use std::path::PathBuf;

use anyhow::Result;
use libbpf_cargo::SkeletonBuilder;

const SKEL_SRC: &str = "bpf/kmemsnoop.bpf.c";

fn main() -> Result<()> {
    /* The BPF object goes to a temporary directory; only the skeleton is
     * kept, in OUT_DIR, where src/main.rs include!()s it. */
    let skel = PathBuf::from(env::var("OUT_DIR")?).join("kmemsnoop.skel.rs");
    SkeletonBuilder::new()
        .source(SKEL_SRC)
        .clang_args(["-I.", "-Wextra", "-Wall", "-Werror"])
        .build_and_generate(&skel)?;

    for src in [SKEL_SRC, "bpf/msg.h", "bpf/utils.h", "vmlinux.h"] {
        println!("cargo:rerun-if-changed={src}");
    }

    Ok(())
}
