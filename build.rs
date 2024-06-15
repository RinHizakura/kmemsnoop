use anyhow::Result;
use std::fs::create_dir_all;
use std::path::Path;

use libbpf_cargo::SkeletonBuilder;

const SKEL_SRC: &str = "bpf/kmemsnoop.bpf.c";
const SKEL_OUT: &str = "bpf/.output/kmemsnoop.skel.rs";

fn main() -> Result<()> {
    // FIXME: Is it possible to output to env!("OUT_DIR")?
    std::env::set_var("BPF_OUT_DIR", "bpf/.output");

    create_dir_all("bpf/.output")?;

    let skel = Path::new(SKEL_OUT);
    SkeletonBuilder::new()
        .source(SKEL_SRC)
        .clang_args(["-I.", "-Wextra", "-Wall", "-Werror"])
        .build_and_generate(&skel)?;

    println!("cargo:rerun-if-changed={}", SKEL_SRC);

    Ok(())
}
