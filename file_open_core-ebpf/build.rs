use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use aya_tool::generate::InputFile;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("vmlinux.rs");

    let names: Vec<&str> = vec![
        "cred",
        "sock",
        "sockaddr",
        "sockaddr_in",
        "sockaddr_in6",
        "task_struct",
    ];

    let bindings = aya_tool::generate(
        InputFile::Header(PathBuf::from("src/shim/vmlinux.h")),
        &names,
        &[],
    )
    .unwrap();
    println!("cargo:rerun-if-changed=src/shim/vmlinux.h");

    let mut out = File::create(dest_path).unwrap();
    write!(out, "{}", bindings).unwrap();

    let _ = Command::new("clang")
        .arg("-I")
        .arg("src/")
        .arg("-O2")
        .arg("-emit-llvm")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg("-g")
        .arg("src/shim/access.c")
        .arg("-o")
        .arg(format!("{out_dir}/access.o"))
        .status()
        .expect("Failed to compile the C-shim");

    println!("cargo:rustc-link-lib=link-arg=--btf");
    // println!("cargo:rustc-link-lib=link-arg=--log-level=debug");
    // println!("cargo:rustc-link-lib=link-arg=--log-file=/tmp/linker.log");
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=link-arg={out_dir}/access.o");
    println!("cargo:rerun-if-changed=src/shim/access.c");
}
