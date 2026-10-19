//! Compiles the kernel C (extracted verbatim) into a static library with the
//! semantics-affecting flags of the kernel build (harness/kbuild-cmdlines.txt).
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let root = root.canonicalize().unwrap();
    // Flags kept from the kernel command line that affect semantics; the rest
    // (kernel code model, stack protector, retpolines, warnings) are dropped.
    let flags = [
        "-O2", "-std=gnu11", "-fno-strict-overflow", "-fno-strict-aliasing", "-funsigned-char",
        "-fno-delete-null-pointer-checks", "-fno-common", "-fwrapv-pointer",
        "-Wall", "-Wno-unused-function",
    ];
    let srcs = ["extracted/tnum.c", "extracted/cnum.c", "harness/c/layer_b.c"];
    let mut objs = vec![];
    for s in srcs {
        let src = root.join(s);
        let obj = out.join(PathBuf::from(s).file_stem().unwrap()).with_extension("o");
        let st = Command::new("gcc")
            .args(flags)
            .arg("-I").arg(root.join("harness/shim"))
            .arg("-I").arg(&root)
            .arg("-c").arg(&src).arg("-o").arg(&obj)
            .status().expect("gcc");
        assert!(st.success(), "gcc failed on {}", s);
        println!("cargo:rerun-if-changed={}", src.display());
        objs.push(obj);
    }
    let lib = out.join("libkernel_c.a");
    let _ = std::fs::remove_file(&lib);
    let st = Command::new("ar").arg("rcs").arg(&lib).args(&objs).status().expect("ar");
    assert!(st.success());
    println!("cargo:rerun-if-changed={}", root.join("harness/shim").display());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=kernel_c");
}
