# Environment (recorded 2026-10-19, task 0)

All version strings below are the literal output of the command shown.

## Kernel tree

| Item | Value | Command |
|---|---|---|
| `~/linux-ebpf` HEAD | v7.3-rc5-1314-g4f842631f178 (4f842631f178f41baa2d2d444a277d54c07666a1) | `git -C ~/linux-ebpf describe HEAD`, `git rev-parse HEAD` |
| `bpf-next/master` | v7.3-rc5-1314-g4f842631f178 (4f842631f178f41baa2d2d444a277d54c07666a1) | `git -C ~/linux-ebpf describe bpf-next/master` |
| Branch | ebpf-spike | `git branch --show-current` |
| HEAD commit date | 2026-10-19 04:23:55 +0200 | `git log -1 --format=%cd --date=iso` |
| Date of this record | 2026-10-19 10:10 UTC | `date -u` |

## Rust

| Tool | Version | Command |
|---|---|---|
| rustc | rustc 1.94.0 (4a4ef493e 2026-03-02) | `rustc --version` |
| cargo | cargo 1.94.0 (85eff7c80 2026-01-15) | `cargo --version` |

## Charon / Aeneas (pinned pair, used for every result unless stated otherwise)

| Tool | Version | Command |
|---|---|---|
| charon | 0.1.220 at commit 909ff09a, binary `~/charon/bin/charon` (built 2026-07-10) | `~/charon/bin/charon version`; `git -C ~/charon rev-parse --short HEAD` |
| charon binary NOT used | `~/aeneas-project/aeneas/charon/bin/charon` prints 0.1.170 (stale build of 2026-02-26 of the same checkout); Aeneas c2015b86 rejects its LLBC ("supports llbc emitted by charon v0.1.220") | `~/aeneas-project/aeneas/charon/bin/charon version` |
| charon's pinned Rust toolchain | nightly-2026-06-01-x86_64-unknown-linux-gnu (`~/charon`); the stale binary pins nightly-2026-02-07 | `~/charon/bin/charon toolchain-path` |
| aeneas | aeneas c2015b86 | `~/aeneas-project/aeneas/bin/aeneas -version` |
| aeneas charon-pin | 909ff09ad0f144f83d354f2c3d26f631fb9f8e9a | `tail -1 ~/aeneas-project/aeneas/charon-pin` |

Both `charon-driver` binaries are nix builds (RUNPATH into `/nix/store`). Through
`rustup run` they fail with `libz.so.1: cannot open shared object file` because the loader
takes `librustc_driver` from the rustup toolchain and the nix glibc's cache does not list
`/lib/x86_64-linux-gnu`. Workaround used: `LD_LIBRARY_PATH` pointing at a directory that
contains only a symlink to `/nix/store/z55x0q74zldi64iwamqf8wgrm2iza5rk-zlib-1.3.1/lib/libz.so.1`
(putting `/lib/x86_64-linux-gnu` itself on the path breaks `charon`: `GLIBC_2.39 not found`).

## Charon / Aeneas (HEAD pair in `~/aeneas_merge_abstractions`, used only where stated)

| Tool | Version | Command |
|---|---|---|
| charon | 0.1.254 (b104e24fea7d721b71e6c39fd70f26ff20bc0980) | `~/aeneas_merge_abstractions/charon/bin/charon version` |
| aeneas | aeneas 505b6ca3-dirty | `~/aeneas_merge_abstractions/aeneas/bin/aeneas -version` |

## Lean (from inside `lean/`, the lake project; `lean-toolchain` = leanprover/lean4:v4.31.0)

| Tool | Version | Command |
|---|---|---|
| lake | Lake version 5.0.0-src+68218e8 (Lean version 4.31.0) | `cd lean && lake --version` |
| lean | Lean (version 4.31.0, x86_64-unknown-linux-gnu, commit 68218e876d2a38b1985b8590fff244a83c321783, Release) | `cd lean && lean --version` |
| mathlib | rev fabf563a7c95a166b8d7b6efca11c8b4dc9d911f (inputRev v4.31.0) | `lean/lake-manifest.json` |

The Aeneas Lean library and mathlib are the prebuilt copies under
`~/aeneas-project/aeneas/backends/lean/.lake`; `lean/.lake/packages` is a symlink to
them so nothing is rebuilt.

## C compilers

| Tool | Version | Command |
|---|---|---|
| gcc | gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0 | `gcc --version` |
| clang | clang version 19.1.5 (https://github.com/llvm/llvm-project.git ab4b5a2db582958af1ee308a790cfdb42bd24720) | `clang --version` |
| kernel build compiler | CONFIG_CC_IS_GCC=y, CONFIG_GCC_VERSION=110400 | `grep CONFIG_CC_IS ~/build-ebpf/.config` |

## Host

| Item | Value | Command |
|---|---|---|
| OS | Ubuntu 22.04.5 LTS | `/etc/os-release` |
| kernel | 6.8.0-138-generic | `uname -r` |
| CPUs | 20 | `nproc` |
| python3 | Python 3.10.12 | `python3 --version` |

LibAFL: not used in this phase.
