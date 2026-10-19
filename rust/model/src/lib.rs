//! Safe-Rust model of the Linux eBPF verifier's scalar value tracking.
//!
//! Source: `~/linux-ebpf` at commit 4f842631f178 (bpf-next/master, 2026-10-19).
//! One Rust function per C function, same name, same field names, same integer
//! widths.  Wrapping arithmetic is written out wherever the C relies on
//! unsigned wraparound (the kernel builds with `-fno-strict-overflow`).
//! Preconditions the C relies on (shift counts, non-zero divisors) are stated
//! in comments; the Rust panics (debug) or returns `fail` (Aeneas) where C
//! would be undefined.
//!
//! Module map:
//!   tnum_c     <- kernel/bpf/tnum.c, include/linux/tnum.h
//!   cnum_c     <- kernel/bpf/cnum.c, kernel/bpf/cnum_defs.h, include/linux/cnum.h,
//!                 imod() from include/linux/bpf_verifier.h
//!   verifier_c <- the value-tracking fields of struct bpf_reg_state and the
//!                 functions of kernel/bpf/verifier.c / states.c that touch them
//! (Module names carry a _c suffix so that no Lean namespace clashes with a
//! parameter name such as `reg` or `tnum`; Aeneas emits `reg.f x` for a call
//! into module `reg`, which Lean reads as a field projection when a local
//! `reg` is in scope.)
//!   probes <- tiny functions exercising Rust constructs for Charon/Aeneas
#![forbid(unsafe_code)]
#![allow(non_snake_case, clippy::needless_return)]

pub mod tnum_c;
pub mod cnum_c;
pub mod verifier_c;
pub mod probes;
