//! FFI mirror of the kernel structs and the C entry points.
#![allow(non_camel_case_types, dead_code)]
use bpf_model::cnum_c::{Cnum32, Cnum64};
use bpf_model::tnum_c::Tnum;
use bpf_model::verifier_c::BpfRegState;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct tnum { pub value: u64, pub mask: u64 }
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct cnum32 { pub base: u32, pub size: u32 }
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct cnum64 { pub base: u64, pub size: u64 }

/// struct bpf_reg_state as laid out by harness/shim/linux/bpf_verifier.h
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct bpf_reg_state {
    pub type_: u32,
    pub delta: i32,
    pub raw: [u64; 2],
    pub var_off: tnum,
    pub r64: cnum64,
    pub r32: cnum32,
    pub base: u16,
    pub step: u16,
    pub id: u32,
    pub parent_id: u32,
    pub bits: u32,
}

impl From<Tnum> for tnum { fn from(t: Tnum) -> tnum { tnum { value: t.value, mask: t.mask } } }
impl From<tnum> for Tnum { fn from(t: tnum) -> Tnum { Tnum { value: t.value, mask: t.mask } } }
impl From<Cnum32> for cnum32 { fn from(c: Cnum32) -> cnum32 { cnum32 { base: c.base, size: c.size } } }
impl From<cnum32> for Cnum32 { fn from(c: cnum32) -> Cnum32 { Cnum32 { base: c.base, size: c.size } } }
impl From<Cnum64> for cnum64 { fn from(c: Cnum64) -> cnum64 { cnum64 { base: c.base, size: c.size } } }
impl From<cnum64> for Cnum64 { fn from(c: cnum64) -> Cnum64 { Cnum64 { base: c.base, size: c.size } } }
impl From<BpfRegState> for bpf_reg_state {
    fn from(r: BpfRegState) -> bpf_reg_state {
        bpf_reg_state {
            type_: 1, delta: 0, raw: [0; 2],
            var_off: r.var_off.into(), r64: r.r64.into(), r32: r.r32.into(),
            base: r.base, step: r.step, id: 0, parent_id: 0, bits: 0,
        }
    }
}
impl From<bpf_reg_state> for BpfRegState {
    fn from(r: bpf_reg_state) -> BpfRegState {
        BpfRegState { var_off: r.var_off.into(), r64: r.r64.into(), r32: r.r32.into(), base: r.base, step: r.step }
    }
}

extern "C" {
    pub fn k_sizeof_reg() -> usize;
    pub fn k_offsetof_var_off() -> usize;
    pub fn k_offsetof_base() -> usize;
    pub fn k_offsetof_id() -> usize;

    // tnum.c
    pub fn tnum_const(value: u64) -> tnum;
    pub fn tnum_range(min: u64, max: u64) -> tnum;
    pub fn tnum_lshift(a: tnum, shift: u8) -> tnum;
    pub fn tnum_rshift(a: tnum, shift: u8) -> tnum;
    pub fn tnum_arshift(a: tnum, min_shift: u8, insn_bitness: u8) -> tnum;
    pub fn tnum_add(a: tnum, b: tnum) -> tnum;
    pub fn tnum_sub(a: tnum, b: tnum) -> tnum;
    pub fn tnum_neg(a: tnum) -> tnum;
    pub fn tnum_and(a: tnum, b: tnum) -> tnum;
    pub fn tnum_or(a: tnum, b: tnum) -> tnum;
    pub fn tnum_xor(a: tnum, b: tnum) -> tnum;
    pub fn tnum_mul(a: tnum, b: tnum) -> tnum;
    pub fn tnum_overlap(a: tnum, b: tnum) -> bool;
    pub fn tnum_intersect(a: tnum, b: tnum) -> tnum;
    pub fn tnum_union(a: tnum, b: tnum) -> tnum;
    pub fn tnum_cast(a: tnum, size: u8) -> tnum;
    pub fn tnum_is_aligned(a: tnum, size: u64) -> bool;
    pub fn tnum_in(a: tnum, b: tnum) -> bool;
    pub fn tnum_sbin(s: *mut u8, size: usize, a: tnum) -> i32;
    pub fn tnum_subreg(a: tnum) -> tnum;
    pub fn tnum_clear_subreg(a: tnum) -> tnum;
    pub fn tnum_with_subreg(reg: tnum, subreg: tnum) -> tnum;
    pub fn tnum_const_subreg(a: tnum, value: u32) -> tnum;
    pub fn tnum_bswap16(a: tnum) -> tnum;
    pub fn tnum_bswap32(a: tnum) -> tnum;
    pub fn tnum_bswap64(a: tnum) -> tnum;
    pub fn tnum_step(t: tnum, z: u64) -> u64;
    pub fn tnum_alignment(a: tnum) -> u32;

    // cnum.c (32)
    pub fn cnum32_from_urange(min: u32, max: u32) -> cnum32;
    pub fn cnum32_from_srange(min: i32, max: i32) -> cnum32;
    pub fn cnum32_umin(c: cnum32) -> u32;
    pub fn cnum32_umax(c: cnum32) -> u32;
    pub fn cnum32_smin(c: cnum32) -> i32;
    pub fn cnum32_smax(c: cnum32) -> i32;
    pub fn cnum32_union(a: cnum32, b: cnum32) -> cnum32;
    pub fn cnum32_intersect(a: cnum32, b: cnum32) -> cnum32;
    pub fn cnum32_intersect_with(dst: *mut cnum32, src: cnum32);
    pub fn cnum32_intersect_with_urange(dst: *mut cnum32, min: u32, max: u32);
    pub fn cnum32_intersect_with_srange(dst: *mut cnum32, min: i32, max: i32);
    pub fn cnum32_contains(c: cnum32, v: u32) -> bool;
    pub fn cnum32_is_const(c: cnum32) -> bool;
    pub fn cnum32_is_empty(c: cnum32) -> bool;
    pub fn cnum32_add(a: cnum32, b: cnum32) -> cnum32;
    pub fn cnum32_negate(a: cnum32) -> cnum32;
    pub fn cnum32_is_subset(outer: cnum32, inner: cnum32) -> bool;
    // cnum.c (64)
    pub fn cnum64_from_urange(min: u64, max: u64) -> cnum64;
    pub fn cnum64_from_srange(min: i64, max: i64) -> cnum64;
    pub fn cnum64_umin(c: cnum64) -> u64;
    pub fn cnum64_umax(c: cnum64) -> u64;
    pub fn cnum64_smin(c: cnum64) -> i64;
    pub fn cnum64_smax(c: cnum64) -> i64;
    pub fn cnum64_union(a: cnum64, b: cnum64) -> cnum64;
    pub fn cnum64_intersect(a: cnum64, b: cnum64) -> cnum64;
    pub fn cnum64_intersect_with(dst: *mut cnum64, src: cnum64);
    pub fn cnum64_intersect_with_urange(dst: *mut cnum64, min: u64, max: u64);
    pub fn cnum64_intersect_with_srange(dst: *mut cnum64, min: i64, max: i64);
    pub fn cnum64_contains(c: cnum64, v: u64) -> bool;
    pub fn cnum64_is_const(c: cnum64) -> bool;
    pub fn cnum64_is_empty(c: cnum64) -> bool;
    pub fn cnum64_add(a: cnum64, b: cnum64) -> cnum64;
    pub fn cnum64_negate(a: cnum64) -> cnum64;
    pub fn cnum64_is_subset(outer: cnum64, inner: cnum64) -> bool;
    pub fn cnum32_from_cnum64(c: cnum64) -> cnum32;
    pub fn cnum64_cnum32_intersect(a: cnum64, b: cnum32) -> cnum64;
    pub fn cnum64_intersect_linear(input: cnum64, base: u16, step: u16) -> cnum64;
    pub fn k_imod(v: i64, step: u16) -> u16;

    // verifier.c / states.c via wrappers
    pub fn k_reg_bounds_sync(r: *mut bpf_reg_state);
    pub fn k___update_reg_bounds(r: *mut bpf_reg_state);
    pub fn k___update_reg32_bounds(r: *mut bpf_reg_state);
    pub fn k___update_reg64_bounds(r: *mut bpf_reg_state);
    pub fn k___reg_deduce_bounds(r: *mut bpf_reg_state);
    pub fn k___reg_bound_offset(r: *mut bpf_reg_state);
    pub fn k___update_bounds_from_step(r: *mut bpf_reg_state);
    pub fn k_zext_32_to_64(r: *mut bpf_reg_state);
    pub fn k_scalar32_min_max_add(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_min_max_add(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar32_min_max_sub(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_min_max_sub(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar32_min_max_mul(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_min_max_mul(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar32_min_max_and(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_min_max_and(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar32_min_max_or(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_min_max_or(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar32_min_max_xor(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_min_max_xor(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar32_min_max_lsh(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_min_max_lsh(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar32_min_max_rsh(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_min_max_rsh(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar32_min_max_arsh(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_min_max_arsh(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_step_mul(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_step_lsh(d: *mut bpf_reg_state, s: *mut bpf_reg_state);
    pub fn k_scalar_step_add(d: *mut bpf_reg_state, a: *const bpf_reg_state, b: *const bpf_reg_state);
    pub fn k_scalar_step_scale(d: *mut bpf_reg_state, amount: u64);
    pub fn k_coerce_reg_to_size(r: *mut bpf_reg_state, size: i32);
    pub fn k_range_within(o: *const bpf_reg_state, c: *const bpf_reg_state) -> bool;
    pub fn k_range_bounds_violation(r: *mut bpf_reg_state) -> bool;
    pub fn k_const_tnum_range_mismatch(r: *mut bpf_reg_state) -> bool;
    pub fn k_const_tnum_range_mismatch_32(r: *mut bpf_reg_state) -> bool;
    pub fn k_cnum32_from_tnum(t: tnum) -> cnum32;
    pub fn k_cnum64_from_tnum(t: tnum) -> cnum64;
}
