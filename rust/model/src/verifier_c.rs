//! The value-tracking fields of `struct bpf_reg_state` (include/linux/bpf_verifier.h)
//! and the functions of kernel/bpf/verifier.c and kernel/bpf/states.c that read
//! or write them.
//!
//! Only the value-tracking fields are modelled: var_off, r64, r32, base, step.
//! The C functions take `struct bpf_reg_state *`; here they take `&mut BpfRegState`
//! (writes) or `&BpfRegState` (reads).  `__mark_reg_known` additionally clears
//! id/parent_id/map_uid and the pointer union in C; those fields do not exist here.

use crate::cnum_c::*;
use crate::tnum_c::*;

#[derive(Clone, Copy)]
#[cfg_attr(feature = "difftest", derive(PartialEq, Eq, Debug))]
pub struct BpfRegState {
    pub var_off: Tnum,
    pub r64: Cnum64,
    pub r32: Cnum32,
    /// The s64 value lies on base + step * k. Invariant: base < step.
    pub base: u16,
    pub step: u16,
}

/* include/linux/bpf_verifier.h accessors */

pub fn reg_smin(reg: &BpfRegState) -> i64 { cnum64_smin(reg.r64) }
pub fn reg_smax(reg: &BpfRegState) -> i64 { cnum64_smax(reg.r64) }
pub fn reg_umin(reg: &BpfRegState) -> u64 { cnum64_umin(reg.r64) }
pub fn reg_umax(reg: &BpfRegState) -> u64 { cnum64_umax(reg.r64) }
pub fn reg_s32_min(reg: &BpfRegState) -> i32 { cnum32_smin(reg.r32) }
pub fn reg_s32_max(reg: &BpfRegState) -> i32 { cnum32_smax(reg.r32) }
pub fn reg_u32_min(reg: &BpfRegState) -> u32 { cnum32_umin(reg.r32) }
pub fn reg_u32_max(reg: &BpfRegState) -> u32 { cnum32_umax(reg.r32) }

pub fn reg_set_srange32(reg: &mut BpfRegState, smin: i32, smax: i32) { reg.r32 = cnum32_from_srange(smin, smax); }
pub fn reg_set_urange32(reg: &mut BpfRegState, umin: u32, umax: u32) { reg.r32 = cnum32_from_urange(umin, umax); }
pub fn reg_set_srange64(reg: &mut BpfRegState, smin: i64, smax: i64) { reg.r64 = cnum64_from_srange(smin, smax); }
pub fn reg_set_urange64(reg: &mut BpfRegState, umin: u64, umax: u64) { reg.r64 = cnum64_from_urange(umin, umax); }

/// include/linux/count_zeros.h: `x ? __ffs(x) : BITS_PER_LONG` (BITS_PER_LONG = 64).
pub fn count_trailing_zeros(x: u64) -> u32 {
    x.trailing_zeros()
}

/* kernel/bpf/verifier.c: stride (base/step) helpers */

pub fn reg_step_reset(reg: &mut BpfRegState) {
    reg.base = 0;
    reg.step = 1;
}

/// C: `scalar_step_add(dst_reg, a, b)` is called as `scalar_step_add(dst, dst, &src)`,
/// i.e. `a` aliases `dst`.  Rust forbids `&mut` and `&` to the same object, so
/// `a` and `b` are taken by value (copies); the result is identical.
/// Precondition: reg.step != 0.
pub fn scalar_step_add(dst_reg: &mut BpfRegState, a: BpfRegState, b: BpfRegState) {
    let reg: BpfRegState;
    let amount: i64;

    if tnum_is_const(b.var_off) {
        reg = a;
        amount = b.var_off.value as i64;
    } else if tnum_is_const(a.var_off) {
        reg = b;
        amount = a.var_off.value as i64;
    } else {
        reg_step_reset(dst_reg);
        return;
    }

    /* Conservatively reset the stride if either wrap is possible. */
    if reg_smin(&reg).checked_add(amount).is_none() || reg_smax(&reg).checked_add(amount).is_none() {
        reg_step_reset(dst_reg);
        return;
    }

    dst_reg.base = ((reg.base as u32 + imod(amount, reg.step) as u32) % reg.step as u32) as u16;
    dst_reg.step = reg.step;
}

pub fn scalar_step_scale(dst_reg: &mut BpfRegState, amount: u64) {
    let step: u16;

    /* check_mul_overflow(dst_reg->step, amount, &step): product must fit u16 */
    let prod = (dst_reg.step as u64).checked_mul(amount);
    let step_fits = match prod {
        Some(p) => p <= u16::MAX as u64,
        None => false,
    };
    if amount == 0
        || !step_fits
        || reg_smin(dst_reg).checked_mul(amount as i64).is_none()
        || reg_smax(dst_reg).checked_mul(amount as i64).is_none()
    {
        reg_step_reset(dst_reg);
        return;
    }
    step = match prod { Some(p) => p as u16, None => 0 };
    dst_reg.base = (dst_reg.base as u64 * amount) as u16;
    dst_reg.step = step;
}

/// Requires 0 < bits < 64.
pub fn reg_step_check_unsigned(reg: &mut BpfRegState, bits: u32) {
    if reg_umax(reg) >= (1u64 << bits) {
        reg_step_reset(reg);
    }
}

pub fn scalar_step_mul(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    if tnum_is_const(src_reg.var_off) {
        scalar_step_scale(dst_reg, src_reg.var_off.value);
    } else {
        reg_step_reset(dst_reg);
    }
}

pub fn scalar_step_lsh(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let amount: u64 = src_reg.var_off.value;

    if tnum_is_const(src_reg.var_off) && amount < 64 {
        scalar_step_scale(dst_reg, 1u64 << amount);
    } else {
        reg_step_reset(dst_reg);
    }
}

/* kernel/bpf/verifier.c: marking helpers */

/// This helper doesn't clear reg->id
pub fn ___mark_reg_known(reg: &mut BpfRegState, imm: u64) {
    reg.var_off = tnum_const(imm);
    reg.r64 = cnum64_from_urange(imm, imm);
    reg.r32 = cnum32_from_urange(imm as u32, imm as u32);
    reg_step_reset(reg);
}

/// C also memsets the non-value fields and clears id/parent_id/map_uid.
pub fn __mark_reg_known(reg: &mut BpfRegState, imm: u64) {
    ___mark_reg_known(reg, imm);
}

pub fn __mark_reg32_known(reg: &mut BpfRegState, imm: u64) {
    reg.var_off = tnum_const_subreg(reg.var_off, imm as u32);
    reg.r32 = cnum32_from_urange(imm as u32, imm as u32);
}

pub fn __mark_reg32_unbounded(reg: &mut BpfRegState) {
    reg.r32 = CNUM32_UNBOUNDED;
}

pub fn __mark_reg64_unbounded(reg: &mut BpfRegState) {
    reg.r64 = CNUM64_UNBOUNDED;
}

/// Reset the min/max bounds of a register
pub fn __mark_reg_unbounded(reg: &mut BpfRegState) {
    __mark_reg64_unbounded(reg);
    __mark_reg32_unbounded(reg);
}

pub fn reset_reg64_and_tnum(reg: &mut BpfRegState) {
    __mark_reg64_unbounded(reg);
    reg.var_off = tnum_unknown;
}

pub fn reset_reg32_and_tnum(reg: &mut BpfRegState) {
    __mark_reg32_unbounded(reg);
    reg.var_off = tnum_unknown;
}

/* kernel/bpf/verifier.c: reg_bounds_sync() and its helpers */

pub fn cnum32_from_tnum(tnum: Tnum) -> Cnum32 {
    let tnum = tnum_subreg(tnum);
    /* C: `tnum.mask & S32_MIN` sign-extends S32_MIN to u64; `as u64` does the same. */
    if (tnum.mask & (S32_MIN as u64)) != 0 || (tnum.value & (S32_MIN as u64)) != 0 {
        /* min signed is max(sign bit) | min(other bits) */
        /* max signed is min(sign bit) | max(other bits) */
        cnum32_from_srange(
            (tnum.value | (tnum.mask & (S32_MIN as u64))) as i32,
            (tnum.value | (tnum.mask & (S32_MAX as u64))) as i32,
        )
    } else {
        cnum32_from_urange(tnum.value as u32, (tnum.value | tnum.mask) as u32)
    }
}

pub fn cnum64_from_tnum(tnum: Tnum) -> Cnum64 {
    if (tnum.mask & (S64_MIN as u64)) != 0 || (tnum.value & (S64_MIN as u64)) != 0 {
        cnum64_from_srange(
            (tnum.value | (tnum.mask & (S64_MIN as u64))) as i64,
            (tnum.value | (tnum.mask & (S64_MAX as u64))) as i64,
        )
    } else {
        cnum64_from_urange(tnum.value, tnum.value | tnum.mask)
    }
}

pub fn __update_reg32_bounds(reg: &mut BpfRegState) {
    let t = cnum32_from_tnum(reg.var_off);
    cnum32_intersect_with(&mut reg.r32, t);
}

pub fn __update_reg64_bounds(reg: &mut BpfRegState) {
    let tnum_next: u64;
    let tmax: u64;
    let umin_in_tnum: bool;

    let t = cnum64_from_tnum(reg.var_off);
    cnum64_intersect_with(&mut reg.r64, t);

    /* Check if u64 and tnum overlap in a single value */
    tnum_next = tnum_step(reg.var_off, reg_umin(reg));
    umin_in_tnum = (reg_umin(reg) & !reg.var_off.mask) == reg.var_off.value;
    tmax = reg.var_off.value | reg.var_off.mask;
    if umin_in_tnum && tnum_next > reg_umax(reg) {
        /* The u64 range and the tnum only overlap in umin. */
        let v = reg_umin(reg);
        ___mark_reg_known(reg, v);
    } else if !umin_in_tnum && tnum_next == tmax {
        /* ... only overlap in tmax. */
        ___mark_reg_known(reg, tmax);
    } else if !umin_in_tnum && tnum_next <= reg_umax(reg) && tnum_step(reg.var_off, tnum_next) > reg_umax(reg) {
        /* ... only overlap in between umin (excluded) and umax. */
        ___mark_reg_known(reg, tnum_next);
    }
}

pub fn __update_reg_bounds(reg: &mut BpfRegState) {
    __update_reg32_bounds(reg);
    __update_reg64_bounds(reg);
}

pub fn deduce_bounds_32_from_64(reg: &mut BpfRegState) {
    let t = cnum32_from_cnum64(reg.r64);
    cnum32_intersect_with(&mut reg.r32, t);
}

pub fn deduce_bounds_64_from_32(reg: &mut BpfRegState) {
    reg.r64 = cnum64_cnum32_intersect(reg.r64, reg.r32);
}

pub fn __reg_deduce_bounds(reg: &mut BpfRegState) {
    deduce_bounds_32_from_64(reg);
    deduce_bounds_64_from_32(reg);
}

/// Attempts to improve var_off based on unsigned min/max information.
/// Precondition: reg.step != 0 (else C shifts by 64).
pub fn __reg_bound_offset(reg: &mut BpfRegState) {
    let var64_off = tnum_intersect(reg.var_off, tnum_range(reg_umin(reg), reg_umax(reg)));
    let var32_off = tnum_intersect(
        tnum_subreg(var64_off),
        tnum_range(reg_u32_min(reg) as u64, reg_u32_max(reg) as u64),
    );
    let trailing_zero_bits: u32;
    let base: u16 = reg.base;
    let step: u16 = reg.step;

    reg.var_off = tnum_or(tnum_clear_subreg(var64_off), var32_off);

    if base == 0 {
        trailing_zero_bits = count_trailing_zeros(step as u64);
    } else {
        let tb = count_trailing_zeros(base as u64);
        let ts = count_trailing_zeros(step as u64);
        trailing_zero_bits = if tb < ts { tb } else { ts };
    }
    reg.var_off = tnum_and(reg.var_off, tnum_const(!0u64 << trailing_zero_bits));
}

pub fn __update_bounds_from_step(reg: &mut BpfRegState) {
    reg.r64 = cnum64_intersect_linear(reg.r64, reg.base, reg.step);
    deduce_bounds_32_from_64(reg);
}

pub fn range_bounds_violation(reg: &BpfRegState) -> bool {
    cnum32_is_empty(reg.r32) || cnum64_is_empty(reg.r64)
}

pub fn reg_bounds_sync(reg: &mut BpfRegState) {
    /* If the input reg_state is invalid, we can exit early */
    if range_bounds_violation(reg) {
        return;
    }
    /* We might have learned new bounds from the var_off. */
    __update_reg_bounds(reg);
    /* We might have learned something about the sign bit. */
    __reg_deduce_bounds(reg);
    __reg_deduce_bounds(reg);
    /* We might have learned some bits from the bounds. */
    __reg_bound_offset(reg);
    /* Intersecting with the old var_off might have improved our bounds slightly. */
    __update_reg_bounds(reg);
    /* base+step must be in sync with r64; place this as a final step. */
    __update_bounds_from_step(reg);
}

pub fn const_tnum_range_mismatch(reg: &BpfRegState) -> bool {
    if !tnum_is_const(reg.var_off) {
        return false;
    }

    !cnum64_is_const(reg.r64) || reg.r64.base != reg.var_off.value
}

pub fn const_tnum_range_mismatch_32(reg: &BpfRegState) -> bool {
    if !tnum_subreg_is_const(reg.var_off) {
        return false;
    }

    !cnum32_is_const(reg.r32) || reg.r32.base != tnum_subreg(reg.var_off).value as u32
}

/// C: `reg_bounds_sanity_check(env, reg, ctx)`.  The log message is dropped;
/// `env->test_reg_invariants` is a parameter.  Returns 0 or -EFAULT (-14).
/// The four checks of reg_bounds_sanity_check(), in its order (read-only helper so
/// that Aeneas does not thread the `&mut` register through the `||` chain).
pub fn reg_invariants_violated(reg: &BpfRegState) -> bool {
    range_bounds_violation(reg)
        || const_tnum_range_mismatch(reg)
        || const_tnum_range_mismatch_32(reg)
        || reg.step == 0
        || reg.base >= reg.step
}

pub fn reg_bounds_sanity_check(reg: &mut BpfRegState, test_reg_invariants: bool) -> i32 {
    if !reg_invariants_violated(reg) {
        return 0;
    }
    if test_reg_invariants {
        return -14;
    }
    __mark_reg_unbounded(reg);
    reg_step_reset(reg);
    0
}

/* kernel/bpf/verifier.c: width coercion */

/// BPF architecture zero extends alu32 ops into 64-bit registers
pub fn zext_32_to_64(reg: &mut BpfRegState) {
    reg_step_check_unsigned(reg, 32);
    reg.var_off = tnum_subreg(reg.var_off);
    let lo = reg_u32_min(reg) as u64;
    let hi = reg_u32_max(reg) as u64;
    reg_set_urange64(reg, lo, hi);
}

/// truncate register to smaller size (in bytes); must be called with size < 8
pub fn coerce_reg_to_size(reg: &mut BpfRegState, size: i32) {
    let mask: u64 = (1u64 << (size * 8)) - 1;

    reg_step_check_unsigned(reg, (size * 8) as u32);

    /* clear high bits in bit representation */
    reg.var_off = tnum_cast(reg.var_off, size as u8);

    /* fix arithmetic bounds */
    if (reg_umin(reg) & !mask) == (reg_umax(reg) & !mask) {
        let lo = reg_umin(reg) & mask;
        let hi = reg_umax(reg) & mask;
        reg_set_urange64(reg, lo, hi);
    } else {
        reg_set_urange64(reg, 0, mask);
    }

    if size < 4 {
        __mark_reg32_unbounded(reg);
    }

    reg_bounds_sync(reg);
}

/* kernel/bpf/verifier.c: scalar ALU transfer functions */

pub fn scalar32_min_max_add(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    dst_reg.r32 = cnum32_add(dst_reg.r32, src_reg.r32);
}

pub fn scalar_min_max_add(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    dst_reg.r64 = cnum64_add(dst_reg.r64, src_reg.r64);
}

pub fn scalar32_min_max_sub(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    dst_reg.r32 = cnum32_add(dst_reg.r32, cnum32_negate(src_reg.r32));
}

pub fn scalar_min_max_sub(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    dst_reg.r64 = cnum64_add(dst_reg.r64, cnum64_negate(src_reg.r64));
}

/// `min_array(array, 4)` from include/linux/minmax.h
fn min_array_s32(a: [i32; 4]) -> i32 {
    let mut e = a[3];
    let mut i: usize = 3;
    while i > 0 {
        i -= 1;
        if a[i] < e { e = a[i]; }
    }
    e
}

fn max_array_s32(a: [i32; 4]) -> i32 {
    let mut e = a[3];
    let mut i: usize = 3;
    while i > 0 {
        i -= 1;
        if a[i] > e { e = a[i]; }
    }
    e
}

fn min_array_s64(a: [i64; 4]) -> i64 {
    let mut e = a[3];
    let mut i: usize = 3;
    while i > 0 {
        i -= 1;
        if a[i] < e { e = a[i]; }
    }
    e
}

fn max_array_s64(a: [i64; 4]) -> i64 {
    let mut e = a[3];
    let mut i: usize = 3;
    while i > 0 {
        i -= 1;
        if a[i] > e { e = a[i]; }
    }
    e
}

pub fn scalar32_min_max_mul(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let mut smin: i32 = reg_s32_min(dst_reg);
    let mut smax: i32 = reg_s32_max(dst_reg);
    let mut umin: u32 = reg_u32_min(dst_reg);
    let mut umax: u32 = reg_u32_max(dst_reg);
    let mut tmp_prod: [i32; 4] = [0; 4];

    /* check_mul_overflow(umax, src.umax, &umax) || check_mul_overflow(umin, src.umin, &umin) */
    let mut overflow = false;
    match umax.checked_mul(reg_u32_max(src_reg)) {
        Some(p) => umax = p,
        None => overflow = true,
    }
    if !overflow {
        match umin.checked_mul(reg_u32_min(src_reg)) {
            Some(p) => umin = p,
            None => overflow = true,
        }
    }
    if overflow {
        /* Overflow possible, we know nothing */
        umin = 0;
        umax = U32_MAX;
    }

    let mut soverflow = false;
    let pairs: [(i32, i32); 4] = [
        (smin, reg_s32_min(src_reg)),
        (smin, reg_s32_max(src_reg)),
        (smax, reg_s32_min(src_reg)),
        (smax, reg_s32_max(src_reg)),
    ];
    let mut i: usize = 0;
    while i < 4 && !soverflow {
        match pairs[i].0.checked_mul(pairs[i].1) {
            Some(p) => tmp_prod[i] = p,
            None => soverflow = true,
        }
        i += 1;
    }
    if soverflow {
        /* Overflow possible, we know nothing */
        smin = S32_MIN;
        smax = S32_MAX;
    } else {
        smin = min_array_s32(tmp_prod);
        smax = max_array_s32(tmp_prod);
    }

    dst_reg.r32 = cnum32_intersect(cnum32_from_urange(umin, umax), cnum32_from_srange(smin, smax));
}

pub fn scalar_min_max_mul(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let mut smin: i64 = reg_smin(dst_reg);
    let mut smax: i64 = reg_smax(dst_reg);
    let mut umin: u64 = reg_umin(dst_reg);
    let mut umax: u64 = reg_umax(dst_reg);
    let mut tmp_prod: [i64; 4] = [0; 4];

    let mut overflow = false;
    match umax.checked_mul(reg_umax(src_reg)) {
        Some(p) => umax = p,
        None => overflow = true,
    }
    if !overflow {
        match umin.checked_mul(reg_umin(src_reg)) {
            Some(p) => umin = p,
            None => overflow = true,
        }
    }
    if overflow {
        umin = 0;
        umax = U64_MAX;
    }

    let mut soverflow = false;
    let pairs: [(i64, i64); 4] = [
        (smin, reg_smin(src_reg)),
        (smin, reg_smax(src_reg)),
        (smax, reg_smin(src_reg)),
        (smax, reg_smax(src_reg)),
    ];
    let mut i: usize = 0;
    while i < 4 && !soverflow {
        match pairs[i].0.checked_mul(pairs[i].1) {
            Some(p) => tmp_prod[i] = p,
            None => soverflow = true,
        }
        i += 1;
    }
    if soverflow {
        smin = S64_MIN;
        smax = S64_MAX;
    } else {
        smin = min_array_s64(tmp_prod);
        smax = max_array_s64(tmp_prod);
    }

    dst_reg.r64 = cnum64_intersect(cnum64_from_urange(umin, umax), cnum64_from_srange(smin, smax));
}

pub fn scalar32_min_max_and(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let src_known: bool = tnum_subreg_is_const(src_reg.var_off);
    let dst_known: bool = tnum_subreg_is_const(dst_reg.var_off);
    let var32_off: Tnum = tnum_subreg(dst_reg.var_off);
    let umax_val: u32 = reg_u32_max(src_reg);

    if src_known && dst_known {
        __mark_reg32_known(dst_reg, var32_off.value);
        return;
    }

    /* minimum from the var_off; maximum is the minimum of the operands' maxima */
    let dmax = reg_u32_max(dst_reg);
    reg_set_urange32(dst_reg, var32_off.value as u32, if dmax < umax_val { dmax } else { umax_val });
}

pub fn scalar_min_max_and(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let src_known: bool = tnum_is_const(src_reg.var_off);
    let dst_known: bool = tnum_is_const(dst_reg.var_off);
    let umax_val: u64 = reg_umax(src_reg);

    if src_known && dst_known {
        let v = dst_reg.var_off.value;
        __mark_reg_known(dst_reg, v);
        return;
    }

    let dmax = reg_umax(dst_reg);
    let lo = dst_reg.var_off.value;
    reg_set_urange64(dst_reg, lo, if dmax < umax_val { dmax } else { umax_val });

    /* We may learn something more from the var_off */
    __update_reg_bounds(dst_reg);
}

pub fn scalar32_min_max_or(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let src_known: bool = tnum_subreg_is_const(src_reg.var_off);
    let dst_known: bool = tnum_subreg_is_const(dst_reg.var_off);
    let var32_off: Tnum = tnum_subreg(dst_reg.var_off);
    let umin_val: u32 = reg_u32_min(src_reg);

    if src_known && dst_known {
        __mark_reg32_known(dst_reg, var32_off.value);
        return;
    }

    /* maximum from the var_off; minimum is the maximum of the operands' minima */
    let dmin = reg_u32_min(dst_reg);
    reg_set_urange32(
        dst_reg,
        if dmin > umin_val { dmin } else { umin_val },
        (var32_off.value | var32_off.mask) as u32,
    );
}

pub fn scalar_min_max_or(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let src_known: bool = tnum_is_const(src_reg.var_off);
    let dst_known: bool = tnum_is_const(dst_reg.var_off);
    let umin_val: u64 = reg_umin(src_reg);

    if src_known && dst_known {
        let v = dst_reg.var_off.value;
        __mark_reg_known(dst_reg, v);
        return;
    }

    let dmin = reg_umin(dst_reg);
    let hi = dst_reg.var_off.value | dst_reg.var_off.mask;
    reg_set_urange64(dst_reg, if dmin > umin_val { dmin } else { umin_val }, hi);

    /* We may learn something more from the var_off */
    __update_reg_bounds(dst_reg);
}

pub fn scalar32_min_max_xor(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let src_known: bool = tnum_subreg_is_const(src_reg.var_off);
    let dst_known: bool = tnum_subreg_is_const(dst_reg.var_off);
    let var32_off: Tnum = tnum_subreg(dst_reg.var_off);

    if src_known && dst_known {
        __mark_reg32_known(dst_reg, var32_off.value);
        return;
    }

    /* We get both minimum and maximum from the var32_off. */
    reg_set_urange32(dst_reg, var32_off.value as u32, (var32_off.value | var32_off.mask) as u32);
}

pub fn scalar_min_max_xor(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let src_known: bool = tnum_is_const(src_reg.var_off);
    let dst_known: bool = tnum_is_const(dst_reg.var_off);

    if src_known && dst_known {
        /* dst_reg->var_off.value has been updated earlier */
        let v = dst_reg.var_off.value;
        __mark_reg_known(dst_reg, v);
        return;
    }

    /* We get both minimum and maximum from the var_off. */
    let lo = dst_reg.var_off.value;
    let hi = dst_reg.var_off.value | dst_reg.var_off.mask;
    reg_set_urange64(dst_reg, lo, hi);
}

pub fn __scalar32_min_max_lsh(dst_reg: &mut BpfRegState, umin_val: u64, umax_val: u64) {
    /* If we might shift our top bit out, then we know nothing */
    if umax_val > 31 || (reg_u32_max(dst_reg) as u64) > 1u64 << (31 - umax_val) {
        reg_set_urange32(dst_reg, 0, U32_MAX);
    } else {
        /* We lose all sign bit information (except what we can pick up from var_off) */
        let lo = reg_u32_min(dst_reg) << umin_val;
        let hi = reg_u32_max(dst_reg) << umax_val;
        reg_set_urange32(dst_reg, lo, hi);
    }
}

/// Precondition (is_safe_to_compute_dst_reg_range): src is const and < 32.
pub fn scalar32_min_max_lsh(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let umax_val: u32 = reg_u32_max(src_reg);
    let umin_val: u32 = reg_u32_min(src_reg);
    /* u32 alu operation will zext upper bits */
    let subreg: Tnum = tnum_subreg(dst_reg.var_off);

    __scalar32_min_max_lsh(dst_reg, umin_val as u64, umax_val as u64);
    dst_reg.var_off = tnum_subreg(tnum_lshift(subreg, umin_val as u8));
    __mark_reg64_unbounded(dst_reg);
    __update_reg32_bounds(dst_reg);
}

pub fn __scalar64_min_max_lsh(dst_reg: &mut BpfRegState, umin_val: u64, umax_val: u64) {
    let u: Cnum64;
    let s: Cnum64;

    /* Special case <<32: sign extension pattern */
    if umin_val == 32 && umax_val == 32 {
        s = cnum64_from_srange((reg_s32_min(dst_reg) as i64) << 32, (reg_s32_max(dst_reg) as i64) << 32);
    } else {
        s = CNUM64_UNBOUNDED;
    }

    /* If we might shift our top bit out, then we know nothing */
    if reg_umax(dst_reg) > 1u64 << (63 - umax_val) {
        u = CNUM64_UNBOUNDED;
    } else {
        u = cnum64_from_urange(reg_umin(dst_reg) << umin_val, reg_umax(dst_reg) << umax_val);
    }

    dst_reg.r64 = cnum64_intersect(u, s);
}

/// Precondition: src is const and < 64.
pub fn scalar_min_max_lsh(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let umax_val: u64 = reg_umax(src_reg);
    let umin_val: u64 = reg_umin(src_reg);

    /* scalar64 calc uses 32bit unshifted bounds so must be called first */
    __scalar64_min_max_lsh(dst_reg, umin_val, umax_val);
    __scalar32_min_max_lsh(dst_reg, umin_val, umax_val);

    dst_reg.var_off = tnum_lshift(dst_reg.var_off, umin_val as u8);
    /* We may learn something more from the var_off */
    __update_reg_bounds(dst_reg);
}

/// Precondition: src is const and < 32.
pub fn scalar32_min_max_rsh(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let subreg: Tnum = tnum_subreg(dst_reg.var_off);
    let umax_val: u32 = reg_u32_max(src_reg);
    let umin_val: u32 = reg_u32_min(src_reg);

    dst_reg.var_off = tnum_rshift(subreg, umin_val as u8);
    let lo = reg_u32_min(dst_reg) >> umax_val;
    let hi = reg_u32_max(dst_reg) >> umin_val;
    reg_set_urange32(dst_reg, lo, hi);

    __mark_reg64_unbounded(dst_reg);
    __update_reg32_bounds(dst_reg);
}

/// Precondition: src is const and < 64.
pub fn scalar_min_max_rsh(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let umax_val: u64 = reg_umax(src_reg);
    let umin_val: u64 = reg_umin(src_reg);

    dst_reg.var_off = tnum_rshift(dst_reg.var_off, umin_val as u8);
    let lo = reg_umin(dst_reg) >> umax_val;
    let hi = reg_umax(dst_reg) >> umin_val;
    reg_set_urange64(dst_reg, lo, hi);

    __mark_reg32_unbounded(dst_reg);
    __update_reg_bounds(dst_reg);
}

/// Precondition: src is const and < 32.
pub fn scalar32_min_max_arsh(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let umin_val: u64 = reg_u32_min(src_reg) as u64;

    let lo = ((reg_s32_min(dst_reg) >> umin_val) as u32) as i32;
    let hi = ((reg_s32_max(dst_reg) >> umin_val) as u32) as i32;
    reg_set_srange32(dst_reg, lo, hi);

    dst_reg.var_off = tnum_arshift(tnum_subreg(dst_reg.var_off), umin_val as u8, 32);

    __mark_reg64_unbounded(dst_reg);
    __update_reg32_bounds(dst_reg);
}

/// Precondition: src is const and < 64.
pub fn scalar_min_max_arsh(dst_reg: &mut BpfRegState, src_reg: &BpfRegState) {
    let umin_val: u64 = reg_umin(src_reg);

    let lo = reg_smin(dst_reg) >> umin_val;
    let hi = reg_smax(dst_reg) >> umin_val;
    reg_set_srange64(dst_reg, lo, hi);

    dst_reg.var_off = tnum_arshift(dst_reg.var_off, umin_val as u8, 64);

    __mark_reg32_unbounded(dst_reg);
    __update_reg_bounds(dst_reg);
}

/* kernel/bpf/states.c: state pruning comparison */

/// check %cur's range satisfies %old's.  Precondition: old.step != 0.
pub fn range_within(old: &BpfRegState, cur: &BpfRegState) -> bool {
    if !cnum64_is_subset(old.r64, cur.r64) || !cnum32_is_subset(old.r32, cur.r32) {
        return false;
    }

    if old.step <= 1 {
        return true;
    }

    if cnum64_is_const(cur.r64) {
        return imod(cnum64_smin(cur.r64), old.step) == old.base;
    }

    /* C: u16 operands promote to int, so the difference is signed and '%' truncates. */
    cur.step % old.step == 0 && (cur.base as i32 - old.base as i32) % old.step as i32 == 0
}
