//! Tiny functions probing Rust constructs for Charon/Aeneas, one per construct
//! named in PROMPT-phase0.md task 5, where the port itself does not already
//! exercise it in isolation.
#![allow(dead_code)]

pub fn probe_wrapping_add(a: u64, b: u64) -> u64 { a.wrapping_add(b) }
pub fn probe_wrapping_sub(a: u64, b: u64) -> u64 { a.wrapping_sub(b) }
pub fn probe_wrapping_mul(a: u64, b: u64) -> u64 { a.wrapping_mul(b) }
pub fn probe_wrapping_neg(a: u64) -> u64 { a.wrapping_neg() }

pub fn probe_checked_add(a: i64, b: i64) -> bool { a.checked_add(b).is_some() }
pub fn probe_checked_mul(a: i32, b: i32) -> i32 {
    match a.checked_mul(b) {
        Some(p) => p,
        None => 0,
    }
}
pub fn probe_overflowing_add(a: u32, b: u32) -> (u32, bool) { a.overflowing_add(b) }

pub fn probe_leading_zeros(x: u64) -> u32 { x.leading_zeros() }
pub fn probe_trailing_zeros(x: u64) -> u32 { x.trailing_zeros() }

/// shift by a variable amount with the C guard mirrored
pub fn probe_var_shift(x: u64, n: u8) -> u64 {
    if n > 63 { 0 } else { x << n }
}
pub fn probe_var_shift_u32_by_u64(x: u32, n: u64) -> u32 {
    if n > 31 { 0 } else { x << n }
}

pub fn probe_cast_i32_u32(x: i32) -> u32 { x as u32 }
pub fn probe_cast_u32_i32(x: u32) -> i32 { x as i32 }
pub fn probe_cast_i32_u64(x: i32) -> u64 { x as u64 }
pub fn probe_cast_u64_i32(x: u64) -> i32 { x as i32 }
pub fn probe_cast_i64_u64(x: i64) -> u64 { x as u64 }
pub fn probe_cast_u64_u32(x: u64) -> u32 { x as u32 }
pub fn probe_cast_u32_u64(x: u32) -> u64 { x as u64 }
pub fn probe_cast_i32_i64(x: i32) -> i64 { x as i64 }

pub fn probe_min_method(a: u64, b: u64) -> u64 { a.min(b) }
pub fn probe_max_fn(a: i64, b: i64) -> i64 { core::cmp::max(a, b) }
pub fn probe_min_if(a: u64, b: u64) -> u64 { if a < b { a } else { b } }

/// a 64-iteration loop
pub fn probe_loop64(x: u64) -> u32 {
    let mut i: u32 = 0;
    let mut n: u32 = 0;
    while i < 64 {
        if (x >> i) & 1 != 0 { n += 1; }
        i += 1;
    }
    n
}

pub fn probe_early_return(x: u64) -> u64 {
    if x == 0 { return 1; }
    if x == 1 { return 2; }
    x * 2
}

#[derive(Clone, Copy)]
pub enum Op { Add, Sub, And, Or }

pub fn probe_match_enum(op: Op, a: u64, b: u64) -> u64 {
    match op {
        Op::Add => a.wrapping_add(b),
        Op::Sub => a.wrapping_sub(b),
        Op::And => a & b,
        Op::Or => a | b,
    }
}

#[derive(Clone, Copy)]
pub struct Pair { pub lo: u64, pub hi: u64 }

pub fn probe_struct_update_mut(p: &mut Pair, d: u64) {
    p.lo = p.lo.wrapping_add(d);
    if p.hi < p.lo { p.hi = p.lo; }
}

/// bool guard read through a shared reference (Aeneas issue #1347 shape)
pub fn probe_bool_guard_ref(flag: &bool, x: u64) -> u64 {
    let f = *flag;
    let y = if f { x } else { 0 };
    if f { y + 1 } else { y }
}

pub fn probe_swap_bytes(x: u16) -> u16 { x.swap_bytes() }
pub fn probe_rem_i64(v: i64, s: u16) -> i32 { (v % (s as i64)) as i32 }
pub fn probe_array_index(a: [i32; 4], i: usize) -> i32 { if i < 4 { a[i] } else { 0 } }
pub fn probe_slice_write(s: &mut [u8], i: usize) { if i < s.len() { s[i] = 1; } }
