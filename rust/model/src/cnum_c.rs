//! Port of kernel/bpf/cnum.c, kernel/bpf/cnum_defs.h (instantiated for T=32
//! and T=64, so every template function exists twice, exactly as in C) and
//! include/linux/cnum.h, plus imod() from include/linux/bpf_verifier.h.
//!
//! The C template is `#define T 32 / #include "cnum_defs.h"`; here the same
//! text is a macro_rules! body instantiated twice.  Every identifier that the
//! C derives with __PASTE is passed explicitly.

/// struct cnum32 { u32 base; u32 size; }
#[derive(Clone, Copy)]
#[cfg_attr(feature = "difftest", derive(PartialEq, Eq, Debug))]
pub struct Cnum32 {
    pub base: u32,
    pub size: u32,
}

/// struct cnum64 { u64 base; u64 size; }
#[derive(Clone, Copy)]
#[cfg_attr(feature = "difftest", derive(PartialEq, Eq, Debug))]
pub struct Cnum64 {
    pub base: u64,
    pub size: u64,
}

pub const U32_MAX: u32 = u32::MAX;
pub const S32_MAX: i32 = i32::MAX;
pub const S32_MIN: i32 = i32::MIN;
pub const U64_MAX: u64 = u64::MAX;
pub const S64_MAX: i64 = i64::MAX;
pub const S64_MIN: i64 = i64::MIN;

pub const CNUM32_UNBOUNDED: Cnum32 = Cnum32 { base: 0, size: U32_MAX };
pub const CNUM32_EMPTY: Cnum32 = Cnum32 { base: U32_MAX, size: U32_MAX };
pub const CNUM64_UNBOUNDED: Cnum64 = Cnum64 { base: 0, size: U64_MAX };
pub const CNUM64_EMPTY: Cnum64 = Cnum64 { base: U64_MAX, size: U64_MAX };

/// include/linux/bpf_verifier.h: mathematical modulo normalised to [0, step).
/// Precondition: step != 0 (C: division by zero otherwise).
pub fn imod(v: i64, step: u16) -> u16 {
    /* div_s64_rem(v, step, &rem): rem = v % step with C truncation, as s32 */
    let rem: i32 = (v % (step as i64)) as i32;
    if rem < 0 {
        (rem + step as i32) as u16
    } else {
        rem as u16
    }
}

macro_rules! cnum_defs {
    ($cnum_t:ident, $ut:ty, $st:ty, $UT_MAX:expr, $ST_MAX:expr, $ST_MIN:expr, $EMPTY:expr,
     $from_urange:ident, $from_srange:ident, $urange_overflow:ident, $umin:ident, $umax:ident,
     $srange_overflow:ident, $smin:ident, $smax:ident, $intersect:ident, $intersect_with:ident,
     $intersect_with_urange:ident, $intersect_with_srange:ident, $normalize:ident, $union:ident,
     $add:ident, $negate:ident, $is_empty:ident, $contains:ident, $is_const:ident, $is_subset:ident) => {

        pub fn $from_urange(min: $ut, max: $ut) -> $cnum_t {
            $cnum_t { base: min, size: max.wrapping_sub(min) }
        }

        pub fn $from_srange(min: $st, max: $st) -> $cnum_t {
            let size: $ut = (max as $ut).wrapping_sub(min as $ut);
            let base: $ut = if size == $UT_MAX { 0 } else { min as $ut };

            $cnum_t { base, size }
        }

        /// True if this cnum represents two unsigned ranges. Caller ensures !is_empty.
        pub fn $urange_overflow(cnum: $cnum_t) -> bool {
            /* Same as cnum.base + cnum.size > UT_MAX but avoids overflow */
            cnum.size > $UT_MAX - cnum.base
        }

        pub fn $umin(cnum: $cnum_t) -> $ut {
            if $urange_overflow(cnum) { 0 } else { cnum.base }
        }

        pub fn $umax(cnum: $cnum_t) -> $ut {
            if $urange_overflow(cnum) { $UT_MAX } else { cnum.base + cnum.size }
        }

        /// True if this cnum represents two signed ranges. Caller ensures !is_empty.
        pub fn $srange_overflow(cnum: $cnum_t) -> bool {
            $contains(cnum, $ST_MAX as $ut) && $contains(cnum, $ST_MIN as $ut)
        }

        pub fn $smin(cnum: $cnum_t) -> $st {
            if $srange_overflow(cnum) { $ST_MIN } else { cnum.base as $st }
        }

        pub fn $smax(cnum: $cnum_t) -> $st {
            if $srange_overflow(cnum) { $ST_MAX } else { cnum.base.wrapping_add(cnum.size) as $st }
        }

        /// Possibly empty intersection; over-approximates when the arcs meet twice.
        pub fn $intersect(a: $cnum_t, b: $cnum_t) -> $cnum_t {
            if $is_empty(a) || $is_empty(b) {
                return $EMPTY;
            }

            /* if (a.base > b.base) swap(a, b); */
            let (a, b) = if a.base > b.base { (b, a) } else { (a, b) };

            /* Rotate frame of reference such that a.base is 0. */
            let dbase: $ut = b.base - a.base;
            let b1 = $cnum_t { base: dbase, size: b.size };
            if $urange_overflow(b1) {
                if b1.base <= a.size {
                    /* two disjoint arcs: over-approximate */
                    return if a.size <= b.size { a } else { b };
                } else {
                    /* Only 'b' tail intersects 'a'. */
                    let tail: $ut = b1.base.wrapping_add(b1.size);
                    return $cnum_t {
                        base: a.base,
                        size: if a.size < tail { a.size } else { tail },
                    };
                }
            } else if a.size >= b1.base {
                let rest: $ut = a.size - dbase;
                return $cnum_t {
                    base: b.base,
                    size: if rest < b.size { rest } else { b.size },
                };
            } else {
                return $EMPTY;
            }
        }

        pub fn $intersect_with(dst: &mut $cnum_t, src: $cnum_t) {
            *dst = $intersect(*dst, src);
        }

        pub fn $intersect_with_urange(dst: &mut $cnum_t, min: $ut, max: $ut) {
            $intersect_with(dst, $from_urange(min, max));
        }

        pub fn $intersect_with_srange(dst: &mut $cnum_t, min: $st, max: $st) {
            $intersect_with(dst, $from_srange(min, max));
        }

        pub fn $normalize(cnum: $cnum_t) -> $cnum_t {
            let mut cnum = cnum;
            if cnum.size == $UT_MAX {
                cnum.base = 0;
            }
            cnum
        }

        /// Smallest arc containing both 'a' and 'b'; ties broken by smaller base.
        pub fn $union(a: $cnum_t, b: $cnum_t) -> $cnum_t {
            if $is_empty(a) {
                return b;
            }
            if $is_empty(b) {
                return a;
            }

            let b1 = $normalize($cnum_t { base: b.base.wrapping_sub(a.base), size: b.size });
            let b1_end: $ut = b1.base.wrapping_add(b1.size);
            let end: $ut = if a.size > b1_end { a.size } else { b1_end };

            if $urange_overflow(b1) {
                /* a1 reaches b1's main arc: together they cover the circle. */
                if b1.base <= a.size {
                    return $cnum_t { base: 0, size: $UT_MAX };
                }
                /* Extend b1's tail through a1's end, then rotate back. */
                return $normalize($cnum_t { base: b.base, size: end.wrapping_sub(b1.base) });
            }

            let mut ab = $cnum_t { base: a.base, size: end };
            if b1.base <= a.size {
                return $normalize(ab);
            }

            /* The arcs are disjoint; ba is the other possible covering arc. */
            let ba = $cnum_t { base: b.base, size: a.size.wrapping_sub(b1.base) };
            if ba.size < ab.size || (ba.size == ab.size && ba.base < ab.base) {
                ab = ba;
            }

            $normalize(ab)
        }

        pub fn $add(a: $cnum_t, b: $cnum_t) -> $cnum_t {
            if $is_empty(a) || $is_empty(b) {
                return $EMPTY;
            }
            if a.size > $UT_MAX - b.size {
                $cnum_t { base: 0, size: $UT_MAX }
            } else {
                $normalize($cnum_t { base: a.base.wrapping_add(b.base), size: a.size + b.size })
            }
        }

        pub fn $negate(a: $cnum_t) -> $cnum_t {
            if $is_empty(a) {
                return $EMPTY;
            }
            $normalize($cnum_t { base: a.base.wrapping_add(a.size).wrapping_neg(), size: a.size })
        }

        pub fn $is_empty(cnum: $cnum_t) -> bool {
            cnum.base == $EMPTY.base && cnum.size == $EMPTY.size
        }

        pub fn $contains(cnum: $cnum_t, v: $ut) -> bool {
            !$is_empty(cnum) && v.wrapping_sub(cnum.base) <= cnum.size
        }

        pub fn $is_const(cnum: $cnum_t) -> bool {
            cnum.size == 0
        }

        pub fn $is_subset(bigger: $cnum_t, smaller: $cnum_t) -> bool {
            let mut bigger = bigger;
            let mut smaller = smaller;
            if $is_empty(smaller) {
                return true;
            }
            if $is_empty(bigger) {
                return false;
            }
            /* rotate both arcs such that 'bigger' starts at origin */
            smaller.base = smaller.base.wrapping_sub(bigger.base);
            bigger.base = 0;
            if $urange_overflow(smaller) && bigger.size < $UT_MAX {
                return false;
            }
            smaller.base.wrapping_add(smaller.size) <= bigger.size
        }
    };
}

cnum_defs!(Cnum32, u32, i32, U32_MAX, S32_MAX, S32_MIN, CNUM32_EMPTY,
    cnum32_from_urange, cnum32_from_srange, cnum32_urange_overflow, cnum32_umin, cnum32_umax,
    cnum32_srange_overflow, cnum32_smin, cnum32_smax, cnum32_intersect, cnum32_intersect_with,
    cnum32_intersect_with_urange, cnum32_intersect_with_srange, cnum32_normalize, cnum32_union,
    cnum32_add, cnum32_negate, cnum32_is_empty, cnum32_contains, cnum32_is_const, cnum32_is_subset);

cnum_defs!(Cnum64, u64, i64, U64_MAX, S64_MAX, S64_MIN, CNUM64_EMPTY,
    cnum64_from_urange, cnum64_from_srange, cnum64_urange_overflow, cnum64_umin, cnum64_umax,
    cnum64_srange_overflow, cnum64_smin, cnum64_smax, cnum64_intersect, cnum64_intersect_with,
    cnum64_intersect_with_urange, cnum64_intersect_with_srange, cnum64_normalize, cnum64_union,
    cnum64_add, cnum64_negate, cnum64_is_empty, cnum64_contains, cnum64_is_const, cnum64_is_subset);

/* kernel/bpf/cnum.c, the non-template part */

pub fn cnum32_from_cnum64(cnum: Cnum64) -> Cnum32 {
    if cnum64_is_empty(cnum) {
        return CNUM32_EMPTY;
    }

    if cnum.size >= U32_MAX as u64 {
        Cnum32 { base: 0, size: U32_MAX }
    } else {
        Cnum32 { base: cnum.base as u32, size: cnum.size as u32 }
    }
}

/// Tighten 'a' using the knowledge that (u32)v is in 'b' for every v in 'a'.
pub fn cnum64_cnum32_intersect(a: Cnum64, b: Cnum32) -> Cnum64 {
    let b1 = Cnum32 { base: b.base.wrapping_sub(a.base as u32), size: b.size };
    let mut t = a;
    let mut d: u64;
    let b1_max: u64;

    if cnum64_is_empty(a) || cnum32_is_empty(b) {
        return CNUM64_EMPTY;
    }

    if cnum32_urange_overflow(b1) {
        /* (u32)b1.base + (u32)b1.size: 32-bit wrap is fine and necessary */
        b1_max = b1.base.wrapping_add(b1.size) as u64;
        if (a.size as u32) as u64 > b1_max && (a.size as u32) < b1.base {
            d = (a.size as u32) as u64 - b1_max;
            t.size -= d;
        } else {
            /* No adjustments possible */
        }
    } else {
        if t.size < b1.base as u64 {
            return CNUM64_EMPTY;
        }
        t.base = t.base.wrapping_add(b1.base as u64);
        t.size -= b1.base as u64;
        b1_max = (b1.base + b1.size) as u64;
        d = 0;
        if ((a.size as u32) as u64) < b1.base as u64 {
            d = (a.size as u32) as u64 + ((1u64 << 32) - b1_max);
        } else if (a.size as u32) as u64 >= b1_max {
            d = (a.size as u32) as u64 - b1_max;
        }
        if t.size < d {
            return CNUM64_EMPTY;
        }
        t.size -= d;
    }
    t
}

/// Intersect 'in' with the set of integers 'base + step * k'.
/// (The C parameter is named `in`, a Rust keyword; it is `input` here.)
pub fn cnum64_intersect_linear(input: Cnum64, base: u16, step: u16) -> Cnum64 {
    let smin: i64 = cnum64_smin(input);
    let smax: i64 = cnum64_smax(input);
    let lo: i64;
    let hi: i64;
    let mut d: u16;

    if step <= 1 || cnum64_is_empty(input) || cnum64_srange_overflow(input) {
        return input;
    }
    /* d = (base - smin) mod step */
    d = imod(base as i64 - imod(smin, step) as i64, step);
    if (smax as u64).wrapping_sub(smin as u64) < d as u64 {
        return CNUM64_EMPTY;
    }
    lo = smin + d as i64;
    /* d = (smax - base) mod step */
    d = imod(imod(smax, step) as i64 - base as i64, step);
    hi = smax - d as i64;
    cnum64_from_srange(lo, hi)
}
