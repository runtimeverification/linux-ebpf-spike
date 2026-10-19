//! Port of kernel/bpf/tnum.c and the inline helpers of include/linux/tnum.h.

/// struct tnum { u64 value; u64 mask; }
#[derive(Clone, Copy)]
#[cfg_attr(feature = "difftest", derive(PartialEq, Eq, Debug))]
pub struct Tnum {
    pub value: u64,
    pub mask: u64,
}

/// `#define TNUM(_v, _m) (struct tnum){.value = _v, .mask = _m}`
fn TNUM(_v: u64, _m: u64) -> Tnum {
    Tnum { value: _v, mask: _m }
}

/// `const struct tnum tnum_unknown = { .value = 0, .mask = -1 };`
#[allow(non_upper_case_globals)]
pub const tnum_unknown: Tnum = Tnum { value: 0, mask: u64::MAX };

/* Kernel bit helpers used by tnum.c (include/asm-generic/bitops, linux/swab.h). */

/// fls64(x): index (1-based) of the most significant set bit, 0 if x == 0.
pub fn fls64(x: u64) -> u8 {
    (64 - x.leading_zeros()) as u8
}

/// __ffs64(word): index (0-based) of the least significant set bit; word != 0.
pub fn __ffs64(word: u64) -> u32 {
    word.trailing_zeros()
}

/// ___constant_swab16 from include/uapi/linux/swab.h
pub fn swab16(x: u16) -> u16 {
    ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8)
}

/// ___constant_swab32
pub fn swab32(x: u32) -> u32 {
    ((x & 0x000000ff) << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000) >> 24)
}

/// ___constant_swab64
pub fn swab64(x: u64) -> u64 {
    ((x & 0x00000000000000ff) << 56)
        | ((x & 0x000000000000ff00) << 40)
        | ((x & 0x0000000000ff0000) << 24)
        | ((x & 0x00000000ff000000) << 8)
        | ((x & 0x000000ff00000000) >> 8)
        | ((x & 0x0000ff0000000000) >> 24)
        | ((x & 0x00ff000000000000) >> 40)
        | ((x & 0xff00000000000000) >> 56)
}

pub fn tnum_const(value: u64) -> Tnum {
    TNUM(value, 0)
}

pub fn tnum_range(min: u64, max: u64) -> Tnum {
    let chi = min ^ max;
    let bits = fls64(chi);

    /* special case, needed because 1ULL << 64 is undefined */
    if bits > 63 {
        return tnum_unknown;
    }
    let delta = (1u64 << bits) - 1;
    TNUM(min & !delta, delta)
}

/// Precondition (C: undefined otherwise): shift < 64.
pub fn tnum_lshift(a: Tnum, shift: u8) -> Tnum {
    TNUM(a.value << shift, a.mask << shift)
}

/// Precondition: shift < 64.
pub fn tnum_rshift(a: Tnum, shift: u8) -> Tnum {
    TNUM(a.value >> shift, a.mask >> shift)
}

/// Precondition: min_shift < insn_bitness (32 or 64).
pub fn tnum_arshift(a: Tnum, min_shift: u8, insn_bitness: u8) -> Tnum {
    if insn_bitness == 32 {
        TNUM(
            ((a.value as i32) >> min_shift) as u32 as u64,
            ((a.mask as i32) >> min_shift) as u32 as u64,
        )
    } else {
        TNUM(((a.value as i64) >> min_shift) as u64, ((a.mask as i64) >> min_shift) as u64)
    }
}

pub fn tnum_add(a: Tnum, b: Tnum) -> Tnum {
    let sm = a.mask.wrapping_add(b.mask);
    let sv = a.value.wrapping_add(b.value);
    let sigma = sm.wrapping_add(sv);
    let chi = sigma ^ sv;
    let mu = chi | a.mask | b.mask;
    TNUM(sv & !mu, mu)
}

pub fn tnum_sub(a: Tnum, b: Tnum) -> Tnum {
    let dv = a.value.wrapping_sub(b.value);
    let alpha = dv.wrapping_add(a.mask);
    let beta = dv.wrapping_sub(b.mask);
    let chi = alpha ^ beta;
    let mu = chi | a.mask | b.mask;
    TNUM(dv & !mu, mu)
}

pub fn tnum_neg(a: Tnum) -> Tnum {
    tnum_sub(TNUM(0, 0), a)
}

pub fn tnum_and(a: Tnum, b: Tnum) -> Tnum {
    let alpha = a.value | a.mask;
    let beta = b.value | b.mask;
    let v = a.value & b.value;
    TNUM(v, alpha & beta & !v)
}

pub fn tnum_or(a: Tnum, b: Tnum) -> Tnum {
    let v = a.value | b.value;
    let mu = a.mask | b.mask;
    TNUM(v, mu & !v)
}

pub fn tnum_xor(a: Tnum, b: Tnum) -> Tnum {
    let v = a.value ^ b.value;
    let mu = a.mask | b.mask;
    TNUM(v & !mu, mu)
}

pub fn tnum_mul(a: Tnum, b: Tnum) -> Tnum {
    let mut a = a;
    let mut b = b;
    let mut acc = TNUM(0, 0);

    while a.value != 0 || a.mask != 0 {
        /* LSB of tnum a is a certain 1 */
        if a.value & 1 != 0 {
            acc = tnum_add(acc, b);
        }
        /* LSB of tnum a is uncertain */
        else if a.mask & 1 != 0 {
            acc = tnum_union(acc, tnum_add(acc, b));
        }
        /* Note: no case for LSB is certain 0 */
        a = tnum_rshift(a, 1);
        b = tnum_lshift(b, 1);
    }
    acc
}

pub fn tnum_overlap(a: Tnum, b: Tnum) -> bool {
    let mu = !a.mask & !b.mask;
    (a.value & mu) == (b.value & mu)
}

pub fn tnum_intersect(a: Tnum, b: Tnum) -> Tnum {
    let v = a.value | b.value;
    let mu = a.mask & b.mask;
    TNUM(v & !mu, mu)
}

pub fn tnum_union(a: Tnum, b: Tnum) -> Tnum {
    let v = a.value & b.value;
    let mu = (a.value ^ b.value) | a.mask | b.mask;
    TNUM(v & !mu, mu)
}

/// Precondition: size < 8 (C: `1ULL << 64` is undefined; callers pass 1, 2, 4).
pub fn tnum_cast(a: Tnum, size: u8) -> Tnum {
    let mut a = a;
    a.value &= (1u64 << (size * 8)) - 1;
    a.mask &= (1u64 << (size * 8)) - 1;
    a
}

pub fn tnum_is_aligned(a: Tnum, size: u64) -> bool {
    if size == 0 {
        return true;
    }
    ((a.value | a.mask) & (size - 1)) == 0
}

pub fn tnum_in(a: Tnum, b: Tnum) -> bool {
    let mut b = b;
    if b.mask & !a.mask != 0 {
        return false;
    }
    b.value &= !a.mask;
    a.value == b.value
}

/// `int tnum_sbin(char *str, size_t size, struct tnum a)`; here size = str.len().
/// Precondition: str.len() >= 1.
pub fn tnum_sbin(str: &mut [u8], a: Tnum) -> i32 {
    let size: usize = str.len();
    let mut a = a;
    let mut n: usize = 64;

    while n != 0 {
        if n < size {
            if a.mask & 1 != 0 {
                str[n - 1] = b'x';
            } else if a.value & 1 != 0 {
                str[n - 1] = b'1';
            } else {
                str[n - 1] = b'0';
            }
        }
        a.mask >>= 1;
        a.value >>= 1;
        n -= 1;
    }
    let last = if size - 1 < 64 { size - 1 } else { 64 };
    str[last] = 0;
    64
}

pub fn tnum_subreg(a: Tnum) -> Tnum {
    tnum_cast(a, 4)
}

pub fn tnum_clear_subreg(a: Tnum) -> Tnum {
    tnum_lshift(tnum_rshift(a, 32), 32)
}

pub fn tnum_with_subreg(reg: Tnum, subreg: Tnum) -> Tnum {
    tnum_or(tnum_clear_subreg(reg), tnum_subreg(subreg))
}

pub fn tnum_const_subreg(a: Tnum, value: u32) -> Tnum {
    tnum_with_subreg(a, tnum_const(value as u64))
}

pub fn tnum_bswap16(a: Tnum) -> Tnum {
    TNUM(swab16((a.value & 0xFFFF) as u16) as u64, swab16((a.mask & 0xFFFF) as u16) as u64)
}

pub fn tnum_bswap32(a: Tnum) -> Tnum {
    TNUM(swab32((a.value & 0xFFFFFFFF) as u32) as u64, swab32((a.mask & 0xFFFFFFFF) as u32) as u64)
}

pub fn tnum_bswap64(a: Tnum) -> Tnum {
    TNUM(swab64(a.value), swab64(a.mask))
}

pub fn tnum_step(t: Tnum, z: u64) -> u64 {
    let tmax = t.value | t.mask;

    /* if z >= largest member of t, return largest member of t */
    if z >= tmax {
        return tmax;
    }

    /* if z < smallest member of t, return smallest member of t */
    if z < t.value {
        return t.value;
    }

    let d = z.wrapping_sub(t.value);
    /* fls64(d & ~t.mask) <= 63 here because d < t.mask (see tnum.c comment). */
    let carry_mask = (1u64 << fls64(d & !t.mask)).wrapping_sub(1);
    let filled = d | carry_mask | !t.mask;
    let inc = filled.wrapping_add(1) & t.mask;
    t.value | inc
}

pub fn tnum_alignment(a: Tnum) -> u32 {
    let v = a.value | a.mask;

    if v != 0 {
        __ffs64(v)
    } else {
        64
    }
}

/* include/linux/tnum.h inline helpers */

pub fn tnum_is_const(a: Tnum) -> bool {
    a.mask == 0
}

pub fn tnum_equals_const(a: Tnum, b: u64) -> bool {
    tnum_is_const(a) && a.value == b
}

pub fn tnum_is_unknown(a: Tnum) -> bool {
    !a.mask == 0
}

pub fn tnum_subreg_is_const(a: Tnum) -> bool {
    tnum_subreg(a).mask == 0
}
