//! Differential tester: kernel C (compiled verbatim in user space) against the
//! safe-Rust model, on random inputs plus boundary values.
//!
//! Every test is a function from a flat word vector to Option<divergence>.
//! Inputs are decoded from the words so that preconditions (shift counts,
//! non-zero step, well-formed tnums where the verifier guarantees them) hold
//! for every word vector; this keeps shrinking simple and total.
//!
//! Usage: difftest [--cases N] [--seed S] [--threads T] [--only SUBSTR] [--markdown]
mod c;

use bpf_model::cnum_c::*;
use bpf_model::tnum_c::*;
use bpf_model::verifier_c::*;
use std::fmt::Debug;
use std::time::Instant;

/* ---------- random words ---------- */

const BOUNDARY: &[u64] = &[
    0, 1, 2, 3, 4, 7, 8, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000,
    0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1_0000_0000, 0x1_ffff_ffff, 0x1_8000_0000,
    0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_fffe,
    0xffff_ffff_0000_0000, 0xffff_ffff_8000_0000, 0xffff_ffff_7fff_ffff, 0x8000_0000_ffff_ffff,
    0x7fff_ffff_ffff_fffe, 0x8000_0000_0000_0001, 0x0000_0000_8000_0001, 0xffff_fffe_ffff_ffff,
];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    /// A word with varied bit density: 1/4 boundary values, else random of several shapes.
    fn word(&mut self) -> u64 {
        let k = self.next();
        match k % 16 {
            0..=3 => BOUNDARY[(k >> 8) as usize % BOUNDARY.len()],
            4 => self.next() & self.next(),
            5 => self.next() | self.next(),
            6 => self.next() & self.next() & self.next(),
            7 => self.next() % 1024,
            8 => (self.next() % 1024).wrapping_neg(),
            9 => self.next() as u32 as u64,
            10 => (self.next() as u32 as u64) << 32,
            11 => self.next() as u16 as u64,
            12 => BOUNDARY[(k >> 8) as usize % BOUNDARY.len()].wrapping_add(self.next() % 8).wrapping_sub(4),
            _ => self.next(),
        }
    }
}

/* ---------- decoding words into inputs ---------- */

fn tn(v: u64, m: u64) -> Tnum { Tnum { value: v, mask: m } }
/// well-formed tnum (value & mask == 0), as the verifier maintains
fn tnw(v: u64, m: u64) -> Tnum { Tnum { value: v & !m, mask: m } }
fn c32(b: u64, s: u64) -> Cnum32 { Cnum32 { base: b as u32, size: s as u32 } }
fn c64(b: u64, s: u64) -> Cnum64 { Cnum64 { base: b, size: s } }
fn step_of(w: u64) -> u16 { let s = w as u16; if s == 0 { 1 } else { s } }
/// register state from 8 words; step >= 1 and base < step as the verifier maintains
fn rs(w: &[u64]) -> BpfRegState {
    let step = step_of(w[7]);
    BpfRegState { var_off: tnw(w[0], w[1]), r64: c64(w[2], w[3]), r32: c32(w[4], w[5]), base: (w[6] as u16) % step, step }
}
/// register state that has been through reg_bounds_sync (C), so that the
/// transfer functions also see realistic, consistent inputs
fn rs_synced(w: &[u64]) -> BpfRegState {
    let mut r = rs(w);
    if w[0] & 1 == 0 {
        let mut cr: c::bpf_reg_state = r.into();
        unsafe { c::k_reg_bounds_sync(&mut cr) };
        r = cr.into();
    }
    r
}
/// constant register with a value < limit (shift operands)
fn rs_const(w: u64, limit: u64) -> BpfRegState {
    let mut r = BpfRegState { var_off: tnum_unknown, r64: CNUM64_UNBOUNDED, r32: CNUM32_UNBOUNDED, base: 0, step: 1 };
    ___mark_reg_known(&mut r, w % limit);
    r
}

/* ---------- comparison ---------- */

type TestFn = fn(&[u64]) -> Option<String>;
struct Test { name: &'static str, nwords: usize, f: TestFn }

fn cmp<T: PartialEq + Debug>(input: impl FnOnce() -> String, c: T, r: T) -> Option<String> {
    if c == r { None } else { Some(format!("input: {}\n  C:    {:?}\n  Rust: {:?}", input(), c, r)) }
}

fn c_reg1(f: unsafe extern "C" fn(*mut c::bpf_reg_state), r: BpfRegState) -> BpfRegState {
    let mut cr: c::bpf_reg_state = r.into();
    unsafe { f(&mut cr) };
    cr.into()
}
fn c_reg2(f: unsafe extern "C" fn(*mut c::bpf_reg_state, *mut c::bpf_reg_state), d: BpfRegState, s: BpfRegState) -> BpfRegState {
    let mut cd: c::bpf_reg_state = d.into();
    let mut cs: c::bpf_reg_state = s.into();
    unsafe { f(&mut cd, &mut cs) };
    cd.into()
}

macro_rules! t_un { ($name:ident) => { Test { name: stringify!($name), nwords: 2, f: |w| {
    let a = tn(w[0], w[1]);
    cmp(|| format!("a={:?}", a), Tnum::from(unsafe { c::$name(a.into()) }), $name(a)) } } } }
macro_rules! t_bin { ($name:ident) => { Test { name: stringify!($name), nwords: 4, f: |w| {
    let a = tn(w[0], w[1]); let b = tn(w[2], w[3]);
    cmp(|| format!("a={:?} b={:?}", a, b), Tnum::from(unsafe { c::$name(a.into(), b.into()) }), $name(a, b)) } } } }
macro_rules! t_bin_bool { ($name:ident) => { Test { name: stringify!($name), nwords: 4, f: |w| {
    let a = tn(w[0], w[1]); let b = tn(w[2], w[3]);
    cmp(|| format!("a={:?} b={:?}", a, b), unsafe { c::$name(a.into(), b.into()) }, $name(a, b)) } } } }

macro_rules! c_un { ($name:ident, $ct:ident, $mk:ident) => { Test { name: stringify!($name), nwords: 2, f: |w| {
    let a = $mk(w[0], w[1]);
    cmp(|| format!("a={:?}", a), unsafe { c::$name(a.into()) }.into(), $name(a)) } } } }
macro_rules! c_un_scalar { ($name:ident, $mk:ident) => { Test { name: stringify!($name), nwords: 2, f: |w| {
    let a = $mk(w[0], w[1]);
    cmp(|| format!("a={:?}", a), unsafe { c::$name(a.into()) }, $name(a)) } } } }
macro_rules! c_bin { ($name:ident, $mk:ident) => { Test { name: stringify!($name), nwords: 4, f: |w| {
    let a = $mk(w[0], w[1]); let b = $mk(w[2], w[3]);
    cmp(|| format!("a={:?} b={:?}", a, b), unsafe { c::$name(a.into(), b.into()) }.into(), $name(a, b)) } } } }
macro_rules! c_bin_bool { ($name:ident, $mk:ident) => { Test { name: stringify!($name), nwords: 4, f: |w| {
    let a = $mk(w[0], w[1]); let b = $mk(w[2], w[3]);
    cmp(|| format!("a={:?} b={:?}", a, b), unsafe { c::$name(a.into(), b.into()) }, $name(a, b)) } } } }
macro_rules! c_with { ($name:ident, $mk:ident, $ty:ty) => { Test { name: stringify!($name), nwords: 4, f: |w| {
    let a = $mk(w[0], w[1]); let b = $mk(w[2], w[3]);
    let mut ca: $ty = a.into(); unsafe { c::$name(&mut ca, b.into()) };
    let mut ra = a; $name(&mut ra, b);
    cmp(|| format!("dst={:?} src={:?}", a, b), ca.into(), ra) } } } }
macro_rules! c_with_range { ($name:ident, $mk:ident, $ty:ty, $cast:ty) => { Test { name: stringify!($name), nwords: 4, f: |w| {
    let a = $mk(w[0], w[1]); let lo = w[2] as $cast; let hi = w[3] as $cast;
    let mut ca: $ty = a.into(); unsafe { c::$name(&mut ca, lo, hi) };
    let mut ra = a; $name(&mut ra, lo, hi);
    cmp(|| format!("dst={:?} min={} max={}", a, lo, hi), ca.into(), ra) } } } }

macro_rules! r_un { ($name:ident, $kname:ident, $mk:ident) => { Test { name: stringify!($name), nwords: 8, f: |w| {
    let r = $mk(w);
    let mut rr = r; $name(&mut rr);
    cmp(|| format!("reg={:?}", r), c_reg1(c::$kname, r), rr) } } } }
macro_rules! r_bin { ($name:ident, $kname:ident, $mkd:ident, $mks:ident) => { Test { name: stringify!($name), nwords: 16, f: |w| {
    let d = $mkd(&w[0..8]); let s = $mks(&w[8..16]);
    let mut rd = d; $name(&mut rd, &s);
    cmp(|| format!("dst={:?} src={:?}", d, s), c_reg2(c::$kname, d, s), rd) } } } }
macro_rules! r_bin_const { ($name:ident, $kname:ident, $limit:expr) => { Test { name: stringify!($name), nwords: 9, f: |w| {
    let d = rs_synced(&w[0..8]); let s = rs_const(w[8], $limit);
    let mut rd = d; $name(&mut rd, &s);
    cmp(|| format!("dst={:?} src={:?}", d, s), c_reg2(c::$kname, d, s), rd) } } } }
macro_rules! r_bool { ($name:ident, $kname:ident) => { Test { name: stringify!($name), nwords: 8, f: |w| {
    let r = rs(w);
    let mut cr: c::bpf_reg_state = r.into();
    cmp(|| format!("reg={:?}", r), unsafe { c::$kname(&mut cr) }, $name(&r)) } } } }

fn tests() -> Vec<Test> {
    vec![
        // ---- tnum.c ----
        Test { name: "tnum_const", nwords: 1, f: |w| cmp(|| format!("v={:#x}", w[0]), Tnum::from(unsafe { c::tnum_const(w[0]) }), tnum_const(w[0])) },
        Test { name: "tnum_range", nwords: 2, f: |w| cmp(|| format!("min={:#x} max={:#x}", w[0], w[1]), Tnum::from(unsafe { c::tnum_range(w[0], w[1]) }), tnum_range(w[0], w[1])) },
        Test { name: "tnum_lshift", nwords: 3, f: |w| { let a = tn(w[0], w[1]); let s = (w[2] % 64) as u8;
            cmp(|| format!("a={:?} shift={}", a, s), Tnum::from(unsafe { c::tnum_lshift(a.into(), s) }), tnum_lshift(a, s)) } },
        Test { name: "tnum_rshift", nwords: 3, f: |w| { let a = tn(w[0], w[1]); let s = (w[2] % 64) as u8;
            cmp(|| format!("a={:?} shift={}", a, s), Tnum::from(unsafe { c::tnum_rshift(a.into(), s) }), tnum_rshift(a, s)) } },
        Test { name: "tnum_arshift", nwords: 4, f: |w| { let a = tn(w[0], w[1]); let bits = if w[3] & 1 == 0 { 64u8 } else { 32u8 }; let s = (w[2] % bits as u64) as u8;
            cmp(|| format!("a={:?} min_shift={} bitness={}", a, s, bits), Tnum::from(unsafe { c::tnum_arshift(a.into(), s, bits) }), tnum_arshift(a, s, bits)) } },
        t_bin!(tnum_add), t_bin!(tnum_sub), t_un!(tnum_neg), t_bin!(tnum_and), t_bin!(tnum_or), t_bin!(tnum_xor),
        t_bin!(tnum_mul), t_bin_bool!(tnum_overlap), t_bin!(tnum_intersect), t_bin!(tnum_union),
        Test { name: "tnum_cast", nwords: 3, f: |w| { let a = tn(w[0], w[1]); let s = (1 + w[2] % 7) as u8;
            cmp(|| format!("a={:?} size={}", a, s), Tnum::from(unsafe { c::tnum_cast(a.into(), s) }), tnum_cast(a, s)) } },
        Test { name: "tnum_is_aligned", nwords: 3, f: |w| { let a = tn(w[0], w[1]); let s = if w[2] % 4 == 0 { 0 } else { 1u64 << (w[2] % 64) };
            cmp(|| format!("a={:?} size={:#x}", a, s), unsafe { c::tnum_is_aligned(a.into(), s) }, tnum_is_aligned(a, s)) } },
        t_bin_bool!(tnum_in),
        Test { name: "tnum_sbin", nwords: 3, f: |w| { let a = tn(w[0], w[1]); let size = 1 + (w[2] % 80) as usize;
            let mut cb = [0xAAu8; 96]; let mut rb = [0xAAu8; 96];
            let cr = unsafe { c::tnum_sbin(cb.as_mut_ptr(), size, a.into()) };
            let rr = tnum_sbin(&mut rb[..size], a);
            cmp(|| format!("a={:?} size={}", a, size), (cr, cb.to_vec()), (rr, rb.to_vec())) } },
        t_un!(tnum_subreg), t_un!(tnum_clear_subreg), t_bin!(tnum_with_subreg),
        Test { name: "tnum_const_subreg", nwords: 3, f: |w| { let a = tn(w[0], w[1]); let v = w[2] as u32;
            cmp(|| format!("a={:?} value={:#x}", a, v), Tnum::from(unsafe { c::tnum_const_subreg(a.into(), v) }), tnum_const_subreg(a, v)) } },
        t_un!(tnum_bswap16), t_un!(tnum_bswap32), t_un!(tnum_bswap64),
        Test { name: "tnum_step", nwords: 3, f: |w| { let t = tnw(w[0], w[1]);
            cmp(|| format!("t={:?} z={:#x}", t, w[2]), unsafe { c::tnum_step(t.into(), w[2]) }, tnum_step(t, w[2])) } },
        Test { name: "tnum_alignment", nwords: 2, f: |w| { let a = tn(w[0], w[1]);
            cmp(|| format!("a={:?}", a), unsafe { c::tnum_alignment(a.into()) }, tnum_alignment(a)) } },
        // ---- cnum.c, 32-bit instantiation ----
        Test { name: "cnum32_from_urange", nwords: 2, f: |w| cmp(|| format!("min={:#x} max={:#x}", w[0] as u32, w[1] as u32), Cnum32::from(unsafe { c::cnum32_from_urange(w[0] as u32, w[1] as u32) }), cnum32_from_urange(w[0] as u32, w[1] as u32)) },
        Test { name: "cnum32_from_srange", nwords: 2, f: |w| cmp(|| format!("min={} max={}", w[0] as i32, w[1] as i32), Cnum32::from(unsafe { c::cnum32_from_srange(w[0] as i32, w[1] as i32) }), cnum32_from_srange(w[0] as i32, w[1] as i32)) },
        c_un_scalar!(cnum32_umin, c32), c_un_scalar!(cnum32_umax, c32), c_un_scalar!(cnum32_smin, c32), c_un_scalar!(cnum32_smax, c32),
        c_bin!(cnum32_union, c32), c_bin!(cnum32_intersect, c32),
        c_with!(cnum32_intersect_with, c32, c::cnum32),
        c_with_range!(cnum32_intersect_with_urange, c32, c::cnum32, u32),
        c_with_range!(cnum32_intersect_with_srange, c32, c::cnum32, i32),
        Test { name: "cnum32_contains", nwords: 3, f: |w| { let a = c32(w[0], w[1]); let v = w[2] as u32;
            cmp(|| format!("a={:?} v={:#x}", a, v), unsafe { c::cnum32_contains(a.into(), v) }, cnum32_contains(a, v)) } },
        c_un_scalar!(cnum32_is_const, c32), c_un_scalar!(cnum32_is_empty, c32),
        c_bin!(cnum32_add, c32), c_un!(cnum32_negate, cnum32, c32), c_bin_bool!(cnum32_is_subset, c32),
        // ---- cnum.c, 64-bit instantiation ----
        Test { name: "cnum64_from_urange", nwords: 2, f: |w| cmp(|| format!("min={:#x} max={:#x}", w[0], w[1]), Cnum64::from(unsafe { c::cnum64_from_urange(w[0], w[1]) }), cnum64_from_urange(w[0], w[1])) },
        Test { name: "cnum64_from_srange", nwords: 2, f: |w| cmp(|| format!("min={} max={}", w[0] as i64, w[1] as i64), Cnum64::from(unsafe { c::cnum64_from_srange(w[0] as i64, w[1] as i64) }), cnum64_from_srange(w[0] as i64, w[1] as i64)) },
        c_un_scalar!(cnum64_umin, c64), c_un_scalar!(cnum64_umax, c64), c_un_scalar!(cnum64_smin, c64), c_un_scalar!(cnum64_smax, c64),
        c_bin!(cnum64_union, c64), c_bin!(cnum64_intersect, c64),
        c_with!(cnum64_intersect_with, c64, c::cnum64),
        c_with_range!(cnum64_intersect_with_urange, c64, c::cnum64, u64),
        c_with_range!(cnum64_intersect_with_srange, c64, c::cnum64, i64),
        Test { name: "cnum64_contains", nwords: 3, f: |w| { let a = c64(w[0], w[1]);
            cmp(|| format!("a={:?} v={:#x}", a, w[2]), unsafe { c::cnum64_contains(a.into(), w[2]) }, cnum64_contains(a, w[2])) } },
        c_un_scalar!(cnum64_is_const, c64), c_un_scalar!(cnum64_is_empty, c64),
        c_bin!(cnum64_add, c64), c_un!(cnum64_negate, cnum64, c64), c_bin_bool!(cnum64_is_subset, c64),
        // ---- cnum.c, mixed ----
        c_un!(cnum32_from_cnum64, cnum32, c64),
        Test { name: "cnum64_cnum32_intersect", nwords: 4, f: |w| { let a = c64(w[0], w[1]); let b = c32(w[2], w[3]);
            cmp(|| format!("a={:?} b={:?}", a, b), Cnum64::from(unsafe { c::cnum64_cnum32_intersect(a.into(), b.into()) }), cnum64_cnum32_intersect(a, b)) } },
        Test { name: "cnum64_intersect_linear", nwords: 4, f: |w| { let a = c64(w[0], w[1]); let base = w[2] as u16; let step = w[3] as u16;
            cmp(|| format!("in={:?} base={} step={}", a, base, step), Cnum64::from(unsafe { c::cnum64_intersect_linear(a.into(), base, step) }), cnum64_intersect_linear(a, base, step)) } },
        Test { name: "imod", nwords: 2, f: |w| { let v = w[0] as i64; let step = step_of(w[1]);
            cmp(|| format!("v={} step={}", v, step), unsafe { c::k_imod(v, step) }, imod(v, step)) } },
        // ---- verifier.c: sync and helpers (raw and synced inputs) ----
        r_un!(reg_bounds_sync, k_reg_bounds_sync, rs),
        r_un!(__update_reg_bounds, k___update_reg_bounds, rs),
        r_un!(__update_reg32_bounds, k___update_reg32_bounds, rs),
        r_un!(__update_reg64_bounds, k___update_reg64_bounds, rs),
        r_un!(__reg_deduce_bounds, k___reg_deduce_bounds, rs),
        r_un!(__reg_bound_offset, k___reg_bound_offset, rs),
        r_un!(__update_bounds_from_step, k___update_bounds_from_step, rs),
        r_un!(zext_32_to_64, k_zext_32_to_64, rs_synced),
        Test { name: "cnum32_from_tnum", nwords: 2, f: |w| { let t = tnw(w[0], w[1]);
            cmp(|| format!("t={:?}", t), Cnum32::from(unsafe { c::k_cnum32_from_tnum(t.into()) }), cnum32_from_tnum(t)) } },
        Test { name: "cnum64_from_tnum", nwords: 2, f: |w| { let t = tnw(w[0], w[1]);
            cmp(|| format!("t={:?}", t), Cnum64::from(unsafe { c::k_cnum64_from_tnum(t.into()) }), cnum64_from_tnum(t)) } },
        r_bool!(range_bounds_violation, k_range_bounds_violation),
        r_bool!(const_tnum_range_mismatch, k_const_tnum_range_mismatch),
        r_bool!(const_tnum_range_mismatch_32, k_const_tnum_range_mismatch_32),
        Test { name: "coerce_reg_to_size", nwords: 9, f: |w| { let r = rs_synced(&w[0..8]); let size = [1i32, 2, 4][(w[8] % 3) as usize];
            let mut rr = r; coerce_reg_to_size(&mut rr, size);
            let mut cr: c::bpf_reg_state = r.into(); unsafe { c::k_coerce_reg_to_size(&mut cr, size) };
            cmp(|| format!("reg={:?} size={}", r, size), BpfRegState::from(cr), rr) } },
        // ---- verifier.c: ALU transfer functions ----
        r_bin!(scalar32_min_max_add, k_scalar32_min_max_add, rs_synced, rs_synced),
        r_bin!(scalar_min_max_add, k_scalar_min_max_add, rs_synced, rs_synced),
        r_bin!(scalar32_min_max_sub, k_scalar32_min_max_sub, rs_synced, rs_synced),
        r_bin!(scalar_min_max_sub, k_scalar_min_max_sub, rs_synced, rs_synced),
        r_bin!(scalar32_min_max_mul, k_scalar32_min_max_mul, rs_synced, rs_synced),
        r_bin!(scalar_min_max_mul, k_scalar_min_max_mul, rs_synced, rs_synced),
        r_bin!(scalar32_min_max_and, k_scalar32_min_max_and, rs_synced, rs_synced),
        r_bin!(scalar_min_max_and, k_scalar_min_max_and, rs_synced, rs_synced),
        r_bin!(scalar32_min_max_or, k_scalar32_min_max_or, rs_synced, rs_synced),
        r_bin!(scalar_min_max_or, k_scalar_min_max_or, rs_synced, rs_synced),
        r_bin!(scalar32_min_max_xor, k_scalar32_min_max_xor, rs_synced, rs_synced),
        r_bin!(scalar_min_max_xor, k_scalar_min_max_xor, rs_synced, rs_synced),
        r_bin_const!(scalar32_min_max_lsh, k_scalar32_min_max_lsh, 32),
        r_bin_const!(scalar_min_max_lsh, k_scalar_min_max_lsh, 64),
        r_bin_const!(scalar32_min_max_rsh, k_scalar32_min_max_rsh, 32),
        r_bin_const!(scalar_min_max_rsh, k_scalar_min_max_rsh, 64),
        r_bin_const!(scalar32_min_max_arsh, k_scalar32_min_max_arsh, 32),
        r_bin_const!(scalar_min_max_arsh, k_scalar_min_max_arsh, 64),
        // ---- verifier.c: stride helpers ----
        r_bin!(scalar_step_mul, k_scalar_step_mul, rs_synced, rs_synced),
        r_bin!(scalar_step_lsh, k_scalar_step_lsh, rs_synced, rs_synced),
        Test { name: "scalar_step_add", nwords: 16, f: |w| { let d = rs_synced(&w[0..8]); let s = rs_synced(&w[8..16]);
            let mut rd = d; scalar_step_add(&mut rd, d, s);
            let mut cd: c::bpf_reg_state = d.into(); let cs: c::bpf_reg_state = s.into();
            let ca = cd; unsafe { c::k_scalar_step_add(&mut cd, &ca, &cs) };
            cmp(|| format!("dst={:?} src={:?}", d, s), BpfRegState::from(cd), rd) } },
        Test { name: "scalar_step_scale", nwords: 9, f: |w| { let d = rs_synced(&w[0..8]); let amount = w[8];
            let mut rd = d; scalar_step_scale(&mut rd, amount);
            let mut cd: c::bpf_reg_state = d.into(); unsafe { c::k_scalar_step_scale(&mut cd, amount) };
            cmp(|| format!("dst={:?} amount={:#x}", d, amount), BpfRegState::from(cd), rd) } },
        // ---- states.c ----
        Test { name: "range_within", nwords: 16, f: |w| { let o = rs_synced(&w[0..8]); let cu = rs_synced(&w[8..16]);
            let co: c::bpf_reg_state = o.into(); let cc: c::bpf_reg_state = cu.into();
            cmp(|| format!("old={:?} cur={:?}", o, cu), unsafe { c::k_range_within(&co, &cc) }, range_within(&o, &cu)) } },
    ]
}

/* ---------- shrinking ---------- */

/// Greedy word-wise shrink: try 0, boundary values, and single-bit clears per word.
fn shrink(t: &Test, start: &[u64]) -> Vec<u64> {
    let mut cur = start.to_vec();
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..cur.len() {
            let mut cands: Vec<u64> = vec![0, 1];
            cands.extend_from_slice(BOUNDARY);
            for b in 0..64 { if cur[i] & (1 << b) != 0 { cands.push(cur[i] & !(1 << b)); } }
            for cand in cands {
                if cand.count_ones() >= cur[i].count_ones() && cand != 0 { continue; }
                if cand == cur[i] { continue; }
                let mut trial = cur.clone();
                trial[i] = cand;
                if (t.f)(&trial).is_some() {
                    cur = trial;
                    changed = true;
                    break;
                }
            }
        }
    }
    cur
}

struct Report { name: &'static str, cases: u64, secs: f64, divergences: u64, first: Option<String>, minimal: Option<String> }

fn run_test(t: &Test, cases: u64, seed: u64) -> Report {
    let mut rng = Rng(seed ^ 0x9E3779B97F4A7C15);
    let mut w = vec![0u64; t.nwords];
    let mut divergences = 0;
    let mut first = None;
    let mut minimal = None;
    let start = Instant::now();
    for _ in 0..cases {
        for x in w.iter_mut() { *x = rng.word(); }
        if let Some(d) = (t.f)(&w) {
            divergences += 1;
            if first.is_none() {
                first = Some(d);
                let m = shrink(t, &w);
                minimal = Some(format!("words={:#x?}\n{}", m, (t.f)(&m).unwrap_or_default()));
            }
        }
    }
    Report { name: t.name, cases, secs: start.elapsed().as_secs_f64(), divergences, first, minimal }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut cases: u64 = 1_000_000;
    let mut seed: u64 = 1;
    let mut threads: usize = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut only: Option<String> = None;
    let mut markdown = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--cases" => { cases = args[i + 1].replace('_', "").parse().unwrap(); i += 1; }
            "--seed" => { seed = args[i + 1].parse().unwrap(); i += 1; }
            "--threads" => { threads = args[i + 1].parse().unwrap(); i += 1; }
            "--only" => { only = Some(args[i + 1].clone()); i += 1; }
            "--markdown" => markdown = true,
            a => panic!("unknown arg {}", a),
        }
        i += 1;
    }
    unsafe {
        assert_eq!(c::k_sizeof_reg(), std::mem::size_of::<c::bpf_reg_state>(), "bpf_reg_state size");
        assert_eq!(c::k_offsetof_var_off(), 24, "offsetof var_off");
        assert_eq!(c::k_offsetof_base(), 64, "offsetof base");
        assert_eq!(c::k_offsetof_id(), 68, "offsetof id");
    }
    let all = tests();
    let selected: Vec<&Test> = all.iter().filter(|t| only.as_ref().map_or(true, |o| t.name.contains(o.as_str()))).collect();
    eprintln!("difftest: {} functions, {} cases each, seed {}, {} threads", selected.len(), cases, seed, threads);

    let next = std::sync::atomic::AtomicUsize::new(0);
    let reports = std::sync::Mutex::new(Vec::new());
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if i >= selected.len() { break; }
                let r = run_test(selected[i], cases, seed.wrapping_add(i as u64 * 7919));
                eprintln!("  {:<32} {:>12} cases {:>8.2} s {:>12.0} cases/s {} divergences", r.name, r.cases, r.secs, r.cases as f64 / r.secs, r.divergences);
                reports.lock().unwrap().push(r);
            });
        }
    });
    let mut reports = reports.into_inner().unwrap();
    reports.sort_by_key(|r| r.name);
    let total_cases: u64 = reports.iter().map(|r| r.cases).sum();
    let wall = t0.elapsed().as_secs_f64();
    if markdown {
        println!("| function | cases | seconds | cases/s | divergences |");
        println!("|---|---:|---:|---:|---:|");
        for r in &reports {
            println!("| {} | {} | {:.2} | {:.0} | {} |", r.name, r.cases, r.secs, r.cases as f64 / r.secs, r.divergences);
        }
        println!("\nTotal: {} functions, {} cases, wall {:.1} s with {} threads, seed {}.", reports.len(), total_cases, wall, threads, seed);
    }
    let mut any = false;
    for r in &reports {
        if r.divergences > 0 {
            any = true;
            println!("\n### DIVERGENCE in {} ({} of {} cases)\nfirst:\n  {}\nminimal:\n  {}", r.name, r.divergences, r.cases,
                     r.first.as_deref().unwrap_or(""), r.minimal.as_deref().unwrap_or(""));
        }
    }
    if !any { println!("\nNo divergences."); }
}
