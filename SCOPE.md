# Scope definition (shared by all Phase 0 tasks)

Kernel tree: `~/linux-ebpf`, branch `ebpf-spike`, HEAD 4f842631f178
(`v7.3-rc5-1314-g4f842631f178`, bpf-next/master as of 2026-10-19). READ ONLY.

Names below are as they exist in that tree. The October-2026 proposal text predates
two changes that matter:

1. The cnum series (2026-04-24, bbc631085503) replaced the eight `{u,s}{32,64}{min,max}_value`
   fields of `struct bpf_reg_state` with `struct cnum64 r64` and `struct cnum32 r32`.
2. The stride series (2026-10-09, 0892ef2a7ef3 "bpf: Representation for intervals with
   steps") added `u16 base, step` to `struct bpf_reg_state` and `__update_bounds_from_step()`
   to `reg_bounds_sync()`.
3. State-equivalence code moved from `kernel/bpf/verifier.c` to `kernel/bpf/states.c`
   (2026-04-12, c82834a5a11f). `range_within()` and `regsafe()` live there now.

## Layer A (pure value-domain libraries)

Files: `kernel/bpf/tnum.c`, `include/linux/tnum.h`, `kernel/bpf/cnum.c`,
`kernel/bpf/cnum_defs.h`, `include/linux/cnum.h`, plus `imod()` in
`include/linux/bpf_verifier.h` (called by `cnum64_intersect_linear`).

tnum.c: tnum_const, tnum_range, tnum_lshift, tnum_rshift, tnum_arshift, tnum_add,
tnum_sub, tnum_neg, tnum_and, tnum_or, tnum_xor, tnum_mul, tnum_overlap, tnum_intersect,
tnum_union, tnum_cast, tnum_is_aligned, tnum_in, tnum_sbin, tnum_subreg,
tnum_clear_subreg, tnum_with_subreg, tnum_const_subreg, tnum_bswap16, tnum_bswap32,
tnum_bswap64, tnum_step, tnum_alignment.
tnum.h inline: tnum_is_const, tnum_equals_const, tnum_is_unknown, tnum_subreg_is_const.
(`tnum_strn` is in `kernel/bpf/log.c`: formatting only, out of scope.)

cnum_defs.h (instantiated for T=32 and T=64, so each name exists twice):
from_urange, from_srange, urange_overflow, umin, umax, srange_overflow, smin, smax,
intersect, intersect_with, intersect_with_urange, intersect_with_srange, normalize,
union, add, negate, is_empty, contains, is_const, is_subset.
cnum.c: cnum32_from_cnum64, cnum64_cnum32_intersect, cnum64_intersect_linear.
bpf_verifier.h: imod.

## Layer B (verifier value tracking on `struct bpf_reg_state`)

File: `kernel/bpf/verifier.c` unless noted.

Sync and its helpers: reg_bounds_sync, range_bounds_violation, __update_reg_bounds,
__update_reg32_bounds, __update_reg64_bounds, cnum32_from_tnum, cnum64_from_tnum,
__reg_deduce_bounds, deduce_bounds_32_from_64, deduce_bounds_64_from_32,
__reg_bound_offset, __update_bounds_from_step, ___mark_reg_known, reg_step_reset.
Invariant checks: const_tnum_range_mismatch, const_tnum_range_mismatch_32,
reg_bounds_sanity_check.
Accessors in `include/linux/bpf_verifier.h`: reg_smin, reg_smax, reg_umin, reg_umax,
reg_s32_min, reg_s32_max, reg_u32_min, reg_u32_max, reg_set_srange32, reg_set_urange32,
reg_set_srange64, reg_set_urange64.
Small state helpers used by the transfer functions: __mark_reg_known, __mark_reg32_known,
__mark_reg32_unbounded, __mark_reg64_unbounded, __mark_reg_unbounded,
reset_reg64_and_tnum, reset_reg32_and_tnum.
ALU transfer functions in the proposed list: scalar_min_max_{add,sub,and,or,xor,lsh,rsh,arsh}
and scalar32_min_max_{add,sub,and,or,xor,lsh,rsh,arsh}, plus their helpers
__scalar32_min_max_lsh and __scalar64_min_max_lsh.
ALU transfer functions that exist but are NOT in the proposed list:
scalar_min_max_{mul,udiv,sdiv,umod,smod} and scalar32_min_max_{mul,udiv,sdiv,umod,smod}.
Stride helpers (new 2026-10-09, not in the proposal): scalar_step_add, scalar_step_scale,
scalar_step_mul, scalar_step_lsh, reg_step_check_unsigned.
Dispatcher (context only, not itself proposed): adjust_scalar_min_max_vals,
is_safe_to_compute_dst_reg_range, zext_32_to_64, coerce_reg_to_size.
Pruning: range_within (kernel/bpf/states.c), tnum_in (kernel/bpf/tnum.c), and their
caller regsafe (kernel/bpf/states.c, context only).

## Stretch

regs_refine_cond_op and its helpers: is_reg_const, reg_const_value, bpf_flip_opcode,
bpf_rev_opcode, and the caller simulate_both_branches_taken (context) and
is_scalar_branch_taken (context).
