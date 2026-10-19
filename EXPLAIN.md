# How scalar value tracking works in the eBPF verifier today

Written for a reader who knows formal verification but not the verifier. Every claim cites
`file:line` in `~/linux-ebpf` at commit 4f842631f178 (bpf-next/master, 2026-10-19); line
numbers were taken with `grep -n` and `sed -n` on that commit. Anything not checked in the
tree is marked UNVERIFIED.

## 1. The abstract value of a register

The verifier symbolically executes a BPF program, keeping for each of the eleven registers a
`struct bpf_reg_state` (`include/linux/bpf_verifier.h:53-190`). When `type == SCALAR_VALUE`
the register holds a 64-bit integer whose actual value is unknown; the verifier tracks an
over-approximation of the set of values it can hold, using three cooperating domains that
share one struct:

| field | type | domain | declared at |
|---|---|---|---|
| `var_off` | `struct tnum { u64 value; u64 mask; }` | tristate number: each bit is known-0, known-1 or unknown | `bpf_verifier.h:134`, `include/linux/tnum.h:14-17` |
| `r64` | `struct cnum64 { u64 base; u64 size; }` | circular 64-bit interval (arc) | `bpf_verifier.h:140`, `include/linux/cnum.h:55-58` |
| `r32` | `struct cnum32 { u32 base; u32 size; }` | circular interval of the low 32 bits | `bpf_verifier.h:141`, `cnum.h:28-31` |
| `base`, `step` | `u16` | stride: the signed value is `base + step * k`; invariant `base < step` | `bpf_verifier.h:142-148` |

A concrete value `x` is consistent with the state if all four facts hold: `(x & ~mask) == value`
(the tnum membership test used in `tnum_in`, `kernel/bpf/tnum.c:210-216`); `x` lies on the arc
`r64`; `(u32)x` lies on the arc `r32`; and `x mod step == base` (signed). The value-tracking
proofs are about the functions that update these five fields.

**tnum.** `value` holds the known bits, `mask` the unknown ones; a well-formed tnum has
`value & mask == 0`. `tnum_unknown` is `{0, ~0}` (`tnum.c:15`), `tnum_const(v)` is `{v, 0}`
(`tnum.c:17-20`). All arithmetic is in `kernel/bpf/tnum.c` (330 lines): add/sub/neg/mul,
and/or/xor, fixed-count shifts, intersection and union, 32-bit sub-register views
(`tnum_subreg`, `tnum_clear_subreg`, `tnum_with_subreg`, `tnum.c:238-251`), byte swaps, and
`tnum_step(t, z)` = the smallest member of `t` greater than `z` (`tnum.c:287-319`).

**cnum (circular numbers).** Replaced the previous eight fields `{u,s}{32,64}{min,max}_value`
on 2026-04-24 (commit bbc631085503). An arc starts at `base` and contains `size + 1` values
going clockwise, so `{base, size}` with `size == U64_MAX` is the full circle and
`{U64_MAX, U64_MAX}` is reserved as the empty set (`cnum.h:33-34`, `cnum.h:60-61`). Signed and
unsigned bounds are *derived*: `cnum64_umin/umax` return `base` and `base + size` unless the
arc crosses the `U64_MAX -> 0` boundary, in which case they return `0` and `U64_MAX`
(`kernel/bpf/cnum_defs.h:56-65`); `cnum64_smin/smax` do the same reading `base` as `s64`,
with the boundary being `S64_MAX -> S64_MIN` (`cnum_defs.h:87-96`). The accessors
`reg_umin/umax/smin/smax` and `reg_u32_*/s32_*` in `bpf_verifier.h:192-230` are thin wrappers.
One arc cannot represent the intersection of an independent signed and unsigned range when
that intersection is two disjoint pieces; the commit message of bbc631085503 documents the
precision lost. The implementation is a single template `cnum_defs.h` included twice with
`T=32` and `T=64` (`kernel/bpf/cnum.c:7-13`), plus three mixed-width functions
(`cnum32_from_cnum64`, `cnum64_cnum32_intersect`, `cnum64_intersect_linear`,
`cnum.c:15-24`, `42-121`, `124-156`).

**stride.** Added 2026-10-09 (commit 0892ef2a7ef3) for loop analysis. `reg_step_reset`
sets `base = 0, step = 1` (no information) (`kernel/bpf/verifier.c:1951-1955`).

## 2. `reg_bounds_sync()`: making the domains agree

`reg_bounds_sync(reg)` (`verifier.c:2354-2380`) is called after almost every write to a
scalar's fields. It propagates information between the domains in a fixed order:

1. `range_bounds_violation` (`verifier.c:2398-2401`): if `r32` or `r64` is already empty, return.
2. `__update_reg_bounds` (`verifier.c:2301-2305`) = `__update_reg32_bounds` then
   `__update_reg64_bounds`: intersect `r32`/`r64` with the range implied by the tnum
   (`cnum32_from_tnum`, `cnum64_from_tnum`, `verifier.c:2238-2259`: if the sign bit is unknown
   or set the tnum is read as a signed range, else as an unsigned one). The 64-bit variant
   (`verifier.c:2266-2299`) additionally uses `tnum_step` to detect the case where the arc and
   the tnum share exactly one value and then marks the register constant.
3. `__reg_deduce_bounds` (`verifier.c:2317-2321`), twice: `deduce_bounds_32_from_64`
   narrows `r32` by the low 32 bits of `r64` (`verifier.c:2307-2310`, `cnum32_from_cnum64`
   in `cnum.c:15-24`), and `deduce_bounds_64_from_32` narrows `r64` using `r32`
   (`verifier.c:2312-2315`, `cnum64_cnum32_intersect` in `cnum.c:42-121`, which trims the
   arc's ends to the first and last 64-bit values whose low word is in `r32`).
4. `__reg_bound_offset` (`verifier.c:2323-2344`): intersect the tnum with `tnum_range(umin,
   umax)` for both widths, then clear the trailing bits that the stride proves zero.
5. `__update_reg_bounds` again (the new tnum may tighten the arcs).
6. `__update_bounds_from_step` (`verifier.c:2346-2350`): intersect `r64` with the arithmetic
   progression `base + step * k` (`cnum64_intersect_linear`, `cnum.c:124-156`) and push the
   result into `r32`.

There is no fixed-point iteration; the order above is the whole algorithm. The invariants
expected afterwards are checked by `reg_bounds_sanity_check` (`verifier.c:2403-2442`): non-empty
arcs, a constant tnum agrees with a constant arc in both widths (`const_tnum_range_mismatch`,
`verifier.c:2382-2396`), and `step != 0 && base < step`. A violation is a verifier bug
(`verifier_bug`, which fails the load when `env->test_reg_invariants` is set, else resets the
register to unbounded).

Where it is called: 17 call sites in `verifier.c` (`grep -n 'reg_bounds_sync(' kernel/bpf/verifier.c`),
in `__mark_reg_s32_range` (2485), `coerce_reg_to_size` (6123), `add_scalar_to_reg` (6953),
`do_refine_retval_range` (12103, 12108, 12131), `adjust_ptr_min_max_vals` (16431),
`adjust_scalar_min_max_vals` (17345), `bpf_set_reg_range` (17597), `bpf_reg_union` (17642),
`check_alu_op` (17773, the `MOV` paths), `simulate_both_branches_taken` (17924-17937, four
calls), and `sync_linked_regs` (18670). `reg_bounds_sanity_check` has 13 call sites
(`grep -n 'reg_bounds_sanity_check(' kernel/bpf/verifier.c`).

## 3. ALU instructions

`check_alu_op` (`verifier.c:17647`) handles `MOV`, `NEG`, `END` itself and sends every other
scalar ALU op to `adjust_reg_min_max_vals` (`verifier.c:17352`, called at 17823), which for two
scalar operands calls `adjust_scalar_min_max_vals` (`verifier.c:17181-17349`). That function:

- returns an unknown register if `is_safe_to_compute_dst_reg_range` (`verifier.c:17098`)
  says no: division and modulo need a constant divisor; shifts need a constant shift amount
  smaller than the width;
- dispatches on the opcode (`verifier.c:17216-17332`). For `BPF_ADD` it runs
  `scalar_step_add`, `scalar32_min_max_add`, `scalar_min_max_add`, then
  `dst->var_off = tnum_add(...)`. The per-opcode *transfer functions* are
  `scalar32_min_max_<op>` (acting on `r32`) and `scalar_min_max_<op>` (acting on `r64`) at
  `verifier.c:16452-17046`; add and sub are one line each (`cnum64_add`, `cnum64_negate`,
  `verifier.c:16452-16474`); and/or/xor take their minimum or maximum from the tnum
  (`verifier.c:16750-16870`); the shifts shift the bounds and the tnum and then mark the
  other width unbounded (`verifier.c:16872-17046`); mul uses `check_mul_overflow` on the four
  corner products (`verifier.c:16476-16536`); div and mod exist too (`verifier.c:16538-16748`)
  but are not in the proposed scope;
- for 32-bit ops, zero-extends (`zext_32_to_64`, `verifier.c:6090-6096`), and finally calls
  `reg_bounds_sync(dst_reg)` (`verifier.c:17345`).

The proof obligation per transfer function is therefore: if `x` is consistent with `dst` and `y`
with `src` (before), then `x op y` is consistent with `dst` after the function *and after the
following sync*; the stride helpers (`scalar_step_add/scale/mul/lsh`, `verifier.c:1957-2034`,
`16135-16151`) carry the same obligation for the `base/step` fields.

## 4. Conditional jumps

`check_cond_jmp_op` (`verifier.c:18679`) copies the two operand registers into four scratch
registers `env->false_reg1/2`, `env->true_reg1/2` (`verifier.c:18769-18772`) and calls
`is_branch_taken` (`verifier.c:18177`, called at 18773). For two scalars this reaches
`is_scalar_branch_taken` (`verifier.c:17953`), which decides the branch from the bounds when it
can, and otherwise `simulate_both_branches_taken` (`verifier.c:17920-17948`): it applies
`regs_refine_cond_op` with the negated opcode to the false pair and with the opcode to the true
pair, syncs all four, and declares a branch dead when its refined registers became empty.
`regs_refine_cond_op` (`verifier.c:18252-18388`) is the refinement itself: for `JEQ` both
registers get the intersection of their arcs and tnums; for `JNE` with a constant the arc is
intersected with the complement of that one value (written as the arc `{val+1, U64_MAX-1}`);
for `JSET` with a single-bit constant the bit is set in the tnum; for `JLE/JLT/JSLE/JSLT` the
arcs are intersected with the appropriate half-ranges (the `GE/GT` forms are turned into these
by `bpf_flip_opcode` and swapping the operands, `verifier.c:18258-18269`). After
`regs_bounds_sanity_check_branches` (`verifier.c:18391-18400`, called at 18836) the four
scratch registers are written back: the false pair into the fall-through state and the true
pair into the pushed branch state (`verifier.c:18840-18844`), and `sync_linked_regs`
propagates the new bounds to registers that share an `id` (`verifier.c:18849-18856`).

## 5. State pruning

At selected instructions `bpf_is_state_visited` (`kernel/bpf/states.c:1367`) compares the
current state with every previously explored state at the same instruction using
`states_equal(env, old, cur, RANGE_WITHIN)` (`states.c:1027`, called at 1463, 1499, 1505,
1531). If an old state is found such that the current one is "covered", the current path is
pruned: the verifier relies on the earlier exploration having already proved every instruction
reachable from here safe. Per register the test is `regsafe` (`states.c:527-674`); for scalars
(`states.c:563-629`) it is, after the id checks,

```
range_within(rold, rcur) && tnum_in(rold->var_off, rcur->var_off)
```

`range_within` (`states.c:301-329`) requires `cnum64_is_subset(old->r64, cur->r64)`,
`cnum32_is_subset(old->r32, cur->r32)` (`cnum_defs.h:277-289`), and, when the old state had a
stride, that the current values lie on it. `tnum_in(a, b)` (`tnum.c:210-216`) is "every member
of `b` is a member of `a`". The pruning obligation is thus: `range_within(old, cur) &&
tnum_in(old, cur)` implies that every value consistent with `cur` is consistent with `old`.
A register that is not `precise` is skipped entirely (`states.c:571-572`).

## 6. Points worth knowing before writing specifications

- Soundness of a transfer function is only meaningful relative to the *conjunction* of the
  four facts in section 1; several functions deliberately throw away one domain (e.g.
  `__mark_reg64_unbounded` in `scalar32_min_max_lsh`, `verifier.c:16900`) and rely on
  `reg_bounds_sync` to rebuild it from the others.
- The C relies on unsigned wraparound in many places (`cnum_defs.h` arithmetic on `base`),
  and on signed wraparound being defined because the kernel is built with
  `-fno-strict-overflow` (`harness/kbuild-cmdlines.txt`).
- Preconditions are enforced by callers, not callees: shift amounts below the width
  (`is_safe_to_compute_dst_reg_range`), `tnum_cast` size below 8, `step != 0` before
  `imod` (`bpf_verifier.h:19-25`).
- The kernel's own invariant checker (`reg_bounds_sanity_check`) is the closest thing to a
  written specification; the `tools/testing/selftests/bpf/prog_tests/reg_bounds.c` test
  (UNVERIFIED: not read in this phase beyond its mention in the commit message of
  bbc631085503) exhaustively checks small ranges.
- Previous formal work on these functions exists in the commit history (Agni, CBMC, Lean
  proofs of `tnum_step` and of the cnum refactors; see `HISTORY.md` section 5).
