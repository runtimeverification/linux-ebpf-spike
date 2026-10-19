# Function inventory (Phase 0)

Kernel tree: `~/linux-ebpf`, branch `ebpf-spike`, HEAD `4f842631f178f41baa2d2d444a277d54c07666a1`
(checked with `git rev-parse HEAD; git branch --show-current` on 2026-10-19). All line numbers
and counts below are for that commit. Scope is as defined in `SCOPE.md`.

## How the numbers were produced

Helper scripts (all in
`/tmp/claude-1000/-home-natalie-linux-ebpf-spike/b1cb0d4e-67e2-4406-91be-f6bd9b01c206/scratchpad/`):

- `loc.py FILE START END`: strips `/* */` and `//` comments from the line range, drops blank
  lines, prints the count. Braces-only lines and the signature line count as code.
- `locate.py FILE NAME...`: finds the definition of each NAME (column-0 line containing
  `NAME(` followed by `{` before any `;`), brace-matches to the closing `}`, prints
  `name file start end loc` (LOC via `loc.py`). Output saved as `ranges.tsv` (138 rows).
- `callers.py TREE scope_names.txt NAME...`: for every `.c`/`.h` file in `kernel/bpf/*.c`,
  `kernel/bpf/*.h`, `include/linux/*.h`, `net/` (recursive) and
  `drivers/net/ethernet/netronome/` (recursive) (file list from `git ls-files`), strips
  comments, finds `NAME(` (for cnum_defs.h templates: `cnum32_x(`, `cnum64_x(`, `FN(x)(` and
  `FN(x(`), drops the definition's own signature lines and prototypes, and attributes each
  remaining hit to the enclosing top-level function. A caller is "in-scope" if its name is in
  `scope_names.txt` (= every row of this inventory, including context rows). Output:
  `callers.txt` (one line per name) and `callers.json` (every hit with file:line:caller).
  Counts are call sites (lines), not distinct callers; the out-of-scope column lists
  distinct caller function names.
- `constructs.py ranges.tsv`: mechanical scan of each function range for loops, goto, switch,
  min/max family, `check_*_overflow`, `__builtin_*`, bit helpers, `swap(`, `div64_*`,
  signed/unsigned casts, shifts whose right operand is not a literal, memset/memcmp, array
  locals, compound literals, ternaries, `%`, `/`; and the set of identifiers followed by `(`.
  Output `constructs.tsv`. The constructs column below is this scan plus a manual read of
  each body (recursion was checked by looking for the function's own name in its call set:
  none found).
- `totals.py`: sums LOC per group from `ranges.tsv`.
- `funcs_{v7.3-rc5,HEAD}_{verifier,states}.txt`: function-name lists used for the rename section
  (`/usr/bin/grep -E '^(static |)(inline |__always_inline |noinline )*[a-z0-9_ ]*(struct [a-z0-9_]+ )?\*?[a-z0-9_]+\(' | sed -E 's/^.*[ *]([a-z0-9_]+)\(.*/\1/' | sort -u`
  on `git show v7.3-rc5:kernel/bpf/verifier.c` and on HEAD).

Note: the interactive `grep` on this machine is ugrep 7.8.4; all regexes here were run with
`/usr/bin/grep` (GNU grep 3.7) or `git grep`.

Cross-checks: `loc.py kernel/bpf/tnum.c 17 330` = 193 = sum of the 28 tnum.c rows;
`loc.py kernel/bpf/cnum_defs.h 23 289` = 145 = sum of the 20 template rows (143) + the two
`EXPORT_SYMBOL_GPL(FN(umin|umax));` lines.

Column key for the table:
- **LOC**: lines without blanks/comments, from `loc.py`.
- **callers**: `total (in/out)` call sites from `callers.py`; then the distinct out-of-scope
  caller functions (file in parentheses when not `kernel/bpf/verifier.c`). "in" callers are
  the other rows of this inventory.
- **fields**: `struct bpf_reg_state` fields read (R) / written (W). Reads through the
  accessors `reg_umin()` etc. are counted as reads of `r64`/`r32`. "n/a" for Layer A
  functions that take no register.
- **pure**: "pure (by value)" = only value parameters, no side effects; "pure (writes *x
  only)" = effects limited to the pointed-to argument(s); otherwise "impure: why".

## Layer A: pure value-domain libraries

### kernel/bpf/tnum.c (proposed)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| tnum_const | tnum.c:17-20 | 4 | 17 (7/10); check_func_ptr_read, check_generic_ptr_alignment, check_pkt_ptr_alignment, coerce_reg_to_size_sx, coerce_subreg_to_size_sx, count_read_offsets | n/a | `TNUM()` compound-literal macro (tnum.c:13) | none | pure (by value) |
| tnum_range | tnum.c:22-36 | 9 | 5 (2/3); check_return_code, coerce_reg_to_size_sx, coerce_subreg_to_size_sx | n/a | fls64, shift by variable `1ULL << bits` (bits <= 63 guarded), reads global `tnum_unknown` | fls64 | pure (by value) |
| tnum_lshift | tnum.c:38-41 | 4 | 4 (4/0) | n/a | shift by variable (u8), shift >= 64 is UB (callers guard) | none | pure (by value) |
| tnum_rshift | tnum.c:43-46 | 4 | 4 (4/0) | n/a | shift by variable (u8) | none | pure (by value) |
| tnum_arshift | tnum.c:48-61 | 9 | 2 (2/0) | n/a | casts (s32)/(s64)/(u32); arithmetic right shift of a signed value by a variable (GCC-defined) | none | pure (by value) |
| tnum_add | tnum.c:63-73 | 10 | 9 (3/6); add_scalar_to_reg, adjust_ptr_min_max_vals, check_func_ptr_read, check_generic_ptr_alignment, check_pkt_ptr_alignment, sync_linked_regs | n/a | wrapping u64 `+` | none | pure (by value) |
| tnum_sub | tnum.c:75-85 | 10 | 3 (2/1); adjust_ptr_min_max_vals | n/a | wrapping u64 `-`/`+` | none | pure (by value) |
| tnum_neg | tnum.c:87-90 | 4 | 1 (1/0) | n/a | none (calls tnum_sub) | none | pure (by value) |
| tnum_and | tnum.c:92-100 | 8 | 4 (4/0) | n/a | none | none | pure (by value) |
| tnum_or | tnum.c:102-109 | 7 | 5 (5/0) | n/a | none | none | pure (by value) |
| tnum_xor | tnum.c:111-118 | 7 | 1 (1/0) | n/a | none | none | pure (by value) |
| tnum_mul | tnum.c:137-161 | 14 | 1 (1/0) | n/a | `while` loop (terminates: `a` is right-shifted each iteration, at most 64 rounds), modifies by-value params | none | pure (by value) |
| tnum_overlap | tnum.c:163-169 | 6 | 2 (2/0) | n/a | none | none | pure (by value) |
| tnum_intersect | tnum.c:174-181 | 7 | 4 (4/0) | n/a | none | none | pure (by value) |
| tnum_union | tnum.c:188-194 | 6 | 2 (1/1); bpf_reg_union | n/a | none | none | pure (by value) |
| tnum_cast | tnum.c:196-201 | 6 | 2 (2/0) | n/a | shift by variable `1ULL << (size * 8)` (UB for size == 8; callers pass 4 or size < 8) | none | pure (by value) |
| tnum_is_aligned | tnum.c:203-208 | 6 | 2 (0/2); check_generic_ptr_alignment, check_pkt_ptr_alignment | n/a | none | none | pure (by value) |
| tnum_in | tnum.c:210-216 | 7 | 7 (4/3); check_func_ptr_read, check_return_code, count_read_offsets (in-scope: regsafe, 4 sites) | n/a | none | none | pure (by value) |
| tnum_sbin | tnum.c:218-236 | 18 | 0 (0/0); no caller anywhere in the tree (`git grep -n 'tnum_sbin('` finds only prototype and definition) | n/a | `for` loop, `min()`, `size_t` casts, writes caller buffer | min | pure (writes *str only) |
| tnum_subreg | tnum.c:238-241 | 4 | 22 (20/2); coerce_subreg_to_size_sx, set_sext32_default_val | n/a | none | none | pure (by value) |
| tnum_clear_subreg | tnum.c:243-246 | 4 | 2 (2/0) | n/a | none | none | pure (by value) |
| tnum_with_subreg | tnum.c:248-251 | 4 | 5 (5/0) | n/a | none | none | pure (by value) |
| tnum_const_subreg | tnum.c:253-256 | 4 | 1 (1/0) | n/a | implicit u32 -> u64 widening | none | pure (by value) |
| tnum_bswap16 | tnum.c:258-261 | 4 | 1 (0/1); scalar_byte_swap | n/a | none | swab16 | pure (by value) |
| tnum_bswap32 | tnum.c:263-266 | 4 | 1 (0/1); scalar_byte_swap | n/a | none | swab32 | pure (by value) |
| tnum_bswap64 | tnum.c:268-271 | 4 | 1 (0/1); scalar_byte_swap | n/a | none | swab64 | pure (by value) |
| tnum_step | tnum.c:287-319 | 14 | 4 (2/2); count_read_offsets (in-scope: __update_reg64_bounds, 2 sites) | n/a | fls64, shift by variable `1ULL << fls64(...)`, wrapping u64 `+`/`-` | fls64 | pure (by value) |
| tnum_alignment | tnum.c:325-330 | 5 | 1 (0/1); linear_bounds (scev.c) | n/a | ternary, __ffs64 | __ffs64 | pure (by value) |

### include/linux/tnum.h static inline (proposed)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| tnum_is_const | tnum.h:72-75 | 4 | 69 (19/50); 42 distinct: __check_buffer_access, __check_ptr_off_reg, __process_kf_arg_ptr_to_graph_node, __process_kf_arg_ptr_to_graph_root, adjust_ptr_min_max_vals, assign_scalar_id_before_mov, bpf_diag_fmt_btf_type (diagnostics.c), check_arg_const_str, check_flow_keys_access, check_func_arg_reg_off, check_map_access, check_map_field_pointer, check_map_mem_read, check_mem_access, check_mem_size_reg, check_ptr_to_btf_access, check_reg_sane_offset_ptr, check_reg_sane_offset_scalar, check_stack_access_for_ptr_arithmetic, check_stack_access_within_bounds, check_stack_range_initialized, check_stack_read, check_stack_read_fixed_off, check_stack_write, check_stack_write_var_off, coerce_reg_to_size_sx, coerce_subreg_to_size_sx, do_check, eval_expr (scev.c), get_constant_map_key, nfp_bpf_check_exit, nfp_bpf_check_stack_access, nfp_bpf_map_mark_used, nfp_bpf_stack_arg_ok, nfp_record_adjust_head (all five: netronome nfp/bpf/verifier.c), print_reg_state (log.c), process_const_alloc_mem_size, process_const_arg, process_kptr_func, process_spin_lock, sanitize_ptr_alu, stack_slot_obj_get_spi | n/a | none | none | pure (by value) |
| tnum_equals_const | tnum.h:78-81 | 4 | 3 (0/3); bpf_register_is_null (bpf_verifier.h), mark_ptr_or_null_reg, reg_is_init_pkt_pointer | n/a | none | none | pure (by value) |
| tnum_is_unknown | tnum.h:84-87 | 4 | 5 (0/5); bpf_diag_fmt_btf_type (diagnostics.c), check_return_code, is_unbound_scev_reg (scev.c), print_reg_state (log.c) | n/a | none | none | pure (by value) |
| tnum_subreg_is_const | tnum.h:129-132 | 4 | 8 (8/0) | n/a | none | none | pure (by value) |

### kernel/bpf/cnum_defs.h templates (proposed)

Each template is instantiated twice by `kernel/bpf/cnum.c` (`#define T 32` / `#define T 64`,
cnum.c:7-13), giving `cnum32_<name>` and `cnum64_<name>`. Line ranges are the template's
(given once). Names are pasted with `FN(name)` = `__PASTE(__PASTE(cnum, T), __PASTE(_, name))`
(cnum_defs.h:14-21); `ut`/`st`/`UT_MAX`/`ST_MAX`/`ST_MIN`/`EMPTY` are likewise pasted. All rows
use macro templating; the "constructs" column lists what else appears. Callers are counted
for both instantiations plus `FN(x)` uses inside cnum_defs.h itself. "static inline" marks
templates that are not exported through `include/linux/cnum.h`.

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| cnum{T}_from_urange | cnum_defs.h:23-26 | 4 | 13 (11/2); coerce_reg_to_size_sx | n/a | `(ut)` cast, wrapping `-`, compound literal | none | pure (by value) |
| cnum{T}_from_srange | cnum_defs.h:28-34 | 6 | 10 (9/1); linear_bounds (scev.c) | n/a | `(ut)` casts, ternary, compound literal | none | pure (by value) |
| cnum{T}_urange_overflow (static inline) | cnum_defs.h:42-46 | 4 | 6 (6/0) | n/a | `(ut)` cast | none | pure (by value) |
| cnum{T}_umin | cnum_defs.h:56-59 (+ EXPORT_SYMBOL_GPL at :60) | 4 | 4 (2/2); bpf_diag_fmt_btf_type (diagnostics.c) (in-scope: reg_umin, reg_u32_min) | n/a | ternary | EXPORT_SYMBOL_GPL | pure (by value) |
| cnum{T}_umax | cnum_defs.h:62-65 (+ EXPORT_SYMBOL_GPL at :66) | 4 | 4 (2/2); bpf_diag_fmt_btf_type (diagnostics.c) (in-scope: reg_umax, reg_u32_max) | n/a | ternary, wrapping `+` | EXPORT_SYMBOL_GPL | pure (by value) |
| cnum{T}_srange_overflow (static inline) | cnum_defs.h:74-77 | 4 | 3 (3/0) | n/a | `(ut)` casts of ST_MAX/ST_MIN | none | pure (by value) |
| cnum{T}_smin | cnum_defs.h:87-90 | 4 | 9 (4/5); bpf_clamp_scev_regs (scev.c), bpf_widen_scev_regs (scev.c), bpf_diag_fmt_btf_type (diagnostics.c) | n/a | ternary, `(st)` cast | none | pure (by value) |
| cnum{T}_smax | cnum_defs.h:92-95 | 4 | 7 (3/4); same three as smin | n/a | ternary, `(st)` cast, wrapping `+` | none | pure (by value) |
| cnum{T}_intersect | cnum_defs.h:102-177 | 28 | 7 (6/1); bpf_clamp_scev_regs (scev.c) | n/a | `swap()` of two struct values, `min()`, compound literals, `(ut)` casts, ternary, modifies by-value params | swap, min | pure (by value) |
| cnum{T}_intersect_with | cnum_defs.h:179-182 | 4 | 7 (7/0) | n/a | none | none | pure (writes *dst only) |
| cnum{T}_intersect_with_urange | cnum_defs.h:184-187 | 4 | 8 (8/0) | n/a | none | none | pure (writes *dst only) |
| cnum{T}_intersect_with_srange | cnum_defs.h:189-192 | 4 | 8 (8/0) | n/a | none | none | pure (writes *dst only) |
| cnum{T}_normalize (static inline) | cnum_defs.h:194-199 | 6 | 6 (6/0) | n/a | modifies by-value param | none | pure (by value) |
| cnum{T}_union | cnum_defs.h:205-243 | 24 | 2 (0/2); bpf_reg_union | n/a | `max()`, compound literals, `(ut)` cast, wrapping `-`/`+` | max | pure (by value) |
| cnum{T}_add | cnum_defs.h:245-253 | 9 | 6 (4/2); adjust_ptr_min_max_vals | n/a | compound literals, `(ut)` cast, wrapping `+` | none | pure (by value) |
| cnum{T}_negate | cnum_defs.h:255-260 | 6 | 3 (2/1); adjust_ptr_min_max_vals | n/a | unary minus on unsigned, compound literal | none | pure (by value) |
| cnum{T}_is_empty | cnum_defs.h:262-265 | 4 | 13 (12/1); bpf_clamp_scev_regs (scev.c) | n/a | compares against `EMPTY` compound literal | none | pure (by value) |
| cnum{T}_contains | cnum_defs.h:267-270 | 4 | 1 (1/0) | n/a | wrapping `-` | none | pure (by value) |
| cnum{T}_is_const | cnum_defs.h:272-275 | 4 | 5 (3/2); bpf_diag_fmt_btf_type (diagnostics.c), linear_bounds (scev.c) | n/a | none | none | pure (by value) |
| cnum{T}_is_subset | cnum_defs.h:277-289 | 12 | 2 (2/0) | n/a | modifies by-value params, wrapping `-`/`+`; note the quirky spelling `FN(is_empty(smaller))` at :279/:281 (pastes to `cnum{T}_is_empty(smaller)`) | none | pure (by value) |

### kernel/bpf/cnum.c (proposed)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| cnum32_from_cnum64 | cnum.c:15-24 | 9 | 1 (1/0) | n/a | `(u32)` cast, compound literals, `CNUM32_EMPTY` | none | pure (by value) |
| cnum64_cnum32_intersect | cnum.c:42-121 | 31 | 1 (1/0) | n/a | `(u32)` casts with intentional u32 wraparound (:56), `BIT_ULL(32)`, compound literal, nested if/else, modifies local copy `t` | BIT_ULL | pure (by value) |
| cnum64_intersect_linear | cnum.c:124-156 | 16 | 1 (1/0) | n/a | `(u64)` casts, u16 arithmetic via `imod`, implicit s64->u16 narrowing of `base - imod(...)` into `d` | imod (bpf_verifier.h) | pure (by value) |

### include/linux/bpf_verifier.h: imod (proposed)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| imod | bpf_verifier.h:19-25 | 6 | 5 (4/1); linear_bounds (scev.c) (in-scope: cnum64_intersect_linear x2, range_within, scalar_step_add) | n/a | ternary, s32 remainder, implicit int -> u16 return narrowing | div_s64_rem | pure (by value) |

## Layer B: verifier value tracking on struct bpf_reg_state

`struct bpf_reg_state` is at `include/linux/bpf_verifier.h:53-190`. Fields relevant here:
`type` (:55), `delta` (:59), the anonymous union (:60-128: `range`, `frameno`, `map_ptr`,
`btf`/`btf_id`, `mem_size`, `dynptr`, `iter`, `irq`, `raw`, `subprogno`), `var_off` (:135),
`r64` (:141), `r32` (:142), `base`/`step` (:148-149), `id` (:174), `parent_id` (:182),
`map_uid` (:188), `precise` (:190).

### Sync and its helpers (proposed; kernel/bpf/verifier.c)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| reg_bounds_sync | verifier.c:2354-2380 | 11 | 16 (6/10); __mark_reg_s32_range, add_scalar_to_reg, adjust_ptr_min_max_vals, bpf_reg_union, bpf_set_reg_range, check_alu_op, do_refine_retval_range, sync_linked_regs | RW var_off, r64, r32; R base, step | none directly (sequence of calls; `__reg_deduce_bounds` called twice) | none | pure (writes *reg only) |
| range_bounds_violation | verifier.c:2398-2401 (fwd decl :2352) | 4 | 4 (4/0) | R r32, r64 | none | none | pure (reads *reg only) |
| __update_reg_bounds | verifier.c:2301-2305 | 5 | 7 (7/0) | RW var_off, r64, r32 (via callees) | none | none | pure (writes *reg only) |
| __update_reg32_bounds | verifier.c:2261-2264 | 4 | 5 (4/1); adjust_ptr_min_max_vals | R var_off; RW r32 | none | none | pure (writes *reg only) |
| __update_reg64_bounds | verifier.c:2266-2299 | 17 | 1 (1/0) | R var_off; RW r64; W var_off, r32, base, step (via ___mark_reg_known) | if/else-if chain, tnum_step | none | pure (writes *reg only) |
| cnum32_from_tnum | verifier.c:2238-2248 | 9 | 1 (1/0) | n/a (tnum in, cnum32 out) | S32_MIN/S32_MAX bit tests, implicit u64 -> s32/u32 narrowing at call | none | pure (by value) |
| cnum64_from_tnum | verifier.c:2250-2259 | 8 | 1 (1/0) | n/a | S64_MIN/S64_MAX bit tests, implicit u64 -> s64 | none | pure (by value) |
| __reg_deduce_bounds | verifier.c:2317-2321 | 5 | 2 (2/0) | RW r64, r32 | none | none | pure (writes *reg only) |
| deduce_bounds_32_from_64 | verifier.c:2307-2310 | 4 | 2 (2/0) | R r64; RW r32 | none | none | pure (writes *reg only) |
| deduce_bounds_64_from_32 | verifier.c:2312-2315 | 4 | 1 (1/0) | R r32; RW r64 | none | none | pure (writes *reg only) |
| __reg_bound_offset | verifier.c:2324-2344 | 19 | 1 (1/0) | RW var_off; R r64, r32, base, step | count_trailing_zeros (returns BITS_PER_LONG=64 for 0; `step` is never 0 after sanity check), `min()`, shift by variable `~0ULL << trailing_zero_bits` (<= 15 for u16 step != 0), u16 -> unsigned long | count_trailing_zeros, min | pure (writes *reg only) |
| __update_bounds_from_step | verifier.c:2346-2350 | 5 | 1 (1/0) | R base, step; RW r64, r32 | none | none | pure (writes *reg only) |
| ___mark_reg_known | verifier.c:2063-2069 | 7 | 5 (5/0) | W var_off, r64, r32, base, step | `(u32)` cast | none | pure (writes *reg only) |
| reg_step_reset | verifier.c:1951-1955 | 5 | 25 (19/6); adjust_ptr_min_max_vals, bpf_mark_reg_unknown_imprecise, bpf_reg_union, coerce_reg_to_size_sx, coerce_subreg_to_size_sx, scalar_byte_swap | W base, step | none | none | pure (writes *reg only) |

### Invariant checks (proposed; kernel/bpf/verifier.c)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| const_tnum_range_mismatch | verifier.c:2382-2388 | 6 | 1 (1/0) | R var_off, r64 | none | none | pure (reads *reg only) |
| const_tnum_range_mismatch_32 | verifier.c:2390-2396 | 6 | 1 (1/0) | R var_off, r32 | none | none | pure (reads *reg only) |
| reg_bounds_sanity_check | verifier.c:2403-2442 | 35 | 10 (0/10); __mark_reg_s32_range, bpf_reg_union, bpf_set_reg_range, check_alu_op, check_load_mem, do_refine_retval_range, regs_bounds_sanity_check_branches (4 sites) | R var_off, r64, r32, base, step; W r64, r32, base, step (reset on violation) | `goto out`, printf-style format string, returns -EFAULT | verifier_bug (logs via env), __mark_reg_unbounded, reg_step_reset | impure: writes the verifier log through `env`, reads `env->test_reg_invariants` |

### Accessors (proposed; include/linux/bpf_verifier.h, static inline)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| reg_smin | bpf_verifier.h:192-195 | 4 | 61 (17/44); 27 distinct: __check_ptr_off_reg, __mark_reg_s32_range, adjust_ptr_min_max_vals, bpf_widen_scev_regs (scev.c), btf_datasec_show (btf.c), check_func_arg, check_map_access, check_map_access_type, check_mem_region_access, check_mem_size_reg, check_ptr_to_btf_access, check_reg_sane_offset_ptr, check_reg_sane_offset_scalar, check_sock_access, check_stack_access_within_bounds, check_stack_range_initialized, check_stack_read_var_off, check_stack_write_var_off, coerce_reg_to_size_sx, linear_bounds (scev.c), maybe_fork_scalars, print_scalar_ranges (log.c), reg_not_null, retrieve_ptr_limit, retval_range_within, sanitize_ptr_alu, verbose_invalid_scalar | R r64 | none | none | pure (reads *reg only) |
| reg_smax | bpf_verifier.h:197-200 | 4 | 38 (15/23); 16 distinct: __mark_reg_s32_range, adjust_ptr_min_max_vals, bpf_widen_scev_regs (scev.c), btf_datasec_show (btf.c), check_stack_access_within_bounds, check_stack_range_initialized, check_stack_read_var_off, check_stack_write_var_off, coerce_reg_to_size_sx, linear_bounds (scev.c), maybe_fork_scalars, print_scalar_ranges (log.c), reg_not_null, retval_range_within, sanitize_ptr_alu, verbose_invalid_scalar | R r64 | none | none | pure (reads *reg only) |
| reg_umin | bpf_verifier.h:202-205 | 4 | 35 (25/10); 7 distinct: adjust_ptr_min_max_vals, check_func_arg, check_func_ptr_read, check_mem_size_reg, indirect_jump_min_max_index, nfp_bpf_check_alu (netronome nfp/bpf/verifier.c), print_scalar_ranges (log.c) | R r64 | none | none | pure (reads *reg only) |
| reg_umax | bpf_verifier.h:207-210 | 4 | 58 (25/33); 20 distinct: adjust_ptr_min_max_vals, adjust_reg_min_max_vals, check_alu_op, check_ctx_access, check_func_arg, check_func_ptr_read, check_helper_call, check_helper_mem_access, check_map_access, check_mem_access, check_mem_region_access, check_mem_size_reg, check_packet_access, coerce_subreg_to_size_sx, find_good_pkt_pointers, get_reg_width, indirect_jump_min_max_index, nfp_bpf_check_alu (netronome), print_scalar_ranges (log.c), retrieve_ptr_limit | R r64 | none | none | pure (reads *reg only) |
| reg_s32_min | bpf_verifier.h:212-215 | 4 | 29 (20/9); __mark_reg_s32_range, coerce_subreg_to_size_sx, maybe_fork_scalars, print_scalar_ranges (log.c), retval_range_within | R r32 | none | none | pure (reads *reg only) |
| reg_s32_max | bpf_verifier.h:217-220 | 4 | 27 (18/9); same 5 as reg_s32_min | R r32 | none | none | pure (reads *reg only) |
| reg_u32_min | bpf_verifier.h:222-225 | 4 | 26 (25/1); print_scalar_ranges (log.c) | R r32 | none | none | pure (reads *reg only) |
| reg_u32_max | bpf_verifier.h:227-230 | 4 | 24 (23/1); print_scalar_ranges (log.c) | R r32 | none | none | pure (reads *reg only) |
| reg_set_srange32 | bpf_verifier.h:232-235 | 4 | 16 (5/11); __mark_reg_s32_range, coerce_reg_to_size_sx, coerce_subreg_to_size_sx, do_refine_retval_range, set_sext32_default_val, set_sext64_default_val | W r32 | none | none | pure (writes *reg only) |
| reg_set_urange32 | bpf_verifier.h:237-240 | 4 | 9 (8/1); do_refine_retval_range | W r32 | none | none | pure (writes *reg only) |
| reg_set_srange64 | bpf_verifier.h:242-245 | 4 | 12 (5/7); __mark_reg_s32_range, coerce_reg_to_size_sx, do_refine_retval_range, set_sext64_default_val | W r64 | none | none | pure (writes *reg only) |
| reg_set_urange64 | bpf_verifier.h:247-250 | 4 | 10 (9/1); do_refine_retval_range | W r64 | none | none | pure (writes *reg only) |

### Small state helpers (proposed; kernel/bpf/verifier.c)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| __mark_reg_known | verifier.c:2074-2083 | 9 | 21 (4/17); 14 distinct: __mark_reg_const_zero, __mark_reg_known_zero, add_scalar_to_reg, adjust_reg_min_max_vals, bpf_mark_reg_known_scalar, check_alu_op, check_cond_jmp_op, check_ld_imm, check_map_mem_read, check_stack_arg_write, check_stack_write_fixed_off, mark_reg_graph_node, maybe_fork_scalars, sync_linked_regs | W: every byte from after `type` up to `var_off` (i.e. `delta` and the whole anonymous union) via memset; `id`, `parent_id`, `map_uid` = 0; then var_off, r64, r32, base, step (via ___mark_reg_known). R type (sizeof only) | memset over a struct prefix, offsetof, sizeof, `(u8 *)` pointer cast | memset, offsetof | pure (writes *reg only) |
| __mark_reg32_known | verifier.c:2091-2095 | 5 | 5 (3/2); maybe_fork_scalars (2 sites) | RW var_off; W r32 | `(u32)` cast | none | pure (writes *reg only) |
| __mark_reg32_unbounded | verifier.c:2209-2212 | 4 | 6 (5/1); adjust_ptr_min_max_vals | W r32 | `CNUM32_UNBOUNDED` compound literal | none | pure (writes *reg only) |
| __mark_reg64_unbounded | verifier.c:2214-2217 | 4 | 5 (5/0) | W r64 | `CNUM64_UNBOUNDED` compound literal | none | pure (writes *reg only) |
| __mark_reg_unbounded | verifier.c:2220-2224 | 5 | 4 (2/2); bpf_mark_reg_unknown_imprecise, scalar_byte_swap | W r64, r32 | none | none | pure (writes *reg only) |
| reset_reg64_and_tnum | verifier.c:2226-2230 | 5 | 4 (4/0) | W r64, var_off | reads global const `tnum_unknown` | none | pure (writes *reg only) |
| reset_reg32_and_tnum | verifier.c:2232-2236 | 5 | 4 (4/0) | W r32, var_off | reads global const `tnum_unknown` | none | pure (writes *reg only) |

### ALU transfer functions in the proposed list (kernel/bpf/verifier.c)

All take `(dst_reg, src_reg)` pointers; "src" reads are of `*src_reg`. Signed/unsigned
shift amounts come from `src_reg` bounds which `is_safe_to_compute_dst_reg_range()` has
already restricted to a constant `< insn_bitness`.

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| scalar32_min_max_add | verifier.c:16452-16456 (fwd decl :224) | 5 | 3 (1/2); add_scalar_to_reg, sync_linked_regs | R src r32; RW dst r32 | none | none | pure (writes *dst_reg only) |
| scalar_min_max_add | verifier.c:16458-16462 (fwd decl :225) | 5 | 3 (1/2); add_scalar_to_reg, sync_linked_regs | R src r64; RW dst r64 | none | none | pure (writes *dst_reg only) |
| scalar32_min_max_sub | verifier.c:16464-16468 | 5 | 2 (2/0) (adjust_scalar_min_max_vals: SUB and NEG) | R src r32; RW dst r32 | none | none | pure (writes *dst_reg only) |
| scalar_min_max_sub | verifier.c:16470-16474 | 5 | 2 (2/0) | R src r64; RW dst r64 | none | none | pure (writes *dst_reg only) |
| scalar32_min_max_and | verifier.c:16750-16769 | 15 | 1 (1/0) | R src var_off, r32; dst var_off, r32; W dst r32 (+ dst var_off via __mark_reg32_known) | `min()`, early return | min | pure (writes *dst_reg only) |
| scalar_min_max_and | verifier.c:16771-16792 | 15 | 1 (1/0) | R src var_off, r64; dst var_off, r64; W dst r64, then RW var_off/r64/r32 via __update_reg_bounds; const case writes all fields incl. id via __mark_reg_known | `min()`, early return | min | pure (writes *dst_reg only) |
| scalar32_min_max_or | verifier.c:16794-16813 | 15 | 1 (1/0) | as scalar32_min_max_and | `max()`, early return | max | pure (writes *dst_reg only) |
| scalar_min_max_or | verifier.c:16815-16836 | 15 | 1 (1/0) | as scalar_min_max_and | `max()`, early return | max | pure (writes *dst_reg only) |
| scalar32_min_max_xor | verifier.c:16838-16852 | 12 | 1 (1/0) | R src var_off; dst var_off; W dst r32 (+ var_off in const case) | early return | none | pure (writes *dst_reg only) |
| scalar_min_max_xor | verifier.c:16854-16870 | 13 | 1 (1/0) | R src var_off; dst var_off; W dst r64 (const case: all fields via __mark_reg_known) | early return | none | pure (writes *dst_reg only) |
| __scalar32_min_max_lsh | verifier.c:16872-16884 | 9 | 2 (2/0) | RW dst r32 | shift by variable: `1ULL << (31 - umax_val)` (u64) and `u32 << u64` (result is u32, i.e. 32-bit shift); u32 vs u64 comparison | none | pure (writes *dst_reg only) |
| scalar32_min_max_lsh | verifier.c:16886-16902 | 11 | 1 (1/0) | R src r32; RW dst var_off, r32; W dst r64 (unbounded) | none | none | pure (writes *dst_reg only) |
| __scalar64_min_max_lsh | verifier.c:16904-16928 | 16 | 1 (1/0) | R dst r32 (s32 bounds), r64; W dst r64 | `(s64)` cast then `<< 32`, shift by variable `1ULL << (63 - umax_val)`, `u64 << u64`, `CNUM64_UNBOUNDED` | none | pure (writes *dst_reg only) |
| scalar_min_max_lsh | verifier.c:16930-16943 | 10 | 1 (1/0) | R src r64; RW dst var_off, r64, r32 | call-order dependency (64-bit helper must run before 32-bit helper) | none | pure (writes *dst_reg only) |
| scalar32_min_max_rsh | verifier.c:16945-16973 | 12 | 1 (1/0) | R src r32; RW dst var_off, r32; W dst r64 (unbounded) | shift by variable (`u32 >> u32`) | none | pure (writes *dst_reg only) |
| scalar_min_max_rsh | verifier.c:16975-17005 | 11 | 1 (1/0) | R src r64; RW dst var_off, r64, r32 | shift by variable (`u64 >> u64`) | none | pure (writes *dst_reg only) |
| scalar32_min_max_arsh | verifier.c:17007-17025 | 11 | 1 (1/0) | R src r32; RW dst var_off, r32; W dst r64 (unbounded) | `(s32)` cast, arithmetic `>>` by variable, `(u32)` casts passed to s32 params, u64 local for a u32 shift amount | none | pure (writes *dst_reg only) |
| scalar_min_max_arsh | verifier.c:17027-17046 | 10 | 1 (1/0) | R src r64; RW dst var_off, r64, r32 | arithmetic `s64 >> u64` by variable | none | pure (writes *dst_reg only) |

### Pruning (proposed): range_within; tnum_in is in the tnum.c table

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| range_within | states.c:302-329 | 13 | 4 (4/0) (regsafe, 4 sites) | R old: r64, r32, base, step; cur: r64, r32, base, step | `%` by variable (u16), `(s64)` cast, implicit u16 promotion | imod | pure (reads *old, *cur only) |

### ALU transfer functions that exist but are NOT in the proposed list (extra; kernel/bpf/verifier.c)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| scalar32_min_max_mul | verifier.c:16476-16505 | 26 | 1 (1/0) | R src r32; RW dst r32 | check_mul_overflow x6 (u32 and s32, result through pointer), `min_array`/`max_array`, array local `s32 tmp_prod[4]` | check_mul_overflow, min_array, max_array | pure (writes *dst_reg only) |
| scalar_min_max_mul | verifier.c:16507-16536 | 26 | 1 (1/0) | R src r64; RW dst r64 | same with u64/s64, `s64 tmp_prod[4]` | check_mul_overflow, min_array, max_array | pure (writes *dst_reg only) |
| scalar32_min_max_udiv | verifier.c:16538-16548 | 8 | 1 (1/0) | R src r32; dst r32; W dst r32, r64 (unbounded), var_off (unknown) | plain u32 `/` by variable (divisor is a non-zero const by precondition) | none | pure (writes *dst_reg only) |
| scalar_min_max_udiv | verifier.c:16550-16560 | 8 | 1 (1/0) | R src r64; dst r64; W dst r64, r32 (unbounded), var_off | div64_u64 | div64_u64 | pure (writes *dst_reg only) |
| scalar32_min_max_sdiv | verifier.c:16562-16596 | 22 | 1 (1/0) | R src r32; dst r32; W dst r32, r64, var_off | `goto reset`, `min()`/`max()`, plain s32 `/` by variable, S32_MIN / -1 special case | min, max | pure (writes *dst_reg only) |
| scalar_min_max_sdiv | verifier.c:16598-16632 | 22 | 1 (1/0) | R src r64; dst r64; W dst r64, r32, var_off | `goto reset`, `min()`/`max()`, div64_s64 | div64_s64, min, max | pure (writes *dst_reg only) |
| scalar32_min_max_umod | verifier.c:16634-16651 | 10 | 1 (1/0) | R src r32; dst r32; W dst r32, r64, var_off (not written on the early-return path) | `min()`, early return | min | pure (writes *dst_reg only) |
| scalar_min_max_umod | verifier.c:16653-16670 | 10 | 1 (1/0) | R src r64; dst r64; W dst r64, r32, var_off (not on early return) | `min()`, early return | min | pure (writes *dst_reg only) |
| scalar32_min_max_smod | verifier.c:16672-16709 | 17 | 1 (1/0) | R src r32; dst r32; W dst r32, r64, var_off (not on early return) | `(u32)` cast, unary minus on unsigned, u32 -> s32 implicit, ternary, `min()`/`max()`, if/else-if chain | min, max | pure (writes *dst_reg only) |
| scalar_min_max_smod | verifier.c:16711-16748 | 17 | 1 (1/0) | R src r64; dst r64; W dst r64, r32, var_off (not on early return) | same with u64/s64 | min, max | pure (writes *dst_reg only) |

### Stride helpers (new 2026-10-09, not in the proposal; kernel/bpf/verifier.c)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| scalar_step_add | verifier.c:1957-1999 | 24 | 4 (1/3); add_scalar_to_reg, adjust_ptr_min_max_vals, sync_linked_regs | R a, b: var_off, r64, base, step; W dst base, step (`a` may alias `dst`, as in adjust_scalar_min_max_vals:17218) | check_add_overflow (s64), `(s64)` cast, `%` by variable (u16 step), imod, pointer selection between `a`/`b` | check_add_overflow, imod | pure (writes *dst_reg only) |
| scalar_step_scale | verifier.c:2001-2034 | 13 | 2 (2/0) | R dst r64, base, step; W dst base, step | check_mul_overflow x3 (u16*u64 into u16; s64*s64 into s64), `(s64)` cast, u16 `*` u64 truncated into u16 | check_mul_overflow | pure (writes *dst_reg only) |
| scalar_step_mul | verifier.c:16135-16141 | 7 | 1 (1/0) | R src var_off; W dst base, step | none | none | pure (writes *dst_reg only) |
| scalar_step_lsh | verifier.c:16143-16151 | 8 | 1 (1/0) | R src var_off; W dst base, step | shift by variable `1ULL << amount` (guarded `amount < 64`) | none | pure (writes *dst_reg only) |
| reg_step_check_unsigned | verifier.c:2056-2060 | 5 | 2 (2/0) | R r64; W base, step | shift by variable `1ULL << bits` (precondition 0 < bits < 64) | none | pure (writes *reg only) |

### Dispatcher and context (not themselves proposed; kernel/bpf/verifier.c, states.c)

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| adjust_scalar_min_max_vals | verifier.c:17181-17347 | 138 | 2 (0/2); adjust_reg_min_max_vals, check_alu_op | RW dst var_off, r64, r32, base, step (and every field via __mark_reg_known/__mark_reg_unknown); R src by value (struct copy) | `switch` on opcode with nested if/else, struct copied into `env->fake_reg[0]`, `-1ull` | BPF_OP, BPF_CLASS, sanitize_needed, sanitize_val_alu, sanitize_err, __mark_reg_unknown, maybe_fork_scalars (push_stack), scalar_byte_swap | impure: writes `env->fake_reg[0]`, may push a new verifier state (maybe_fork_scalars), sanitize_* use env |
| is_safe_to_compute_dst_reg_range | verifier.c:17098-17146 | 37 | 1 (1/0) | R src var_off, r64, r32 | `switch` with fallthrough case groups, ternary | BPF_OP, BPF_CLASS | pure (reads *insn, *src_reg only) |
| zext_32_to_64 | verifier.c:6091-6096 | 6 | 3 (1/2); check_alu_op, sync_linked_regs | RW var_off; R r32; W r64, base, step | none | none | pure (writes *reg only) |
| coerce_reg_to_size | verifier.c:6101-6124 | 13 | 2 (0/2); check_mem_access, scalar_byte_swap | RW var_off, r64, r32, base, step | shift by variable `1ULL << (size * 8)` (size < 8 by precondition), `int size` | none | pure (writes *reg only) |
| regsafe | states.c:527-678 | 62 | 4 (0/4); func_states_equal, stack_arg_safe, stacksafe (2 sites) (all states.c) | R rold/rcur: type, precise, id, delta, parent_id, map_uid, range, r64.base, var_off, r64, r32, base, step (via range_within) | `switch` on base_type, memcmp over struct prefixes with offsetof, enum parameter | regs_exact, base_type, memcmp, check_ids, check_scalar_ids | impure: `check_ids`/`check_scalar_ids` record id mappings in `*idmap`; reads `env->explore_alu_limits` |

## Stretch

| name | file:lines | LOC | callers total (in/out); out-of-scope callers | fields | C constructs | kernel helpers | pure |
|---|---|---|---|---|---|---|---|
| regs_refine_cond_op (proposed) | verifier.c:18252-18388 (fwd decl :17913) | 113 | 2 (2/0) | RW reg1/reg2: var_off, r64, r32; W reg1 base, step (JSET\|BPF_X case); R type (via is_reg_const) | two `switch` statements, `swap()` of the two pointer parameters, compound literals `(struct cnum32){ val + 1, U32_MAX - 1 }` with implicit u64 -> u32 narrowing, `BPF_JSET \| BPF_X` pseudo-opcode, wrapping `+1`/`-1` on bounds | hweight64, swap, bpf_flip_opcode | pure (writes *reg1, *reg2 only) |
| is_reg_const (proposed) | verifier.c:3748-3752 | 5 | 12 (8/4); adjust_reg_min_max_vals, is_branch_taken, record_func_key | R type, var_off | ternary | none | pure (reads *reg only) |
| reg_const_value (proposed) | verifier.c:3755-3758 | 4 | 5 (3/2); adjust_reg_min_max_vals, is_branch_taken | R var_off | ternary | none | pure (reads *reg only) |
| bpf_flip_opcode (proposed) | verifier.c:18109-18128 (prototype bpf_verifier.h:2007, non-static) | 17 | 4 (1/3); is_branch_taken, is_pkt_ptr_branch_taken, match_linear_latch (scev.c) | n/a | `static const u8 opcode_flip[16]` array local with designated initializers, shift by constant, unchecked index `opcode >> 4` | none | pure (by value) |
| bpf_rev_opcode (proposed) | verifier.c:18229-18249 (prototype bpf_verifier.h:2008, non-static) | 18 | 2 (1/1); match_linear_latch (scev.c) | n/a | `switch` | none | pure (by value) |
| simulate_both_branches_taken (context) | verifier.c:17920-17948 | 14 | 1 (1/0) | RW env->false_reg1, false_reg2, true_reg1, true_reg2 (all fields) | tri-state int return (1/0/-1) | none | impure: operates on four scratch registers inside `env` |
| is_scalar_branch_taken (context) | verifier.c:17953-18107 | 136 | 1 (0/1); is_branch_taken | R reg1/reg2: var_off, r64, r32 (via accessors); indirectly RW env scratch regs via simulate_both_branches_taken | two `switch` statements (one with fallthrough groups), `swap()` of pointers and of tnum values, `(u64)`/`(s64)` casts, ternaries, pointer-equality test `reg1 == reg2` | swap | impure: via simulate_both_branches_taken (env scratch registers) |

## Totals per layer (from `totals.py` over `ranges.tsv`)

| group | functions | LOC |
|---|---|---|
| A1 tnum.c (proposed) | 28 | 193 |
| A2 tnum.h inline (proposed) | 4 | 16 |
| A3 cnum_defs.h templates (proposed, counted once) | 20 | 143 |
| A4 cnum.c (proposed) | 3 | 56 |
| A5 imod (proposed) | 1 | 6 |
| **Layer A proposed, templates counted once** | **56** | **414** |
| Layer A proposed, both instantiations counted (20 templates x2) | 76 | 557 |
| B1 sync and helpers (proposed) | 14 | 107 |
| B2 invariant checks (proposed) | 3 | 47 |
| B3 accessors (proposed) | 12 | 48 |
| B4 small state helpers (proposed) | 7 | 37 |
| B5 ALU transfer functions IN (proposed, incl. two `__scalar*_lsh` helpers) | 18 | 195 |
| B6 pruning (proposed): range_within (tnum_in is in A1) | 1 | 13 |
| **Layer B proposed** | **55** | **447** |
| B7 ALU transfer functions OUT (extra) | 10 | 166 |
| B8 stride helpers (extra) | 5 | 57 |
| B9 context: adjust_scalar_min_max_vals, is_safe_to_compute_dst_reg_range, zext_32_to_64, coerce_reg_to_size, regsafe | 5 | 256 |
| **Layer B extra + context** | **20** | **479** |
| S1 stretch (proposed): regs_refine_cond_op, is_reg_const, reg_const_value, bpf_flip_opcode, bpf_rev_opcode | 5 | 157 |
| S2 stretch context: simulate_both_branches_taken, is_scalar_branch_taken | 2 | 150 |
| **All proposed (A+B+S1), templates once** | **116** | **1018** |
| All proposed, templates x2 | 136 | 1161 |
| **All extra + context (B7-B9, S2)** | **22** | **629** |

`reg_step_reset` and `__update_bounds_from_step` are counted under B1 because SCOPE.md lists
them there, even though they were added by the stride series (0892ef2a7ef3) after the proposal
was written; moving them to B8 would give B1 = 12 functions / 97 LOC and B8 = 7 / 67.

## scalar_min_max_* functions present in verifier.c

From `/usr/bin/grep -n 'scalar.*_min_max_' kernel/bpf/verifier.c` (definition lines only; the
grep also returns the forward declarations at :224-225 and the call sites):

| function | definition line | proposed list |
|---|---|---|
| scalar32_min_max_add | 16452 | IN |
| scalar_min_max_add | 16458 | IN |
| scalar32_min_max_sub | 16464 | IN |
| scalar_min_max_sub | 16470 | IN |
| scalar32_min_max_mul | 16476 | OUT |
| scalar_min_max_mul | 16507 | OUT |
| scalar32_min_max_udiv | 16538 | OUT |
| scalar_min_max_udiv | 16550 | OUT |
| scalar32_min_max_sdiv | 16562 | OUT |
| scalar_min_max_sdiv | 16598 | OUT |
| scalar32_min_max_umod | 16634 | OUT |
| scalar_min_max_umod | 16653 | OUT |
| scalar32_min_max_smod | 16672 | OUT |
| scalar_min_max_smod | 16711 | OUT |
| scalar32_min_max_and | 16750 | IN |
| scalar_min_max_and | 16771 | IN |
| scalar32_min_max_or | 16794 | IN |
| scalar_min_max_or | 16815 | IN |
| scalar32_min_max_xor | 16838 | IN |
| scalar_min_max_xor | 16854 | IN |
| __scalar32_min_max_lsh | 16872 | IN (helper) |
| scalar32_min_max_lsh | 16886 | IN |
| __scalar64_min_max_lsh | 16904 | IN (helper) |
| scalar_min_max_lsh | 16930 | IN |
| scalar32_min_max_rsh | 16945 | IN |
| scalar_min_max_rsh | 16975 | IN |
| scalar32_min_max_arsh | 17007 | IN |
| scalar_min_max_arsh | 17027 | IN |
| adjust_scalar_min_max_vals | 17181 | context (dispatcher) |

No other `scalar*_min_max_*` symbol exists (the same grep finds nothing for neg, end, div,
mod without the u/s prefix; BPF_NEG is handled by the sub functions via `env->fake_reg[0]`,
verifier.c:17229-17236; BPF_END by `scalar_byte_swap`, :17048, out of scope).

## Rename map (old name -> current name)

Method: `git show <commit> -- kernel/bpf/verifier.c include/linux/bpf_verifier.h kernel/bpf/states.c | /usr/bin/grep -E '^[-+](static |u64|s64|u32|s32|bool|void|int|struct)[^;=]*\('`
for each commit, `git log -S<name>` to find the commit that removed/added a name,
`git log -L` on function bodies, and the v7.3-rc5 vs HEAD function-list diff
(`comm -23`/`comm -13` on the `funcs_*.txt` files). Dates from `git log --format='%h %ad %s' --date=short`.
Note: `v7.3-rc5` is dated 2026-09-27 and already contains the cnum series and the states.c
move (`git merge-base --is-ancestor` confirms both), but not the stride series; so the
v7.3-rc5 comparison only shows the October changes (`flip_opcode`/`rev_opcode` removed;
`bpf_flip_opcode`, `bpf_rev_opcode`, `reg_step_reset`, `reg_step_check_unsigned`,
`scalar_step_{add,scale,mul,lsh}`, `__update_bounds_from_step`, `bpf_mark_reg_known_scalar`,
`bpf_set_reg_range`, `bpf_reg_union`, `bpf_reg_union_compatible` added in verifier.c;
nothing removed and `bpf_split_cur_state`, `current_loop`, `loop_stack_safe`,
`need_loop_checkpoint` added in states.c).

Commits involved:

| commit | date | subject |
|---|---|---|
| 3f50f132d840 | 2020-03-30 | bpf: Verifier, do explicit ALU32 bounds tracking (introduced the `__reg32_*`/`__reg64_*`/`__reg_combine_*` names) |
| 9e314f5d8682 | 2023-11-01 | bpf: drop knowledge-losing __reg_combine_{32,64}_into_{64,32} logic |
| efc11a667878 | 2026-02-27 | bpf: Improve bounds when tnum has a single possible value (adds the tnum_step logic to `__update_reg64_bounds`; `tnum_step` itself added by 76e954155b45, same date) |
| 879cace97667 | 2026-03-13 | bpf: better naming for __reg_deduce_bounds() parts |
| c82834a5a11f | 2026-04-12 | bpf: Move state equivalence logic to states.c |
| 256f0071f9b6 | 2026-04-24 | bpf: representation and basic operations on circular numbers (adds cnum.h, cnum.c, cnum_defs.h; no verifier.c changes) |
| b93f7180f0bc | 2026-04-24 | bpf: use accessor functions for bpf_reg_state min/max fields |
| bbc631085503 | 2026-04-24 | bpf: replace min/max fields with struct cnum{32,64} |
| cd5b460ed1ec | 2026-04-25 | bpf: range_within() must check cnum ranges instead of min/max pairs |
| 79b8ebcbe483 | 2026-04-27 | bpf: Export cnum_umin/umax() helpers for netronome driver |
| 4072d7f56b44 / a8e9a53f6df6 / 78e61c01a760 | 2026-10-09 | bpf: Add tnum_alignment() / cnum{32,64}_union() / cnum64_intersect_linear() (the last also adds `imod()`) |
| 685ac494443e | 2026-10-09 | bpf: Expose bpf_rev_opcode() and bpf_flip_opcode() |
| 0892ef2a7ef3 | 2026-10-09 | bpf: Representation for intervals with steps |

Map:

| old | current | commit(s) | notes |
|---|---|---|---|
| `s64 smin_value`, `s64 smax_value`, `u64 umin_value`, `u64 umax_value` fields | `struct cnum64 r64` | bbc631085503 | field removal/addition seen in the `include/linux/bpf_verifier.h` hunk of that commit; b93f7180f0bc had first routed all reads/writes through `reg_smin()`.. `reg_set_urange64()` |
| `s32 s32_min_value`, `s32 s32_max_value`, `u32 u32_min_value`, `u32 u32_max_value` fields | `struct cnum32 r32` | bbc631085503 | same |
| (none) | `reg_smin`, `reg_smax`, `reg_umin`, `reg_umax`, `reg_s32_min`, `reg_s32_max`, `reg_u32_min`, `reg_u32_max`, `reg_set_srange32`, `reg_set_urange32`, `reg_set_srange64`, `reg_set_urange64` | b93f7180f0bc (added, returning the raw fields); bbc631085503 (bodies switched to cnum) | new accessors in bpf_verifier.h |
| `__reg32_deduce_bounds` | split into `deduce_bounds_32_from_64` + `deduce_bounds_32_from_32` | 879cace97667 | then `deduce_bounds_32_from_32` (the s32<->u32 deduction) removed by bbc631085503; `deduce_bounds_32_from_64` survives (body now `cnum32_intersect_with(&reg->r32, cnum32_from_cnum64(reg->r64))`) |
| `__reg64_deduce_bounds` | `deduce_bounds_64_from_64` | 879cace97667 | removed by bbc631085503 (signed<->unsigned deduction is implicit in cnum) |
| `__reg_deduce_mixed_bounds` | `deduce_bounds_64_from_32` | 879cace97667 | body replaced by `reg->r64 = cnum64_cnum32_intersect(reg->r64, reg->r32)` in bbc631085503 |
| `__reg_combine_32_into_64`, `__reg_combine_64_into_32`, `__reg64_bound_s32`, `__reg64_bound_u32` | (removed) | 9e314f5d8682 (2023) | replaced by plain `reg_bounds_sync()` calls; predates the cnum series |
| `__reg_assign_32_into_64`, `__reg32_bound_s64` | (removed) | bbc631085503 | `zext_32_to_64` now does `reg_set_urange64(reg, reg_u32_min(reg), reg_u32_max(reg))` (hunk at bbc631085503, verifier.c `zext_32_to_64`) |
| `__update_reg32_bounds` | kept, same name | bbc631085503 | body rewritten from min/max updates to `cnum32_intersect_with(&reg->r32, cnum32_from_tnum(reg->var_off))`; the tnum-to-range computation was split out as new `cnum32_from_tnum` |
| `__update_reg64_bounds` | kept, same name | efc11a667878 (tnum_step single-value logic), b93f7180f0bc, bbc631085503 | min/max part replaced by `cnum64_intersect_with(..., cnum64_from_tnum(...))`; new `cnum64_from_tnum` |
| `__update_reg_bounds`, `__reg_deduce_bounds`, `__reg_bound_offset`, `reg_bounds_sync` | kept, same names | bbc631085503 (bodies), 0892ef2a7ef3 | `__reg_deduce_bounds` now calls only the two 32<->64 helpers; `reg_bounds_sync` gained the final `__update_bounds_from_step()` and `__reg_bound_offset` the base/step trailing-zero refinement in 0892ef2a7ef3 |
| `__mark_reg32_known` | kept, same name | b93f7180f0bc, bbc631085503 | body history (`git log -L`): four field writes (`s32_min_value`..`u32_max_value` = imm) -> `reg_set_srange32` + `reg_set_urange32` (b93f) -> single `reg->r32 = cnum32_from_urange((u32)imm, (u32)imm)` (bbc63). Still does not reset base/step (unlike `___mark_reg_known`) |
| `___mark_reg_known` | kept | bbc631085503, 0892ef2a7ef3 | now writes `r64`/`r32` via `cnum*_from_urange` and calls `reg_step_reset` |
| `__mark_reg_unbounded`, `__mark_reg32_unbounded`, `__mark_reg64_unbounded` | kept | b93f7180f0bc, bbc631085503 | bodies now `CNUM{32,64}_UNBOUNDED`; definition order changed in bbc63 (the grep shows each name removed and re-added) |
| `range_bounds_violation` | kept | bbc631085503 | min > max checks -> `cnum32_is_empty \|\| cnum64_is_empty` |
| `range_within` (verifier.c) | `range_within` (states.c:302) | c82834a5a11f (move), b93f7180f0bc (accessors), cd5b460ed1ec (`cnum*_is_subset`), 0892ef2a7ef3 (step/base check) | `regsafe` moved in the same commit |
| `flip_opcode` (static int), `rev_opcode` (static u8) | `bpf_flip_opcode`, `bpf_rev_opcode` (non-static, prototypes in bpf_verifier.h:2007-2008) | 685ac494443e | needed by scev.c |
| (none) | `reg_step_reset`, `scalar_step_add`, `scalar_step_scale`, `reg_step_check_unsigned`, `__update_bounds_from_step`, `scalar_step_mul`, `scalar_step_lsh`; fields `u16 base, step` | 0892ef2a7ef3 | new |
| (none) | `imod` (bpf_verifier.h), `cnum64_intersect_linear` | 78e61c01a760 | new |
| (none) | `cnum{32,64}_union` | a8e9a53f6df6 | new (used only by `bpf_reg_union`) |
| (none) | `tnum_alignment` | 4072d7f56b44 | new (used only by scev.c `linear_bounds`) |
| (none) | `tnum_step` | 76e954155b45 | new 2026-02-27 |
| `cnum{32,64}_umin/umax` static | exported with `EXPORT_SYMBOL_GPL` | 79b8ebcbe483 | the nfp driver does not call cnum functions directly (`git grep cnum -- drivers/` finds nothing); it calls the inline `reg_umin`/`reg_umax` (nfp/bpf/verifier.c:564-567), which expand to `cnum64_umin/umax`, hence the modpost error quoted in that commit |

Nothing in this map is UNVERIFIED: every row was pinned to a commit by one of the commands
above. One item of judgement: whether `deduce_bounds_32_from_64` "is" the old
`__reg32_deduce_bounds` is a naming question (879cace97667 split that function in two and
bbc631085503 later deleted the other half).

## MAINTAINERS

Command: `./scripts/get_maintainer.pl --sections --no-git-fallback -f <file>` (run from
`~/linux-ebpf`, read-only). Results per file (section names only; the full section text is
quoted once below):

| file | sections returned (in order) |
|---|---|
| kernel/bpf/tnum.c | BPF [CORE]; BPF [GENERAL]; THE REST |
| include/linux/tnum.h | BPF [CORE]; THE REST (not BPF [GENERAL]: that section lists `include/linux/bpf*` and `btf*`, not `tnum.h`) |
| kernel/bpf/verifier.c | BPF [CORE]; BPF [GENERAL]; THE REST |
| include/linux/bpf_verifier.h | BPF [GENERAL]; BPF [CORE]; THE REST (both via `include/linux/bpf*`) |
| kernel/bpf/cnum.c | BPF [GENERAL] (via `kernel/bpf/`); THE REST |
| kernel/bpf/cnum_defs.h | BPF [GENERAL] (via `kernel/bpf/`); THE REST |
| kernel/bpf/states.c | BPF [GENERAL] (via `kernel/bpf/`); THE REST |
| include/linux/cnum.h | THE REST only: no BPF section matches `include/linux/cnum.h` |

So `cnum.c`, `cnum_defs.h` and `states.c` are not listed under `BPF [CORE]`; they are covered
only by the `kernel/bpf/` glob of `BPF [GENERAL]`. `include/linux/cnum.h` is covered by
neither BPF section (only by the catch-all `THE REST`). The `BPF [CORE]` section names
`tnum.c`, `tnum.h` and `verifier.c` explicitly.

`grep -n -B2 -A20 'BPF \[CORE\]' MAINTAINERS` (lines 4917-4939), verbatim section:

```
BPF [CORE]
M:	Alexei Starovoitov <ast@kernel.org>
M:	Daniel Borkmann <daniel@iogearbox.net>
R:	John Fastabend <john.fastabend@gmail.com>
L:	bpf@vger.kernel.org
S:	Maintained
F:	include/linux/bpf*
F:	include/linux/filter.h
F:	include/linux/tnum.h
F:	kernel/bpf/core.c
F:	kernel/bpf/dispatcher.c
F:	kernel/bpf/mprog.c
F:	kernel/bpf/syscall.c
F:	kernel/bpf/tnum.c
F:	kernel/bpf/trampoline.c
F:	kernel/bpf/verifier.c
```

`BPF [GENERAL]` (MAINTAINERS lines 4949-4995), verbatim:

```
BPF [GENERAL] (Safe Dynamic Programs and Tools)
M:	Alexei Starovoitov <ast@kernel.org>
M:	Daniel Borkmann <daniel@iogearbox.net>
M:	Andrii Nakryiko <andrii@kernel.org>
M:	Eduard Zingerman <eddyz87@gmail.com>
M:	Kumar Kartikeya Dwivedi <memxor@gmail.com>
R:	Martin KaFai Lau <martin.lau@linux.dev>
R:	Song Liu <song@kernel.org>
R:	Yonghong Song <yonghong.song@linux.dev>
R:	Jiri Olsa <jolsa@kernel.org>
R:	Emil Tsalapatis <emil@etsalapatis.com>
R:	Ihor Solodrai <ihor.solodrai@linux.dev>
L:	bpf@vger.kernel.org
S:	Supported
W:	https://bpf.io/
Q:	https://patchwork.kernel.org/project/netdevbpf/list/?delegate=121173
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git
F:	Documentation/bpf/
F:	Documentation/networking/filter.rst
F:	Documentation/userspace-api/ebpf/
F:	arch/*/include/asm/rqspinlock.h
F:	arch/*/net/*
F:	include/asm-generic/rqspinlock.h
F:	include/linux/bpf*
F:	include/linux/btf*
F:	include/linux/buildid.h
F:	include/linux/filter.h
F:	include/trace/events/xdp.h
F:	include/uapi/linux/bpf*
F:	include/uapi/linux/btf*
F:	include/uapi/linux/filter.h
F:	kernel/bpf/
F:	kernel/trace/bpf_trace.c
F:	lib/buildid.c
F:	net/bpf/
F:	net/core/filter.c
F:	net/sched/act_bpf.c
F:	net/sched/cls_bpf.c
F:	samples/bpf/
F:	scripts/Makefile.btf
F:	scripts/bpf_doc.py
F:	scripts/gen-btf.sh
F:	scripts/pahole-version.sh
F:	tools/bpf/
F:	tools/lib/bpf/
F:	tools/testing/selftests/bpf/
```

## Observations and ambiguities

- `tnum_sbin` has no caller in the tree at HEAD (`git grep -n 'tnum_sbin('`); it is listed in
  SCOPE.md, so it is kept in the table and in the Layer A totals (18 LOC).
- `tnum_in` is listed in SCOPE.md both under Layer A and under "Pruning"; it is counted once
  (in A1).
- Caller counts are call sites. Functions called from the macro-templated `cnum_defs.h` are
  counted once per textual `FN(x)` use, which stands for both instantiations.
- The in-scope/out-of-scope split treats the context rows (dispatcher, `regsafe`,
  `simulate_both_branches_taken`, `is_scalar_branch_taken`) as in-scope callers, because
  they are rows of this inventory. If only "proposed" functions count as in-scope, the
  following rows move entirely to out-of-scope: `is_safe_to_compute_dst_reg_range` (1 site),
  `range_within` (4 sites, all from `regsafe`), `tnum_in`'s 4 in-scope sites,
  `regs_refine_cond_op` (2 sites), `scalar_step_scale` (2 sites), `reg_step_check_unsigned`
  (2 sites), and the ALU functions' single site each from `adjust_scalar_min_max_vals`.
- `cnum{T}_umin/umax` are exported for the netronome driver, but that driver reaches them
  only through the inline accessors `reg_umin`/`reg_umax` (see rename map).
- `include/linux/cnum.h` matches no BPF MAINTAINERS entry at HEAD.
- `__mark_reg32_known` does not reset `base`/`step` while `___mark_reg_known` does; this is
  how the code reads at HEAD (verifier.c:2063-2069 vs :2091-2095), not a finding.
- C-level points worth tracking for the Rust model (observed from the source, not tested):
  `__scalar32_min_max_lsh` shifts a `u32` by a `u64` amount (32-bit shift) and compares a
  `u32` against `1ULL << (31 - umax_val)`; `tnum_cast` and `coerce_reg_to_size` rely on
  `size < 8`; `tnum_arshift`/`scalar*_min_max_arsh` use arithmetic right shift of signed
  values; `cnum64_intersect_linear` narrows `base - imod(...)` (s64) into a `u16` before the
  outer `imod`; `scalar_step_scale` multiplies `u16 base * u64 amount` and truncates to u16
  (safe only because the preceding `check_mul_overflow` on `step` succeeded); the
  `scalar*_min_max_{umod,smod}` early-return paths leave `var_off` and the other width's
  range untouched.
