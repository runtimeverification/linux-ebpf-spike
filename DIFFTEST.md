# Differential testing: kernel C against the Rust model (task 6)

Kernel: `~/linux-ebpf` at 4f842631f178. Rust model: `rust/model` (crate `bpf_model`).
Harness: `rust/difftest` plus `harness/` (C shim, extraction script, kernel build logs).
All numbers below come from the commands shown; the raw outputs are in
`harness/difftest-1e8.md` (table) and `harness/difftest-1e8.log` (per-function lines).

## 1. Kernel build configuration and compiler command lines

```
make -C ~/linux-ebpf O=~/build-ebpf defconfig
~/linux-ebpf/scripts/config --file ~/build-ebpf/.config --enable CONFIG_BPF_SYSCALL --enable CONFIG_BPF_JIT
make -C ~/linux-ebpf O=~/build-ebpf olddefconfig
make -C ~/linux-ebpf O=~/build-ebpf -j20 V=1 kernel/bpf/tnum.o kernel/bpf/cnum.o
```

Result: `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_CC_IS_GCC=y`,
`CONFIG_GCC_VERSION=110400`; the source tree stayed clean (`git -C ~/linux-ebpf status --short`
printed nothing). Full log: `harness/kbuild-V1.log`; the two `gcc` command lines for
`kernel/bpf/tnum.o` and `kernel/bpf/cnum.o`: `harness/kbuild-cmdlines.txt` (lines 262 and 264
of the log).

Flags kept for the user-space build because they affect semantics (`rust/difftest/build.rs`):

| flag | why it matters |
|---|---|
| `-O2` | same optimisation level as the kernel |
| `-std=gnu11` | GNU C dialect used by the kernel (statement expressions in `min()`/`min_array()`) |
| `-fno-strict-overflow` | signed overflow is defined as wraparound in the kernel build |
| `-fno-strict-aliasing` | kernel default |
| `-funsigned-char` | `char` is unsigned in the kernel build (relevant to `tnum_sbin`) |
| `-fno-delete-null-pointer-checks` | kernel default |
| `-fno-common` | kernel default |

Dropped as irrelevant to these functions: code model, stack protector, retpoline/IBT, alignment,
`-nostdinc` and the kernel include paths, `-Werror` and the warning set, `-D__KERNEL__`,
`-fpatchable-function-entry`, `-mcmodel=kernel`, `-mno-red-zone`, `-fcf-protection`.
`-fwrapv-pointer` was added for the user-space build only (no pointer arithmetic occurs in the
tested code; it is harmless). Compiler: the same `gcc 11.4.0` as the kernel build.

## 2. What is compiled, and how

- `extracted/tnum.c`, `extracted/cnum.c` (and the headers `tnum.h`, `cnum.h`, `cnum_defs.h`)
  are verbatim copies of the kernel files (`harness/extract.py`; each file starts with the source
  path, line range and commit hash). They are compiled unmodified with
  `-I harness/shim -I .`, where `harness/shim/linux/*.h` replace the kernel headers they
  include: fixed-width types, `U32_MAX`/`S64_MIN`..., `min`/`max`/`min_array`/`swap`,
  `fls64`/`__ffs64`/`count_trailing_zeros`, `check_add_overflow`/`check_mul_overflow`
  (= `__builtin_*_overflow`, exactly as `include/linux/overflow.h`), `div_s64_rem`,
  `div64_u64`, `div64_s64`, the `swab16/32/64` constant-folding macros, `EXPORT_SYMBOL_GPL`,
  `__PASTE`.
- The Layer B functions (58 from `verifier.c`, `range_within` from `states.c`, `imod` and the
  12 accessors from `bpf_verifier.h`) are copied verbatim by the same script into
  `extracted/verifier_bounds.c`, `extracted/states_range_within.c`,
  `extracted/bpf_verifier_h_accessors.c`. `harness/c/layer_b.c` includes them after a shim
  `struct bpf_reg_state` that keeps the kernel's field order (`type`, `delta`, the anonymous
  union, `var_off`, `r64`, `r32`, `base`, `step`, `id`, `parent_id`, bitfields) so that the
  `memset`/`offsetof` in `__mark_reg_known()` behave as in the kernel, and exports `k_`-prefixed
  wrappers for the `static` functions. Layout is checked at start-up against the Rust FFI mirror
  (`sizeof` 80, `offsetof(var_off)` 24, `offsetof(base)` 64, `offsetof(id)` 68).
- `rust/difftest/build.rs` compiles the three C units into `libkernel_c.a`; the driver calls C
  and Rust on the same input and compares the results field by field.

Re-extracting at a newer kernel commit is `python3 harness/extract.py ~/linux-ebpf extracted`;
the script fails loudly if a function name has disappeared.

## 3. Inputs

Every case is a vector of random 64-bit words decoded into the function's arguments so that the
C preconditions hold (shift counts below the width, `tnum_cast` size 1..7, `step >= 1` and
`base < step` for register states, constant source registers for the shift transfer functions
because `is_safe_to_compute_dst_reg_range()` guarantees that in the verifier, well-formed
tnums (`value & mask == 0`) for register states). Each word is, with probability 1/4, one of
33 boundary values (0, 1, 2, 3, 4, 7, 8, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000,
S32_MAX, 2^31, U32_MAX, 2^32, 2^32+U32_MAX, 2^32+2^31, S64_MAX, S64_MIN, U64_MAX, U64_MAX-1,
0xffffffff00000000, 0xffffffff80000000, 0xffffffff7fffffff, 0x80000000ffffffff,
S64_MAX-1, S64_MIN+1, 2^31+1, 0xfffffffeffffffff), with probability 1/16 a boundary value
plus a small offset, and otherwise a random word of varied bit density (uniform, AND/OR of two
or three uniform words, small, small negative, 32-bit, high-32-bit, 16-bit). Cnum operands
therefore include empty arcs, full circles, constants, and arcs that wrap through 0 and through
the signed boundary. For the transfer functions the register operands are additionally passed
through the kernel's own `reg_bounds_sync()` half of the time so that consistent states are
covered as well as arbitrary ones. PRNG: xorshift64*, seed per function = `seed + 7919 * index`.

## 4. Results: 10^8 cases per function

```
cd rust && cargo build --release
./target/release/difftest --cases 100000000 --seed 20261019 --threads 16 --markdown \
    > ../harness/difftest-1e8.md 2> ../harness/difftest-1e8.log
```

Total: 103 functions, 10 300 000 000 cases, wall 96.8 s on 16 threads, **0 divergences**
(`grep -c divergences harness/difftest-1e8.log`; `tail -1 harness/difftest-1e8.md`).
Throughput per function is in `harness/difftest-1e8.md`; it ranges from 1.9 M cases/s
(`tnum_mul`, 64-iteration loop) to 59 M cases/s (`tnum_const`), with the `reg_bounds_sync`
family and the transfer functions at 2.3 to 4.4 M cases/s because each case also runs the
kernel's `reg_bounds_sync()` to produce consistent inputs. A single-threaded, single-function
measurement: `tnum_add` 22.3 M cases/s, `reg_bounds_sync` 4.4 M cases/s, `cnum64_union`
19.6 M cases/s (`difftest --cases 2000000 --only <name>`).

Functions covered (103): all 28 of `tnum.c`; 17 of the 20 `cnum_defs.h` template functions for
each width (34; the three `static inline` ones, `urange_overflow`, `srange_overflow`,
`normalize`, are not exported from the kernel object and are exercised through their callers);
`cnum32_from_cnum64`, `cnum64_cnum32_intersect`, `cnum64_intersect_linear`, `imod`;
`reg_bounds_sync` and its six helpers, `cnum32_from_tnum`, `cnum64_from_tnum`,
`range_bounds_violation`, `const_tnum_range_mismatch`, `const_tnum_range_mismatch_32`,
`zext_32_to_64`, `coerce_reg_to_size`; the 18 proposed transfer functions
(`scalar{,32}_min_max_{add,sub,and,or,xor,lsh,rsh,arsh}` plus `scalar{,32}_min_max_mul`);
the four stride helpers; `range_within`. Not covered: `udiv/sdiv/umod/smod` (not ported),
`regs_refine_cond_op` (not ported), the `tnum.h` inline predicates other than through callers,
and `reg_bounds_sanity_check` (log/env dependent; its pure part is tested through the three
predicates).

## 5. Divergences found during development

One, a port error, found by the first 200 000-case smoke run and fixed before the 10^8 run:

| function | minimal input (after automatic shrinking) | C | Rust (before fix) | cause |
|---|---|---|---|---|
| `range_within` | old = {r64 empty, r32 empty, base 2, step 3}, cur = {r64 empty, r32 empty, base 1, step 3} | false | true | C computes `(cur->base - old->base) % old->step` on `u16` operands promoted to `int`, so the difference is signed (-1) and `%` truncates to -1 != 0. The port had used wrapping `u16` subtraction (65535 % 3 == 0). Fixed in `rust/model/src/verifier_c.rs` to compute in `i32`. |

No divergence was attributable to the kernel's C (rule 4 of `CLAUDE.md`): nothing to write
to `FINDINGS.md`. Note that agreement between C and Rust is all this harness shows; it says
nothing about whether the computed bounds are sound.

## 6. Limitations

- C undefined behaviour is avoided by construction (preconditions in section 3), not detected;
  the C is compiled with the kernel's flags, not with sanitizers.
- Inputs are independent random draws; no coverage feedback (LibAFL was not used in this phase).
- The 32-bit template functions that the kernel compiles `static inline` are compared only
  through callers.
