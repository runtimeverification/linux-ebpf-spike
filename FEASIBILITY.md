# Aeneas feasibility (task 5)

Everything here was run on 2026-10-19 with the versions in `ENV.md`. "Pinned pair" =
Charon 909ff09a (0.1.220) + Aeneas c2015b86; "HEAD pair" = Charon b104e24f (0.1.254) +
Aeneas 505b6ca3-dirty in `~/aeneas_merge_abstractions`. Commands are given so that each
result can be reproduced.

## 1. The Rust port (`rust/model`, crate `bpf_model`)

Safe Rust only (`#![forbid(unsafe_code)]`), no dependencies, one function per C function with
the C name, field names and integer widths. `cargo build --release -p bpf_model` and
`cargo clippy -p bpf_model` are clean apart from style lints.

| module | C source | functions | notes |
|---|---|---|---|
| `tnum_c.rs` | `kernel/bpf/tnum.c`, `tnum.h` inlines | 28 + 4 | plus `fls64`, `__ffs64`, `swab16/32/64` written out as in the kernel headers so that no `core` intrinsic is needed |
| `cnum_c.rs` | `cnum.c`, `cnum_defs.h`, `cnum.h`, `imod()` | 20 x 2 + 3 + 1 | `cnum_defs.h` is a C template included for T=32 and T=64; the port is a `macro_rules!` instantiated twice with every derived identifier passed explicitly |
| `verifier_c.rs` | `verifier.c`, `states.c`, `bpf_verifier.h` accessors | 61 | `reg_bounds_sync` and all its helpers, the invariant checks, the 12 accessors, 7 state helpers, the 16 proposed transfer functions and their 2 helpers, `mul` (x2), 5 stride helpers, `zext_32_to_64`, `coerce_reg_to_size`, `range_within`, `reg_bounds_sanity_check` |
| `probes.rs` | none | 31 | one tiny function per construct named in the task |

Not ported: `udiv/sdiv/umod/smod` (not in the proposed list), `regs_refine_cond_op` and its
helpers (stretch), `tnum_strn` (formatting, in `log.c`), `adjust_scalar_min_max_vals`
(dispatcher on the instruction encoding), `tnum_sbin` *is* ported (`&mut [u8]` instead of
`char *, size_t`).

**`struct bpf_reg_state` is modelled by its five value-tracking fields only**
(`var_off`, `r64`, `r32`, `base`, `step`). `__mark_reg_known` therefore only does what
`___mark_reg_known` does (in C it also memsets the pointer union and clears `id`,
`parent_id`, `map_uid`).

**By value or `&mut`.** Every function that takes `struct bpf_reg_state *` in C takes
`&mut BpfRegState` (if it writes) or `&BpfRegState` (if it only reads), so that the Rust reads
like the C and the differential harness can call both with the same inputs. Aeneas turns
`&mut` into an extra return value (`Result (… × BpfRegState)`), which is what a proof wants
anyway. The `cnum*_intersect_with*` family likewise takes `&mut Cnum`. All tnum and cnum
functions take and return values, as in C. Two deviations forced by Rust's aliasing rules:

| function | C | Rust | why |
|---|---|---|---|
| `scalar_step_add(dst, a, b)` | called as `scalar_step_add(dst, dst, &src)`, `a` aliases `dst` | `a` and `b` by value (copies) | `&mut dst` and `&dst` cannot coexist; the result is identical because the C reads `a` before writing `dst` |
| `reg_bounds_sanity_check` | four checks with `goto out` | the checks are a read-only helper `reg_invariants_violated(&reg)`; the function then mirrors the C | with `&mut` in a `||` chain Aeneas threads the register through every branch and the generated `if` on the threaded Bool fails to elaborate ("failed to synthesize Decidable") |

Other translation choices: `swap(a, b)` becomes a tuple rebinding; `min()`/`max()` on
integers are written as `if a < b { a } else { b }` (the `Ord::min` method and `core::cmp::max`
both translate fine, see the probes, but the `if` keeps the Lean output free of trait
dispatch); `min_array`/`max_array` are four-element loops; `check_*_overflow` become
`checked_add`/`checked_mul` (the kernel macro is `__builtin_*_overflow`, which also writes the
wrapped result on overflow, but every caller overwrites it in that case); the C parameter
`in` of `cnum64_intersect_linear` is `input` (Rust keyword). Wrapping arithmetic is spelled
`wrapping_*` wherever the C can wrap on inputs allowed by the function's precondition; plain
`+`/`-`/`<<` are used where the C guards against it, which gives Aeneas a provable side
condition instead of silently wrapping.

## 2. Charon and Aeneas on the whole crate

```
cd rust/model
LD_LIBRARY_PATH=<dir containing only libz.so.1> ~/charon/bin/charon cargo --preset=aeneas \
    --dest-file ../../lean/bpf_model.llbc
cd ../../lean && ~/aeneas-project/aeneas/bin/aeneas -backend lean -dest . bpf_model.llbc
lake build BpfModel
```

| step | pinned pair | HEAD pair |
|---|---|---|
| Charon | ok, 2.9 MB LLBC, 266 declarations, ~10 s | ok |
| Aeneas | 212 of 213 transparent functions translated; `probe_bool_guard_ref` fails with `Unreachable` (Interp.ml:609) and is emitted with `sorry`; exit 1, "partial file" | all 213 translated, exit 0 |
| `lake build BpfModel` | ok (3.7 s for the file; 1696 jobs with dependencies) | not run |
| axioms in the output | `core.num.U64.trailing_zeros`, `core.num.U16.swap_bytes`, `core.num.U32.wrapping_neg`, `core.num.U64.wrapping_neg` (4 opaque externals, see 3) | same 4 |

Failures and workarounds, in the order met:

| # | error | construct | workaround | HEAD pair |
|---|---|---|---|---|
| 1 | `charon-driver: error while loading shared libraries: libz.so.1` from `~/aeneas-project/aeneas/charon/bin/charon` | environment: the driver is a nix build; under `rustup run` the loader resolves `librustc_driver` from the rustup toolchain and then cannot find `libz` | `LD_LIBRARY_PATH` set to a directory containing only a symlink to the nix `libz.so.1` (a plain `/lib/x86_64-linux-gnu` breaks `charon` itself: `GLIBC_2.39 not found`) | n/a (native build) |
| 2 | Aeneas: `Incompatible version of charon: this program supports llbc emitted by charon v0.1.220 but attempted to read a file emitted by charon v0.1.170` | the binary in `~/aeneas-project/aeneas/charon/bin` is a stale build (2026-02-26) of the pinned checkout (909ff09a declares 0.1.220) | use `~/charon/bin/charon`, which is 909ff09a built on 2026-07-10 and prints 0.1.220 | n/a |
| 3 | Aeneas `Unreachable`, `Interp.ml:609`, in `probe_bool_guard_ref` | bool guard read through `&bool`, joined value used in a later condition (Aeneas issue #1347) | none needed for the port (no such pattern in the kernel code); the probe is left in with `sorry` | accepted |
| 4 | `lake`: `Invalid field 'cnum32_from_tnum': The environment does not contain 'bpf_model.reg.BpfRegState.cnum32_from_tnum'` (100 errors) | Rust module `reg` and parameter `reg`: Aeneas emits the call `reg.cnum32_from_tnum …` inside `namespace bpf_model`, and Lean reads it as a projection on the local `reg` | modules renamed `tnum_c`, `cnum_c`, `verifier_c` so that no module name is also a parameter name | same output shape, same fix applies |
| 5 | `lake`: `failed to synthesize Decidable violated` in `reg_bounds_sanity_check` | `let violated = a(reg) \|\| b(reg) \|\| …` with `reg: &mut`, then `if !violated`: Aeneas threads `reg` through the chain as `let (reg1, violated) ← if …` and the later `if violated` does not elaborate | read-only helper `reg_invariants_violated(&BpfRegState)` | not checked |
| 6 | (not an error) `derive(Debug, PartialEq, Eq)` on the model types produced `Debug` vtables and `assert_fields_are_eq` axioms in the output | derived trait impls | derives are behind a cargo feature `difftest` that only the harness enables | n/a |

## 3. Construct probes (`rust/model/src/probes.rs`, pinned pair)

| construct | result |
|---|---|
| `wrapping_add/sub/mul` | translated to `core.num.U64.wrapping_*`, pure, with `_bv_eq` simp lemmas in the Aeneas library |
| `wrapping_neg` (u32, u64) | **opaque**: becomes an `axiom core.num.U64.wrapping_neg : U64 → Result U64`; the port uses it in `cnum*_negate`. Fix: write `0u64.wrapping_sub(x)` or add the definition to the Aeneas library |
| `checked_add`, `checked_mul` | translated (`I64.checked_add`, `I32.checked_mul`, returning `Option`); `match` on the option works |
| `overflowing_add` | translated (`core.num.U32.overflowing_add`) |
| `leading_zeros` | translated (`core.num.U64.leading_zeros`) |
| `trailing_zeros` | **opaque** (axiom); used by `__ffs64`/`count_trailing_zeros` in the port. Fix: express via `leading_zeros` of the reversed value, or add the definition to the library |
| shift by a variable amount with the C guard | translated to `if n > 63 then … else x <<< n`; the shift returns `Result` and fails for amounts >= width, so the guard is exactly the side condition |
| shift `u32 << u64` (mixed widths) | translated (`x <<< n` with `n : U64`) |
| `as` casts i32/u32/i64/u64 | translated to `IScalar.hcast`/`UScalar.hcast`/`cast` |
| `a.min(b)` (method), `core::cmp::max` | translated (`core.cmp.impls.OrdU64.min`, `core.cmp.max core.cmp.OrdI64`) |
| 64-iteration `while` loop | translated to `probe_loop64_loop` with a `loop` combinator and a `body` returning `ControlFlow`; `tnum_mul` likewise |
| early `return` | translated to nested `if` |
| `match` on an enum | translated to `match` |
| struct update through `&mut` | translated: the struct is an input and an output (`{ p with lo := i }`) |
| bool guard through `&bool` | **fails on the pinned pair** (issue #1347), passes on HEAD |
| `u16::swap_bytes` | **opaque** (axiom); the port does not use it (`swab16` is written out) |
| `i64 % u16` | translated (`v % i` in `Result`, so the zero-divisor side condition is explicit) |
| fixed array `[i32; 4]` index, slice write | translated (`Array.index_usize`, `Slice.update`) |

## 4. Smoke-test proof: `tnum_add` contains the sum (`lean/Proofs/TnumAdd.lean`)

Statement (membership is the kernel's own test, `(x & ~mask) == value`):

```lean
def Tnum.mem (t : Tnum) (x : U64) : Prop := x.bv &&& ~~~t.mask.bv = t.value.bv
theorem tnum_add_sound (a b : Tnum) (x y : U64) (hx : a.mem x) (hy : b.mem y) :
    ∃ r, tnum_add a b = ok r ∧ r.mem (x.wrapping_add y)
```

The statement also says `tnum_add` never fails. Two proofs were attempted:

1. **Bit-blasting.** After `simp only [tnum_add, TNUM, lift, Tnum.mem]` and the Aeneas
   `_bv_eq` lemmas the goal is a `BitVec 64` identity; Aeneas's `bv_tac 64` (a wrapper around
   Lean's `bv_decide`, i.e. a SAT solver with a checked LRAT certificate) closes it in about
   1 s. `#print axioms`: `propext, Classical.choice, Quot.sound,
   tnum_add_sound._native.bv_decide.ax_1_8`. The last axiom is `bv_decide`'s native-evaluation
   axiom for the certificate checker, so by rule 5 of `CLAUDE.md` this does **not** count as
   "proved"; it is kept as `tnum_add_sound_bv`.
2. **Manual proof** (carry argument: for a bit `i` outside `mu`, the carry into `i` when adding
   members `x`, `y` equals the carry when adding `value`s, because `value & mask == 0` bounds
   the low parts so that `sv_lo + am_lo + bm_lo < 2^(i+1)`; the rest is linear arithmetic).
   **Done.** `tnum_add_sound` is closed with no `sorry`; `#print axioms tnum_add_sound` prints
   `[propext, Classical.choice, Quot.sound]`, so by rule 5 this theorem is *proved*.
   The proof is 8 helper lemmas over general `BitVec w` (about 120 lines): a Nat lemma for the
   carry case split (`omega`), three bitwise identities (`BitVec.eq_of_getLsbD_eq` + `decide`),
   two lemmas bounding the low `i` bits of `X &&& ~~~M` and `X` (`BitVec.toNat_setWidth`,
   `setWidth_and/or`, `toNat_add_of_and_eq_zero`), `toNat_add_mod`, `carry_mem`, and the
   bit-level theorem `tnum_add_bv` finished by `generalize` of the 8 Boolean atoms and
   `decide`; the Aeneas-level theorem is the three reduction lines plus `exact tnum_add_bv`.
   Wall-clock for the proof: about 25 minutes of tactic work in total (statement and bv_decide
   attempt about 20 minutes, manual proof about 4 minutes once the pencil argument was written
   out). `lake build` of the whole project: 3.4 s incremental, 1699 jobs.

## 5. What this shows and does not show

- The whole proposed Layer A and Layer B (minus the stretch) goes through Charon, the pinned
  Aeneas and Lean with two source-level adjustments (module names, one helper); nothing in the
  kernel code itself needed restructuring beyond the aliasing case of `scalar_step_add`.
- Four `core` functions are opaque in this Aeneas version; two of them are used by the port
  (`wrapping_neg`, `trailing_zeros`). They are one-line definitions to add on the Lean side
  (or to avoid in the Rust); until then any theorem about `cnum*_negate`, `__reg_bound_offset`
  or `tnum_alignment` would depend on those axioms.
- Loops (`tnum_mul`, `tnum_sbin`, `min_array`) translate to `loop` combinators; proofs about
  them need the Aeneas loop lemmas (not exercised here).
- The HEAD pair accepts everything; the only reason to prefer it is issue #1347, which the
  kernel code does not trigger.
- `bv_decide` is a very effective tool for the tnum layer (64-bit bit-vector identities) but
  carries an extra axiom; whether that is acceptable is a policy question (see
  `PROPOSAL-INPUTS.md`, open questions).
