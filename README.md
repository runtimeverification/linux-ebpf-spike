# linux-ebpf-spike

Phase 0 of a proposal to prove the Linux eBPF verifier's scalar value tracking correct
in Lean 4, and to keep the proofs current as bpf-next changes.

Kernel tree: bpf-next/master at 4f842631f178 (2026-10-19).

## What is here

- `rust/model`: a safe Rust model of 124 kernel functions: `kernel/bpf/tnum.c`, the cnum
  files (`cnum.c`, `cnum_defs.h`, `cnum.h`), `reg_bounds_sync()` and its helpers, the ALU
  transfer functions for add, sub, and, or, xor, lsh, rsh, arsh and mul, the stride
  helpers, and `range_within()`. One Rust function per C function, same names, same
  integer widths, no dependencies.
- `extracted/`, `harness/`, `rust/difftest`: verbatim copies of the kernel's C, compiled in
  user space with the kernel's semantic flags and compared with the model. 10^8 cases for
  each of 103 functions, 1.03 x 10^10 in total, no divergence.
- `lean/`: the model extracted to Lean 4 by Charon and Aeneas (212 of 213 functions with
  the pinned release, all 213 with the current one), and a first proof in
  `lean/Proofs/TnumAdd.lean`: `tnum_add` contains the sum of any two members of its
  inputs. `#print axioms tnum_add_sound` shows only `propext`, `Classical.choice`,
  `Quot.sound`.
- Reports: `EXPLAIN.md` (how value tracking works today), `SCOPE.md`, `INVENTORY.md`,
  `HISTORY.md`, `FEASIBILITY.md`, `DIFFTEST.md`, `ENV.md`.

## What this is not

Agreement between the C and the Rust model is tested, not proved. Apart from
`tnum_add`, nothing here is proved yet; the proofs are the work the proposal asks to
fund.

## Reproducing

Tool versions are in `ENV.md`. The commands behind every number are in
`FEASIBILITY.md` and `DIFFTEST.md`.

AI assistance (Claude Code) was used for the port, the harness and the reports. The
rules it worked under are in `CLAUDE.md`; every result was checked by running it.

## License

GPL-2.0, the license of the kernel code the model follows. See `LICENSE`.

## Contact

Natasha Klaus <natalie.klaus@runtimeverification.com>, Runtime Verification
