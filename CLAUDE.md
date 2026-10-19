# linux-ebpf-spike

Feasibility and scoping spike for a proposal to Alpha-Omega: machine-checked proofs
of the Linux eBPF verifier's value tracking (tnum, cnum, bounds sync, ALU transfer
functions, pruning checks), with the proofs kept current as bpf-next changes.

Method: C -> safe Rust model -> differential testing against the kernel's own C ->
Charon/Aeneas -> Lean 4 -> proofs.

## Layout

- `~/linux-ebpf`: kernel clone, branch `ebpf-spike` from `bpf-next/master`. READ ONLY.
  Never edit files, build, or switch branches in this tree.
- `~/build-ebpf`: kernel build directory (`make O=~/build-ebpf`). Never build in the
  source tree.
- `~/linux-ebpf-spike`: this repository. All outputs go here.
  - `extracted/`: verbatim copies of kernel C; each file starts with a comment giving
    the source path, line range and commit hash
  - `rust/`: the Rust model (cargo workspace)
  - `lean/`: Charon/Aeneas output and proofs (lake project)
  - `harness/`: differential-testing harness

## Environment pins

- Rust stable 1.94.0.
- Charon 909ff09a with Aeneas c2015b86; Aeneas binary `~/aeneas-project/aeneas/bin/aeneas`.
  Do not use `~/aeneas` (3a8586f-dirty, rejects the pinned Charon's LLBC).
- A HEAD pair of Charon/Aeneas is in `~/aeneas_merge_abstractions`. Use it only when the
  pinned pair fails on a construct, and record which pair produced each result.
- Known issue in c2015b86: `Unreachable` in abstraction merging when a bool guard is read
  through a shared reference and the joined value is used in a later condition
  (Aeneas issue #1347, fixed upstream). Workaround: pass by value.
- Lean 4 / mathlib v4.31.0, selected by the `lean-toolchain` file of the lake project.
  Never run bare `lean --version` outside the project: elan resolves to v4.33.1 and
  starts a download.
- LibAFL 0.15 if coverage-guided fuzzing is used.
- Record the versions actually used in `ENV.md`.

## Rules

1. Do not commit, push, tag or create branches in any repository. Natasha reviews and
   commits.
2. Do not set `user.name` or `user.email` in any repository's git config.
3. Calibration: a claim derived by reasoning over several files is checked empirically
   (compile, run, `git log`, grep) or marked UNVERIFIED. Every number in a report names
   the command that produced it.
4. Security findings: if the kernel's C (not the Rust model) produces bounds that exclude
   a value the register can actually hold, or pruning accepts a state that the explored
   state does not cover, write it to `FINDINGS.md` with a minimal input, stop, and
   report. No issue, email, mailing-list post or public commit. Disclosure is Natasha's
   decision.
5. Wording: "proved" only for a Lean theorem with no `sorry` whose `#print axioms` shows
   at most `propext`, `Classical.choice`, `Quot.sound`. C-to-Rust agreement is "tested",
   with exact case counts. Tested code is never called "verified".
6. Rust model: safe Rust only, no external crates in the model crate, one Rust function
   per C function with the same name, field names and integer widths. Wrapping
   arithmetic is explicit wherever the C relies on wraparound; the kernel builds with
   `-fno-strict-overflow`.
7. English only in all files, code comments and commit-message drafts.
8. If a step blocks for more than about an hour, record the blocker and move on.
