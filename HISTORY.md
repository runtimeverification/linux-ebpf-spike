# HISTORY.md: git archaeology of the scope (Phase 0)

Tree: `~/linux-ebpf`, branch `ebpf-spike`, HEAD `4f842631f178` (`git describe HEAD` =
`v7.3-rc5-1314-g4f842631f178`). Tags `v5.0` and `v7.3-rc5` exist (`git tag -l v5.0 v7.3-rc5`).
Generated on 2026-10-19. All commands were run from `~/linux-ebpf` (read only).
Scope as defined in `SCOPE.md`. Scratch files referenced below live in
`/tmp/claude-1000/-home-natalie-linux-ebpf-spike/b1cb0d4e-67e2-4406-91be-f6bd9b01c206/scratchpad/`.

Date convention: "since DATE" filters on the **author date** (`%ad`, `--date=short`) of each
commit, `date >= DATE`. Filtering on committer date (`%cd`) gives the same counts for both
cut-offs (checked: `awk -F'\t' '$4>="2025-10-19"' scope.meta.tsv | wc -l` = 48;
`'$4>="2024-10-19"'` = 62).

## 0. Method and caveats

### Scope files and functions

Whole files (5): `kernel/bpf/tnum.c`, `include/linux/tnum.h`, `kernel/bpf/cnum.c`,
`kernel/bpf/cnum_defs.h`, `include/linux/cnum.h`. The cnum files first appear in
`256f0071f9b6` (2026-04-24); `kernel/bpf/states.c` first appears in `c82834a5a11f` (2026-04-12)
(`git log --diff-filter=A --format='%h %ad %s' --date=short -- <file>`).

Named functions in the large files, taken from SCOPE.md Layer B and Stretch (all of them, including
the "context only" and "NOT in the proposed list" ones, so the set is a superset of the proposal):

- `kernel/bpf/verifier.c` (68 names): reg_bounds_sync range_bounds_violation __update_reg_bounds __update_reg32_bounds __update_reg64_bounds cnum32_from_tnum cnum64_from_tnum __reg_deduce_bounds deduce_bounds_32_from_64 deduce_bounds_64_from_32 __reg_bound_offset __update_bounds_from_step ___mark_reg_known reg_step_reset const_tnum_range_mismatch const_tnum_range_mismatch_32 reg_bounds_sanity_check __mark_reg_known __mark_reg32_known __mark_reg32_unbounded __mark_reg64_unbounded __mark_reg_unbounded reset_reg64_and_tnum reset_reg32_and_tnum scalar_min_max_add scalar_min_max_sub scalar_min_max_and scalar_min_max_or scalar_min_max_xor scalar_min_max_lsh scalar_min_max_rsh scalar_min_max_arsh scalar32_min_max_add scalar32_min_max_sub scalar32_min_max_and scalar32_min_max_or scalar32_min_max_xor scalar32_min_max_lsh scalar32_min_max_rsh scalar32_min_max_arsh __scalar32_min_max_lsh __scalar64_min_max_lsh scalar_min_max_mul scalar_min_max_udiv scalar_min_max_sdiv scalar_min_max_umod scalar_min_max_smod scalar32_min_max_mul scalar32_min_max_udiv scalar32_min_max_sdiv scalar32_min_max_umod scalar32_min_max_smod scalar_step_add scalar_step_scale scalar_step_mul scalar_step_lsh reg_step_check_unsigned adjust_scalar_min_max_vals is_safe_to_compute_dst_reg_range zext_32_to_64 coerce_reg_to_size regs_refine_cond_op is_reg_const reg_const_value bpf_flip_opcode bpf_rev_opcode simulate_both_branches_taken is_scalar_branch_taken
- `include/linux/bpf_verifier.h` (13 names): imod reg_smin reg_smax reg_umin reg_umax reg_s32_min reg_s32_max reg_u32_min reg_u32_max reg_set_srange32 reg_set_urange32 reg_set_srange64 reg_set_urange64
- `kernel/bpf/states.c` (2 names): range_within regsafe

Every name was located in the current tree first
(`/bin/grep -nE "^(static |)?[a-zA-Z_0-9 \*]*\b<name>\(" <file>`; result in scratchpad
`vfunc_locations.txt`). All 85 name/file pairs resolved; none missing.

### How `git log -L` was run

One job per (function, file): `git log --format=%H -L '<spec>:<path>' v5.0..HEAD`, hashes
extracted with `grep -E '^[0-9a-f]{40}$' | sort -u` (script `run_L.sh`, job list `jobs.txt`,
results `L/<job>.hashes`, `L/<job>.rc`, `L/<job>.err`). 85 jobs; all exited 0 with empty stderr
(`for c in L/*.cmd; do ...; done`, printed none).

`git log -L :<name>:<file>` resolves `<name>` to the **first** "funcname line" (diff driver
`cpp` per `git check-attr diff`: a line starting with a letter or underscore) that contains the
name as a substring. This resolution was checked for every job with
`git blame -L :<name> <rev> -- <file> | head -1` (same resolver; scratchpad `blame_resolution.txt`).
Names that resolve to the wrong line and how they were handled:

| name | problem | handling |
|---|---|---|
| `range_bounds_violation` | forward declaration at verifier.c:2352 precedes the definition at 2398 | `-L 2398,2401:kernel/bpf/verifier.c` (explicit range; end = next `^}`) |
| `__mark_reg_known` | substring of `__mark_reg_known_zero` (prototype at verifier.c:1024) and of `___mark_reg_known` (2063) | `-L 2074,2083:kernel/bpf/verifier.c` |
| `scalar_min_max_add` | forward declaration at verifier.c:225 | `-L 16458,16462:kernel/bpf/verifier.c` |
| `scalar32_min_max_add` | forward declaration at verifier.c:224 | `-L 16452,16456:kernel/bpf/verifier.c` |
| `scalar32_min_max_lsh` | substring of `__scalar32_min_max_lsh` (16872) | `-L 16886,16902:kernel/bpf/verifier.c` |
| `regs_refine_cond_op` | multi-line forward declaration at verifier.c:17913 | `-L 18252,18388:kernel/bpf/verifier.c` |
| `range_within` in pre-move verifier.c | at `c82834a5a11f^` the first match is `retval_range_within` (line 11143); the real definition is at line 19000 | `-L 19000,19011:kernel/bpf/verifier.c v5.0..c82834a5a11f^` |
| `bpf_flip_opcode`, `bpf_rev_opcode` in `include/linux/bpf_verifier.h` | only prototypes there (lines 2007, 2008); the definitions are in verifier.c | not run on the header; run on verifier.c only |
| `cnum_defs.h` template functions (each name exists twice) | not applicable: cnum_defs.h is a whole-file scope item, no `-L` needed | whole-file `git log` |

Functions moved from verifier.c to states.c in `c82834a5a11f` (2026-04-12): `range_within` and
`regsafe`. `-L` follows a function only inside one path, so each was run twice and the results
merged: `-L :<name>:kernel/bpf/states.c v5.0..HEAD` and
`-L <spec>:kernel/bpf/verifier.c v5.0..c82834a5a11f^` (jobs `states.c__*` and
`verifier.c-premove__*`).

**Caveat (line-range bleed).** `git log -L` follows a *line range*, not a symbol. When a function
was inserted, git keeps following the lines that occupied that position in the parent, so the
per-function sets include commits that touched the predecessor or neighbouring code at that
location. This is what makes renames traceable (e.g. `deduce_bounds_32_from_64` traces back to
`__reg32_deduce_bounds`, see section 4) but it also over-includes. Example checked:
`reg_bounds_sanity_check` first appears in `5f99f312bd3b` (2023-11-11,
`git log -Sreg_bounds_sanity_check -- kernel/bpf/verifier.c | tail -1`), yet its `-L` set has
18 commits, 11 of them older than 2023-11-11 (they touched the `__reg_combine_64_into_32` /
bounds-propagation code that stood at that position). The counts below are therefore an upper bound
on "commits that changed an in-scope function"; no commit was removed by hand. Two merge commits
(`bfec8e88ff60`, `891a05ccba92`) entered via the `regsafe` pre-move run; both are flagged where
they appear and non-merge counts are given alongside.

## 1. Commits touching the scope

Union = `git log --format=%H v5.0..HEAD -- kernel/bpf/tnum.c include/linux/tnum.h kernel/bpf/cnum.c kernel/bpf/cnum_defs.h include/linux/cnum.h`
(`wholefile.hashes`, 23 commits) plus all `L/*.hashes` (`perfunc.hashes`, 152 commits), `sort -u`
(`scope.hashes`). Overlap of the two sets: 8 (`comm -12 perfunc.hashes wholefile.hashes | wc -l`).
Metadata: `git log --no-walk=unsorted --format='%H%x09%h%x09%ad%x09%cd%x09%an%x09%ae%x09%s' --date=short $(cat scope.hashes)`
(`scope.meta.tsv`). Per commit: `git log -1 --format=%B <hash> | grep -ciE '^Fixes:'` and
`... | grep -ciE '^Cc:.*stable@(vger\.)?kernel\.org'` (`scope.trailers.tsv`, joined into `scope.joined.tsv`).

| set | commits | non-merge | with `Fixes:` trailer | with `Cc: stable` trailer |
|---|---|---|---|---|
| scope union, v5.0..HEAD | 167 | 165 | 31 | 0 |
| scope union, author date >= 2025-10-19 | 48 | 46 | 11 | 0 |
| whole-file set only (tnum/cnum files), v5.0..HEAD | 23 | 23 | 3 | 0 |
| whole-file set only, author date >= 2025-10-19 | 12 | 12 | 2 | 0 |
| per-function set only, v5.0..HEAD | 152 | 150 | 30 | 0 |

Commands for the table rows: `wc -l < scope.meta.tsv`; `awk -F'\t' '$3>="2025-10-19"' scope.joined.tsv | wc -l`;
`awk -F'\t' '$8>0' scope.joined.tsv | wc -l` (Fixes); `awk -F'\t' '$9>0' ...` (stable);
non-merge: `git rev-list --parents -n1 <hash> | awk 'NF==2'` per hash.
The `Cc: stable` count is zero for every row; a looser check, any body line containing "stable"
(`git log -1 --format='%h %B' <hash> | grep -i stable`), matches only `f2d67fec0b43` (prose:
"for stable trees: ...", "Hence revert is best option for stable."), not a trailer.

The full list of 167 commits is in Appendix A; per-job hash counts in Appendix B.

## 2. Replay set (scope commits with author date >= 2025-10-19)

48 commits (46 non-merge), chronological by author date (`sort -t$'\t' -k3,3 -k4,4 scope.meta.tsv`,
then `awk -F'\t' '$3>="2025-10-19"'`; `replay.meta.tsv`). Classification by scope files touched:
`git show --format= --name-only <hash> | grep -E '^(kernel/bpf/(tnum|cnum|verifier|states)\.c|kernel/bpf/cnum_defs\.h|include/linux/(tnum|cnum|bpf_verifier)\.h)$'`
(`replay.class.tsv`). Class "tnum/cnum-only" = touches at least one of tnum.c/tnum.h/cnum.c/cnum_defs.h/cnum.h
and neither verifier.c nor states.c (bpf_verifier.h ignored for the class, listed in the files column);
"verifier.c/states.c-only" = the converse; "both" = touches both groups.

| hash | author date | subject | class | scope files touched |
|---|---|---|---|---|
| `d43ad9da8052` | 2025-11-03 | bpf: Skip bounds adjustment for conditional jumps on same scalar register | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `493d9e0d6083` | 2025-11-05 | bpf, x86: add support for indirect jumps | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/verifier.c  |
| `d18dec4b8990` | 2025-12-02 | bpf: verifier improvement in 32bit shift sign extension pattern | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `840692326e92` | 2025-12-30 | bpf: allow states pruning for misc/invalid slots in iterator loops | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `bffacdb80b93` | 2026-01-12 | bpf: Recognize special arithmetic shift in the verifier | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `44fdd581d273` | 2026-01-19 | bpf: Add range tracking for BPF_DIV and BPF_MOD | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `b0388bafa494` | 2026-02-03 | bpf: Relax scalar id equivalence for state pruning | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `9d2119984224` | 2026-02-04 | bpf: Add bitwise tracking for BPF_END | both | include/linux/tnum.h kernel/bpf/tnum.c kernel/bpf/verifier.c  |
| `022ac0750883` | 2026-02-12 | bpf: use reg->var_off instead of reg->off for pointers | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/verifier.c  |
| `3d91c618aca4` | 2026-02-12 | bpf: rename bpf_reg_state->off to bpf_reg_state->delta | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/verifier.c  |
| `76e954155b45` | 2026-02-27 | bpf: Introduce tnum_step to step through tnum's members | tnum/cnum-only | include/linux/tnum.h kernel/bpf/tnum.c  |
| `efc11a667878` | 2026-02-27 | bpf: Improve bounds when tnum has a single possible value | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `fbc7aef517d8` | 2026-03-06 | bpf: Fix u32/s32 bounds when ranges cross min/max boundary | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `879cace97667` | 2026-03-13 | bpf: better naming for __reg_deduce_bounds() parts | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `9e5fcb003aec` | 2026-03-13 | bpf: Avoid one round of bounds deduction | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `bc308be380c1` | 2026-03-19 | bpf: Fix sync_linked_regs regarding BPF_ADD_CONST32 zext propagation | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `833ef4a954e1` | 2026-03-20 | bpf: Simplify tnum_step() | tnum/cnum-only | kernel/bpf/tnum.c  |
| `bfec8e88ff60` | 2026-03-22 | Merge git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf 7.0-rc5 (merge) | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `a8502a79e832` | 2026-03-31 | bpf: Fix regsafe() for pointers to packet | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `a1311b94ef85` | 2026-04-02 | bpf: Refactor reg_bounds_sanity_check | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `a2a14e874b4e` | 2026-04-02 | bpf: Exit early if reg_bounds_sync gets invalid inputs | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `b254c6d816e5` | 2026-04-02 | bpf: Simulate branches to prune based on range violations | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `891a05ccba92` | 2026-04-03 | Merge git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf 7.0-rc6+ (merge) | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `c82834a5a11f` | 2026-04-12 | bpf: Move state equivalence logic to states.c | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c  |
| `256f0071f9b6` | 2026-04-24 | bpf: representation and basic operations on circular numbers | tnum/cnum-only | include/linux/cnum.h kernel/bpf/cnum.c kernel/bpf/cnum_defs.h  |
| `b93f7180f0bc` | 2026-04-24 | bpf: use accessor functions for bpf_reg_state min/max fields | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c  |
| `bbc631085503` | 2026-04-24 | bpf: replace min/max fields with struct cnum{32,64} | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/verifier.c  |
| `cd5b460ed1ec` | 2026-04-25 | bpf: range_within() must check cnum ranges instead of min/max pairs | both | include/linux/cnum.h kernel/bpf/cnum_defs.h kernel/bpf/states.c  |
| `79b8ebcbe483` | 2026-04-27 | bpf: Export cnum_umin/umax() helpers for netronome driver | tnum/cnum-only | kernel/bpf/cnum_defs.h  |
| `308c7a0ae885` | 2026-05-28 | bpf: Refactor object relationship tracking and fix dynptr UAF bug | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c  |
| `a15970d916b3` | 2026-07-29 | bpf: Simplify sanitize_err() signature | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `4e3fb5bba680` | 2026-07-30 | bpf: Simplify cnum contains() by removing redundant branches | tnum/cnum-only | kernel/bpf/cnum_defs.h  |
| `705249119d94` | 2026-07-30 | bpf: Avoid redundant min()/max() in cnum signed bounds | tnum/cnum-only | kernel/bpf/cnum_defs.h  |
| `b601a4ecbe67` | 2026-07-30 | bpf: Simplify cnum normalize() by dropping unnecessary comparisons | tnum/cnum-only | kernel/bpf/cnum_defs.h  |
| `c0e091f30f0d` | 2026-08-01 | bpf: Rename ARG_CONST_SIZE{,_OR_ZERO} to ARG_MEM_SIZE{,_OR_ZERO} | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/verifier.c  |
| `71919742c83c` | 2026-09-18 | bpf: Assign lock identity to callback map values | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c  |
| `fd16449a9b3b` | 2026-09-18 | bpf: Preserve packet pointer class displacement in regsafe() | verifier.c/states.c-only | kernel/bpf/states.c  |
| `8901cee9316d` | 2026-09-19 | bpf: Compare stack frames in regs_exact() | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/states.c  |
| `ecc441fc774e` | 2026-09-24 | bpf: Size the per-frame verifier structures for a 2 KiB stack | neither(bpf_verifier.h only) | include/linux/bpf_verifier.h  |
| `0892ef2a7ef3` | 2026-10-09 | bpf: Representation for intervals with steps | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c  |
| `366b4c68d830` | 2026-10-09 | bpf: Allow subrange relations for PTR_TO_STACK in regsafe() | verifier.c/states.c-only | kernel/bpf/states.c  |
| `4072d7f56b44` | 2026-10-09 | bpf: Add tnum_alignment() | tnum/cnum-only | include/linux/tnum.h kernel/bpf/tnum.c  |
| `685ac494443e` | 2026-10-09 | bpf: Expose bpf_rev_opcode() and bpf_flip_opcode() | verifier.c/states.c-only | include/linux/bpf_verifier.h kernel/bpf/verifier.c  |
| `78e61c01a760` | 2026-10-09 | bpf: Add cnum64_intersect_linear() | tnum/cnum-only | include/linux/bpf_verifier.h include/linux/cnum.h kernel/bpf/cnum.c  |
| `89e72f81a455` | 2026-10-09 | bpf: Varying offset access support for PTR_TO_BTF_ID pointers | verifier.c/states.c-only | kernel/bpf/states.c kernel/bpf/verifier.c  |
| `a8e9a53f6df6` | 2026-10-09 | bpf: Add cnum{32,64}_union() | tnum/cnum-only | include/linux/cnum.h kernel/bpf/cnum_defs.h  |
| `4d274f1ef049` | 2026-10-13 | bpf: Reg_bounds_sync() comment fixup | verifier.c/states.c-only | kernel/bpf/verifier.c  |
| `ee4f44e0e3c8` | 2026-10-17 | bpf: Look at all 64 bits of a BPF_JSET mask on 32-bit | verifier.c/states.c-only | kernel/bpf/verifier.c  |

Class counts (`cut -f4 replay.class.tsv | sort | uniq -c`):

| class | commits |
|---|---|
| verifier.c/states.c-only | 35 |
| tnum/cnum-only | 10 |
| both | 2 |
| neither(bpf_verifier.h only) | 1 |

Commits per month, author date (`cut -f2 replay.class.tsv | cut -c1-7 | sort | uniq -c`):

| month | commits |
|---|---|
| 2025-11 | 2 |
| 2025-12 | 2 |
| 2026-01 | 2 |
| 2026-02 | 6 |
| 2026-03 | 7 |
| 2026-04 | 10 |
| 2026-05 | 1 |
| 2026-07 | 4 |
| 2026-08 | 1 |
| 2026-09 | 4 |
| 2026-10 | 9 |

## 3. The cnum series and the stride series

### 3a. `git log --grep=cnum --since=2026-01-01 --format='%h %ad %s' --date=short -- kernel/bpf include/linux` (12 commits; `-i` gives the same 12)

    0892ef2a7ef3 2026-10-09 bpf: Representation for intervals with steps
    78e61c01a760 2026-10-09 bpf: Add cnum64_intersect_linear()
    a8e9a53f6df6 2026-10-09 bpf: Add cnum{32,64}_union()
    705249119d94 2026-07-30 bpf: Avoid redundant min()/max() in cnum signed bounds
    b601a4ecbe67 2026-07-30 bpf: Simplify cnum normalize() by dropping unnecessary comparisons
    4e3fb5bba680 2026-07-30 bpf: Simplify cnum contains() by removing redundant branches
    9c87e61e3c57 2026-06-17 Merge tag 'bpf-next-7.2' of git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next
    79b8ebcbe483 2026-04-27 bpf: Export cnum_umin/umax() helpers for netronome driver
    cd5b460ed1ec 2026-04-25 bpf: range_within() must check cnum ranges instead of min/max pairs
    bbc631085503 2026-04-24 bpf: replace min/max fields with struct cnum{32,64}
    b93f7180f0bc 2026-04-24 bpf: use accessor functions for bpf_reg_state min/max fields
    256f0071f9b6 2026-04-24 bpf: representation and basic operations on circular numbers

### 3b. `git log --grep='circular number' --since=2026-01-01 --format='%h %ad %s' --date=short -- kernel/bpf include/linux` (3 commits, all also in 3a)

    9c87e61e3c57 2026-06-17 Merge tag 'bpf-next-7.2' of git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next
    bbc631085503 2026-04-24 bpf: replace min/max fields with struct cnum{32,64}
    256f0071f9b6 2026-04-24 bpf: representation and basic operations on circular numbers

Union of 3a and 3b: 12 commits. Membership in the scope union and scope files touched
(`grep -c <H> scope.hashes`; `git show --format= --name-only`):

| hash | date | in scope union | scope files | subject |
|---|---|---|---|---|
| `0892ef2a7ef3` | 2026-10-09 | 1 | include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c  | bpf: Representation for intervals with steps |
| `78e61c01a760` | 2026-10-09 | 1 | include/linux/bpf_verifier.h include/linux/cnum.h kernel/bpf/cnum.c  | bpf: Add cnum64_intersect_linear() |
| `a8e9a53f6df6` | 2026-10-09 | 1 | include/linux/cnum.h kernel/bpf/cnum_defs.h  | bpf: Add cnum{32,64}_union() |
| `b601a4ecbe67` | 2026-07-30 | 1 | kernel/bpf/cnum_defs.h  | bpf: Simplify cnum normalize() by dropping unnecessary comparisons |
| `4e3fb5bba680` | 2026-07-30 | 1 | kernel/bpf/cnum_defs.h  | bpf: Simplify cnum contains() by removing redundant branches |
| `705249119d94` | 2026-07-30 | 1 | kernel/bpf/cnum_defs.h  | bpf: Avoid redundant min()/max() in cnum signed bounds |
| `9c87e61e3c57` | 2026-06-17 | 0 |  | Merge tag 'bpf-next-7.2' of git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next |
| `79b8ebcbe483` | 2026-04-27 | 1 | kernel/bpf/cnum_defs.h  | bpf: Export cnum_umin/umax() helpers for netronome driver |
| `cd5b460ed1ec` | 2026-04-25 | 1 | include/linux/cnum.h kernel/bpf/cnum_defs.h kernel/bpf/states.c  | bpf: range_within() must check cnum ranges instead of min/max pairs |
| `b93f7180f0bc` | 2026-04-24 | 1 | include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c  | bpf: use accessor functions for bpf_reg_state min/max fields |
| `256f0071f9b6` | 2026-04-24 | 1 | include/linux/cnum.h kernel/bpf/cnum.c kernel/bpf/cnum_defs.h  | bpf: representation and basic operations on circular numbers |
| `bbc631085503` | 2026-04-24 | 1 | include/linux/bpf_verifier.h kernel/bpf/verifier.c  | bpf: replace min/max fields with struct cnum{32,64} |

The cnum patch series itself, enumerated by the Link message-id prefix of `bbc631085503`
(`git log -1 --format=%B bbc631085503 | grep '^Link:'` gives
`20260424-cnums-everywhere-rfc-v1-v3-3-ca434b39a486@gmail.com`;
`git log --since=2026-04-01 --grep='20260424-cnums-everywhere-rfc-v1-v3-'`):

     0 6c60b2dd5a78 in-union=0 files=[] Merge branch 'bpf-replace-min-max-fields-with-struct-cnum-32-64'
     1 256f0071f9b6 in-union=1 files=[include/linux/cnum.h kernel/bpf/cnum.c kernel/bpf/cnum_defs.h ] bpf: representation and basic operations on circular numbers
     2 b93f7180f0bc in-union=1 files=[include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c ] bpf: use accessor functions for bpf_reg_state min/max fields
     3 bbc631085503 in-union=1 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: replace min/max fields with struct cnum{32,64}
     4 4c0710ab011e in-union=0 files=[] selftests/bpf: new cases handled by 32->64 range refinements

### 3c. `git log --grep='Fixes: bbc631085503' --format='%h %ad %s' --date=short` (no path restriction; 2 commits)

    79b8ebcbe483 2026-04-27 bpf: Export cnum_umin/umax() helpers for netronome driver   [in scope union: 1; scope files: kernel/bpf/cnum_defs.h ]
    cd5b460ed1ec 2026-04-25 bpf: range_within() must check cnum ranges instead of min/max pairs   [in scope union: 1; scope files: include/linux/cnum.h kernel/bpf/cnum_defs.h kernel/bpf/states.c ]

### 3d. Stride series around `0892ef2a7ef3` (2026-10-09, Eduard Zingerman, "bpf: Representation for intervals with steps")

Subject filter: `git log --since=2026-09-01 --format='%h %ad %s' --date=short -- <8 scope files> | grep -iE 'step|stride|intersect_linear'`
(2 commits):

    0892ef2a7ef3 2026-10-09 bpf: Representation for intervals with steps
    78e61c01a760 2026-10-09 bpf: Add cnum64_intersect_linear()

`0892ef2a7ef3` carries no `Fixes:` trailer; its Link is
`20261009-scev-minimal-rebase-v3-19-bcba9bc53ac9@gmail.com`, i.e. patch 19 of the series
"bpf-use-scalar-evolution-to-widen-bounded-loops". Full series by Link prefix
(`git log --since=2026-10-01 --grep='20261009-scev-minimal-rebase-v3-'`): 52 commits
(including the merge and selftests), 7 in the scope union. Members that touch a scope file,
with in-union flag (format: `<patch#> <hash> in-union=<0|1> files=[...] <subject>`):

     1 5b6beb95f7b4 in-union=0 files=[include/linux/bpf_verifier.h ] bpf: Represent stack access effects with arg_access_info
     2 830e4372de5c in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Describe helper stack accesses with arg_access_info
     3 8f3bd4537faa in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Describe kfunc stack accesses with arg_access_info
     5 0360ed8655cf in-union=0 files=[include/linux/bpf_verifier.h ] bpf: Summarize may write stack slots in insn_aux_data
     6 30175f5d9b1a in-union=0 files=[include/linux/bpf_verifier.h ] bpf: Summarize live stack slots in insn_aux_data
     7 c6477be15804 in-union=0 files=[include/linux/bpf_verifier.h ] bpf: Summarize regs that may hold a frame pointer in insn_aux_data
    10 8212c1c2986d in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Derive global subprog stack liveness from BTF signatures
    11 147400e9c27c in-union=0 files=[kernel/bpf/verifier.c ] bpf: Compute parameters liveness in bpf_compute_live_registers()
    12 4072d7f56b44 in-union=1 files=[include/linux/tnum.h kernel/bpf/tnum.c ] bpf: Add tnum_alignment()
    13 a8e9a53f6df6 in-union=1 files=[include/linux/cnum.h kernel/bpf/cnum_defs.h ] bpf: Add cnum{32,64}_union()
    14 78e61c01a760 in-union=1 files=[include/linux/bpf_verifier.h include/linux/cnum.h kernel/bpf/cnum.c ] bpf: Add cnum64_intersect_linear()
    15 685ac494443e in-union=1 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Expose bpf_rev_opcode() and bpf_flip_opcode()
    16 041d7c85c45d in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Expose bpf_grow_stack_state()
    17 f21dcf26986c in-union=0 files=[include/linux/bpf_verifier.h ] bpf: Expose bpf_verbose_snum()
    18 366b4c68d830 in-union=1 files=[kernel/bpf/states.c ] bpf: Allow subrange relations for PTR_TO_STACK in regsafe()
    19 0892ef2a7ef3 in-union=1 files=[include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c ] bpf: Representation for intervals with steps
    20 89e72f81a455 in-union=1 files=[kernel/bpf/states.c kernel/bpf/verifier.c ] bpf: Varying offset access support for PTR_TO_BTF_ID pointers
    21 f414d20879ae in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Save DFS postorder numbers for program instructions
    22 ceea9085f2d1 in-union=0 files=[kernel/bpf/verifier.c ] bpf: Move the live-register and SCC printout to a standalone function
    23 6254fb693289 in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Compute immediate dominators
    24 9ae7f5e8bf1d in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Compute loop hierarchy
    25 f849c3a145eb in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Add bpf_set_reg_range()
    26 bc2afa09c07e in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Add bpf_mark_reg_known_scalar()
    27 6360b15f86ed in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Add bpf_reg_union() and bpf_reg_union_compatible()
    28 97d592e69d09 in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/states.c ] bpf: Add bpf_split_cur_state()
    29 4c3a56544b65 in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Add bpf_same_memory_origin()
    30 1291ad590693 in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Add bpf_spill_size()
    31 2fa579694ddf in-union=0 files=[include/linux/bpf_verifier.h ] bpf: Record basic-block ends in insn_aux_data
    32 60b0109ad195 in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/states.c ] bpf: Allow precision backtracking between overlapping checkpoints
    33 1501b536818b in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Compute scalar evolution expressions for loops
    34 6ccf49f79327 in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/states.c kernel/bpf/verifier.c ] bpf: Use SCEV to widen bounded loops
    35 088a5477a9bd in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/verifier.c ] bpf: Avoid widening registers that hinder exact stack-slot tracking
    36 a2052333e6f9 in-union=0 files=[include/linux/bpf_verifier.h kernel/bpf/states.c ] bpf: Bpf_func_state size optimization

In-scope functions touched by the in-union members (`grep -l <H> L/*.hashes`):

    89e72f81a455 bpf: Varying offset access support for PTR_TO_BTF_ID pointers: states.c__regsafe 
    0892ef2a7ef3 bpf: Representation for intervals with steps: states.c__range_within verifier.c__adjust_scalar_min_max_vals verifier.c__coerce_reg_to_size verifier.c_____mark_reg_known verifier.c____reg_bound_offset verifier.c__reg_bounds_sanity_check verifier.c__reg_bounds_sync verifier.c__regs_refine_cond_op verifier.c__reg_step_check_unsigned verifier.c__reg_step_reset verifier.c__scalar_step_add verifier.c__scalar_step_lsh verifier.c__scalar_step_mul verifier.c__scalar_step_scale verifier.c____update_bounds_from_step verifier.c__zext_32_to_64 
    366b4c68d830 bpf: Allow subrange relations for PTR_TO_STACK in regsafe(): states.c__regsafe 
    685ac494443e bpf: Expose bpf_rev_opcode() and bpf_flip_opcode(): verifier.c__bpf_flip_opcode verifier.c__bpf_rev_opcode verifier.c__regs_refine_cond_op verifier.c__simulate_both_branches_taken 
    78e61c01a760 bpf: Add cnum64_intersect_linear(): bpf_verifier.h__imod [whole-file tnum/cnum set]
    a8e9a53f6df6 bpf: Add cnum{32,64}_union(): [whole-file tnum/cnum set]
    4072d7f56b44 bpf: Add tnum_alignment(): [whole-file tnum/cnum set]

## 4. CVE map

Verification per hash: `git cat-file -e <hash>^{commit}`, `git log -1 --format='%H %ad %an %s' --date=short <hash>`,
`git merge-base --is-ancestor <hash> HEAD`, `git merge-base --is-ancestor <hash> v5.0`,
`git show --format= --name-only <hash>`, hunk functions from `git show <hash> | grep '^@@'`
(scratchpad `cve_commits.txt`). Membership: `grep -c <H> scope.hashes` and `grep -l <H> L/*.hashes`.
Message search: `git log --grep=<CVE id> --format='%h %ad %s' --date=short` (whole history, no path
restriction; scratchpad `cve_grep.txt`).

| CVE | commit | date | subject | in tree (ancestor of HEAD) | ancestor of v5.0 | functions in hunk headers | in scope union | in-scope today? |
|---|---|---|---|---|---|---|---|---|
| CVE-2017-16995 | `95a762e2c8c9` | 2017-12-18 | bpf: fix incorrect sign extension in check_alu_op() | YES | YES (predates v5.0, so outside the v5.0..HEAD window) | `check_alu_op` | no | no: `check_alu_op` is not in SCOPE.md |
| CVE-2020-8835 (fix) | `f2d67fec0b43` | 2020-03-30 | bpf: Undo incorrect __reg_bound_offset32 handling | YES | NO | `__reg_bound_offset`, `reg_set_min_max`, `reg_set_min_max_inv` | yes (job `verifier.c__regs_refine_cond_op`) | `__reg_bound_offset`: yes (Layer B). `__reg_bound_offset32`: added by 581738a681b6, removed by this commit (`git log -S__reg_bound_offset32 -- kernel/bpf/verifier.c` lists exactly these two). `reg_set_min_max`/`_inv`: successor is `regs_refine_cond_op` (Stretch), see trace below |
| CVE-2020-8835 (introducing) | `581738a681b6` | 2019-11-21 | bpf: Provide better register bounds after jmp32 instructions | YES | NO | `__reg_bound_offset`, `reg_set_min_max`, `reg_set_min_max_inv` | yes (job `verifier.c__regs_refine_cond_op`) | as above |
| CVE-2020-27194 | `5b9fbeb75b6a` | 2020-10-07 | bpf: Fix scalar32_min_max_or bounds tracking | YES | NO | `scalar32_min_max_or` | yes (job `verifier.c__scalar32_min_max_or`) | yes (Layer B ALU transfer function) |
| CVE-2021-3490 | `049c4e13714e` | 2021-05-10 | bpf: Fix alu32 const subreg bound tracking on bitwise operations | YES | NO | `scalar32_min_max_and`, `scalar32_min_max_or`, `scalar32_min_max_xor` | yes (jobs `scalar32_min_max_and`, `_or`, `_xor`) | yes (Layer B) |
| CVE-2021-31440 | `10bf4e83167c` | 2021-04-23 | bpf: Fix propagation of 32 bit unsigned bounds from 64 bit bounds | YES | NO | `__reg_combine_64_into_32`, `__reg64_bound_s32` (plus a selftest hunk) | yes (job `verifier.c__reg_bounds_sanity_check`, via line-range bleed; see section 0) | successor in scope, see trace below |

`git log --grep=<CVE id>` results: CVE-2017-16995 is named only by `95a762e2c8c9` itself; the other
four ids do not appear in any commit message in the tree (empty output for each).

Rename traces (`git log -S<name> --format='%h %ad %s' --date=short -- kernel/bpf/verifier.c`):

- `__reg_combine_64_into_32`, `__reg_combine_32_into_64`, `__reg64_bound_s32`: introduced by
  `3f50f132d840` (2020-03-30), removed by `9e314f5d8682` (2023-11-01, "bpf: drop knowledge-losing
  __reg_combine_{32,64}_into_{64,32} logic"), whose message says the calls were replaced by
  `reg_bounds_sync()` (quoted from `git log -1 --format=%B 9e314f5d8682`: "So this patch replaced
  __reg_combine_* with just a normal reg_bounds_sync() which will do a proper job of deriving
  u64/s64 bounds from u32/s32, and vice versa"). The 64-to-32 deduction inside `__reg_deduce_bounds`
  was named `__reg32_deduce_bounds` until `879cace97667` (2026-03-13) renamed it to
  `deduce_bounds_32_from_64` and `__reg_deduce_mixed_bounds` to `deduce_bounds_64_from_32`
  (`git show 879cace97667 -- kernel/bpf/verifier.c | grep -E '^[-+]static .*\('`). So the functional
  successor of `__reg_combine_64_into_32` is `reg_bounds_sync` -> `__reg_deduce_bounds` ->
  `deduce_bounds_32_from_64`, all in Layer B. The one-to-one mapping
  "__reg_combine_64_into_32 == deduce_bounds_32_from_64" is a reading of the commit messages,
  not a git rename: UNVERIFIED as an identity, verified as "replaced by reg_bounds_sync".
- `__reg_bound_offset32`: `581738a681b6` added, `f2d67fec0b43` removed (only two `-S` hits).
  `__reg_bound_offset` exists since `b03c9f9fdc37` (2017-08-07) and is in scope.
- `reg_set_min_max_inv`: `484611357c19` (2016-09-28) added, `4621202adc5b` (2023-11-01) removed.
  `regs_refine_cond_op` first appears in `67420501e868` (2023-11-11, "generalize reg_set_min_max()
  to handle non-const register comparisons"). The `-L` run for `regs_refine_cond_op` contains both
  CVE-2020-8835 commits, i.e. git followed the line range back into `reg_set_min_max`.
- `check_alu_op` (CVE-2017-16995): not traced; out of scope per SCOPE.md.

Other scope commits naming a CVE: `git log v5.0..HEAD --grep='CVE-' -- <8 scope files>` returns
0 commits; grepping `git log -1 --format=%B <hash>` for `CVE-` over all 167 scope-union hashes returns
0 commits. The five CVE fixes above are all pre-v5.0 (95a762e2c8c9) or carry no CVE id in
their message.

## 5. Formal-methods mentions in commit messages

Regex (case-insensitive, word-bounded): `\b(Agni|CBMC|Z3|SMT|model checking|formal verification|formally verified|proof|proofs|proved|Lean|Coq|Isabelle)\b`.
Without word boundaries the same `git log -i -E --grep` returns 130 commits, mostly "clean", "smtp"
and similar substrings; those are not listed.

### 5a. Scope whole files: `git log -i -E --grep="<regex>" v5.0..HEAD --format=%H -- kernel/bpf/tnum.c include/linux/tnum.h kernel/bpf/cnum.c kernel/bpf/cnum_defs.h include/linux/cnum.h kernel/bpf/verifier.c kernel/bpf/states.c include/linux/bpf_verifier.h` (23 commits)

For each hit: hash, date, subject, membership (`grep -c <H> perfunc.hashes` / `wholefile.hashes`),
then the matching body lines (`git log -1 --format=%B <H> | grep -inE "<regex>"`, line number : text).
"keyword only" marks lines where the matched word is ordinary English rather than a reference to a
formal-methods tool or proof.


- **8212c1c2986d 2026-10-09 bpf: Derive global subprog stack liveness from BTF signatures  [per-function set: 0; whole-file tnum/cnum set: 0]** (keyword only: "loop termination proof" is verifier-internal)
    - `10:resets it, invalidating a loop termination proof.`

- **705249119d94 2026-07-30 bpf: Avoid redundant min()/max() in cnum signed bounds  [per-function set: 0; whole-file tnum/cnum set: 1]**
    - `43:Lean4 proofs showing that the new implementation preserves soundness of`
    - `46:        https://github.com/OpenSourceVerif/open-verified-artifacts/tree/cnum-refactor-verif/cnum/lean`

- **b601a4ecbe67 2026-07-30 bpf: Simplify cnum normalize() by dropping unnecessary comparisons  [per-function set: 0; whole-file tnum/cnum set: 1]**
    - `27:Lean4 proofs showing that the new implementation preserves soundness of`
    - `30:        https://github.com/OpenSourceVerif/open-verified-artifacts/tree/cnum-refactor-verif/cnum/lean`

- **4e3fb5bba680 2026-07-30 bpf: Simplify cnum contains() by removing redundant branches  [per-function set: 0; whole-file tnum/cnum set: 1]**
    - `38:Lean4 proofs showing that the new implementation preserves the soundness`
    - `41:        https://github.com/OpenSourceVerif/open-verified-artifacts/tree/cnum-refactor-verif/cnum/lean`

- **2bdc90f53194 2026-08-15 bpf: Report Memory Safety bounds errors  [per-function set: 0; whole-file tnum/cnum set: 0]** (keyword only: diagnostics wording)
    - `7:accesses, and check_mem_region_access() range-proof failures. The bounds report`
    - `8:spells out the required offset + access_size <= object_size proof with concrete`

- **e566701b9b0c 2026-08-01 bpf: Check fixed-size mem args of helpers and kfuncs the same way  [per-function set: 0; whole-file tnum/cnum set: 0]** (keyword only)
    - `18:static stack liveness proved the callee body does not read those slots`

- **cd5b460ed1ec 2026-04-25 bpf: range_within() must check cnum ranges instead of min/max pairs  [per-function set: 1; whole-file tnum/cnum set: 1]**
    - `18:operation. The operation implementation is verified using cbmc model`

- **256f0071f9b6 2026-04-24 bpf: representation and basic operations on circular numbers  [per-function set: 0; whole-file tnum/cnum set: 1]**
    - `6:Operations correctness is verified using cbmc model checker,`

- **b254c6d816e5 2026-04-02 bpf: Simulate branches to prune based on range violations  [per-function set: 1; whole-file tnum/cnum set: 0]**
    - `17:because the branch operators are sound (verified with Agni [1]).`
    - `55:Link: https://github.com/bpfverif/agni [1]`

- **833ef4a954e1 2026-03-20 bpf: Simplify tnum_step()  [per-function set: 0; whole-file tnum/cnum set: 1]**
    - `81:CBMC shows the new code is equiv to original one[1], and`
    - `82:a lean4 proof of correctness is available[2]:`

- **9e5fcb003aec 2026-03-13 bpf: Avoid one round of bounds deduction  [per-function set: 1; whole-file tnum/cnum set: 0]**
    - `33:In a similar manner, using CBMC, Eduard found that it's best to improve`

- **efc11a667878 2026-02-27 bpf: Improve bounds when tnum has a single possible value  [per-function set: 1; whole-file tnum/cnum set: 0]**
    - `69:Agni [3]. For the record, the raw SMT is available at [4]. The property`
    - `76:Link: https://github.com/bpfverif/agni [3]`

- **76e954155b45 2026-02-27 bpf: Introduce tnum_step to step through tnum's members  [per-function set: 0; whole-file tnum/cnum set: 1]**
    - `120:described above. As a proof of correctness, we verified the algorithm`
    - `132:an SMT solver. The verification formula in SMTLIB format is available`
    - `138:C implementation using Agni [2] and verified it against the same`
    - `144:Link: https://github.com/bpfverif/agni [2]`

- **6c7340a7a8d2 2025-09-30 Merge tag 'sched-core-2025-09-26' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip  [per-function set: 0; whole-file tnum/cnum set: 0]** (keyword only: SCHED_SMT Kconfig; merge of the tip tree)
    - `11:   - Unify the SCHED_{SMT,CLUSTER,MC} Kconfig (Peter Zijlstra)`
    - `43:  sched: Unify the SCHED_{SMT,CLUSTER,MC} Kconfig`

- **00bf8d0c6c9b 2025-07-28 bpf: Improve bounds when s64 crosses sign boundary  [per-function set: 1; whole-file tnum/cnum set: 0]**
    - `30:also tested with Agni, the formal verification tool for the range`
    - `33:Link: https://github.com/bpfverif/agni [1]`

- **5345e64760d3 2025-07-24 bpf: Simplify bounds refinement from s32  [per-function set: 1; whole-file tnum/cnum set: 0]**
    - `22:this patch was also tested with the Agni formal verification tool [1].`
    - `72:  Beside going through the reasoning, I also played with CBMC a bit to`
    - `81:Link: https://github.com/bpfverif/agni [1]`

- **7a998a731627 2025-06-23 bpf, verifier: Improve precision for BPF_ADD and BPF_SUB  [per-function set: 1; whole-file tnum/cnum set: 0]**
    - `92:We verified the correctness of the new implementations using Agni [3,4].`
    - `100:[3] https://github.com/bpfverif/agni`

- **9aa0ebde0014 2024-12-17 bpf, verifier: Improve precision of BPF_MUL  [per-function set: 1; whole-file tnum/cnum set: 0]**
    - `97:Finally, we proved the soundness of the new scalar_min_max_mul() and`
    - `101:theory. Additionally, using Agni [2,3], we obtained the encodings for`
    - `109:   BPF_MUL. We proved (using an SMT solver) that this new version of`
    - `114:   scalar32_min_max_mul(). By leveraging the existing proof of tnum_mul`

- **55f325958ccc 2024-07-30 bpf: switch maps to CLASS(fd, ...)  [per-function set: 0; whole-file tnum/cnum set: 0]** (keyword only)
    - `7:	Among other things, the proof of memory safety no longer has to`

- **1f586614f3ff 2024-04-16 bpf: Harden and/or/xor value tracking in verifier  [per-function set: 1; whole-file tnum/cnum set: 0]**
    - `25:Agni [2, 3] consideres it a false positive. This is because, during the`
    - `26:verification of the abstract operator scalar_min_max_and(), Agni restricts`
    - `87:using Agni and SMT verification that our patch always produces signed`
    - `93:  [3] https://github.com/bpfverif/agni`

- **2039f26f3aca 2021-07-13 bpf: Fix leakage due to insufficient speculative store bypass mitigation  [per-function set: 0; whole-file tnum/cnum set: 0]** (keyword only: "threat proved")
    - `199:  explored more mitigations for variant 4 but the threat proved to be more`

- **05924717ac70 2021-05-30 bpf, tnums: Provably sound, faster, and more precise algorithm for tnum_mul  [per-function set: 0; whole-file tnum/cnum set: 1]**
    - `36:Importantly, we present a proof of soundness of the new algorithm in the`

- **37086bfdc737 2021-02-02 bpf: Propagate stack bounds to registers in atomics w/ BPF_FETCH  [per-function set: 0; whole-file tnum/cnum set: 0]** (keyword only)
    - `17:A simple test is added with an infinite loop that can only be proved`

Summary of 5a: of the 23 hits, 9 are in the per-function scope set
(`grep -c 'per-function set: 1' fm_whole.txt`), 8 are in the whole-file tnum/cnum set, and
7 touch verifier.c/states.c/bpf_verifier.h outside the scope functions.
Tools named (`git log -1 --format=%B <H> | grep -qiE "\b<word>\b"` over the 23 hits): Agni (8 commits), CBMC (5 commits), Lean4/lean4 (4 commits), SMT (5 commits, one of them the SCHED_SMT noise), "formal verification" (2 commits), Z3/Coq/Isabelle/"model checking"/"formally verified" (0 commits each; "cbmc model checker" matches CBMC, not the phrase "model checking").

### 5b. `tools/testing/selftests/bpf/prog_tests/reg_bounds.c`: `git log -i -E --grep="<regex>" --format='%h %ad %s' --date=short -- tools/testing/selftests/bpf/prog_tests/reg_bounds.c` (whole history)

0 commits. File contents at HEAD: `grep -niE "<regex>" tools/testing/selftests/bpf/prog_tests/reg_bounds.c` returns nothing.

### 5c. `Documentation/bpf/`: `git log -i -E --grep="<regex>" --format='%h %ad %s' --date=short -- Documentation/bpf/` (whole history)

1 commit:

    --- 628add78b07a 2021-01-22 bpf, docs: Update build procedure for manually compiling LLVM and Clang
        18:I verified the procedure and it is proved to be feasible, so we should

    (keyword only: "proved to be feasible" about a build procedure.)

File contents at HEAD: `grep -rniE "<regex>" Documentation/bpf/` returns nothing. In the eight scope
files, `grep -niE "<regex>"` matches only a local variable `proof` in verifier.c (lines 4741-4820,
diagnostics) and a comment "static stack liveness proved" at verifier.c:8017.

## Appendix A. All 167 scope-union commits since v5.0 (chronological by author date)

Columns: hash, author date, commit date, author, subject, Fixes-trailer count, Cc-stable count,
source set (W = whole-file tnum/cnum set, F = per-function -L set), merge flag.
(`scope.joined.tsv`; set membership via `grep -c <H> wholefile.hashes` / `perfunc.hashes`.)

| hash | author date | commit date | author | subject | Fixes | stable | set | merge |
|---|---|---|---|---|---|---|---|---|
| `092ed0968bb6` | 2019-01-26 | 2019-01-26 | Jiong Wang | bpf: verifier support JMP32 | 0 | 0 | F |  |
| `a72dafafbd5f` | 2019-01-26 | 2019-01-26 | Jiong Wang | bpf: refactor verifier min/max code for condition jump | 0 | 0 | F |  |
| `d83525ca62cf` | 2019-01-31 | 2019-02-01 | Alexei Starovoitov | bpf: introduce bpf_spin_lock | 0 | 0 | F |  |
| `46f8bc92758c` | 2019-02-09 | 2019-02-10 | Martin KaFai Lau | bpf: Add a bpf_sock pointer to __sk_buff and a bpf_sk_fullsock helper | 0 | 0 | F |  |
| `655a51e536c0` | 2019-02-09 | 2019-02-10 | Martin KaFai Lau | bpf: Add struct bpf_tcp_sock and BPF_FUNC_tcp_sock | 0 | 0 | F |  |
| `9df1c28bb752` | 2019-04-26 | 2019-04-26 | Matt Mullins | bpf: add writable context for raw tracepoints | 0 | 0 | F |  |
| `457c89965399` | 2019-05-19 | 2019-05-21 | Thomas Gleixner | treewide: Add SPDX license identifier for missed files | 0 | 0 | W |  |
| `5327ed3d44b7` | 2019-05-24 | 2019-05-24 | Jiong Wang | bpf: verifier: mark verified-insn with sub-register zext flag | 0 | 0 | F |  |
| `fada7fdc83c0` | 2019-06-06 | 2019-06-10 | Jonathan Lemon | bpf: Allow bpf_map_lookup_elem() on an xskmap | 0 | 0 | F |  |
| `b5dc0163d8fd` | 2019-06-15 | 2019-06-19 | Alexei Starovoitov | bpf: precise scalar_value tracking | 0 | 0 | F |  |
| `f7cf25b2026d` | 2019-06-15 | 2019-06-19 | Alexei Starovoitov | bpf: track spill/fill of constants | 0 | 0 | F |  |
| `69ecfdaa5349` | 2019-08-20 | 2019-08-20 | Masahiro Yamada | bpf: add include guard to tnum.h | 0 | 0 | W |  |
| `6754172c208d` | 2019-08-21 | 2019-08-24 | Alexei Starovoitov | bpf: fix precision tracking in presence of bpf2bpf calls | 1 | 0 | F |  |
| `581738a681b6` | 2019-11-21 | 2019-11-24 | Yonghong Song | bpf: Provide better register bounds after jmp32 instructions | 0 | 0 | F |  |
| `f54c7898ed1c` | 2019-12-22 | 2019-12-22 | Daniel Borkmann | bpf: Fix precision tracking for unbounded scalars | 1 | 0 | F |  |
| `0af2ffc93a4b` | 2020-01-15 | 2020-01-15 | Daniel Borkmann | bpf: Fix incorrect verifier simulation of ARSH under ALU32 | 1 | 0 | WF |  |
| `07cd263148a5` | 2020-03-24 | 2020-03-25 | John Fastabend | bpf: Verifer, refactor adjust_scalar_min_max_vals | 0 | 0 | F |  |
| `294f2fc6da27` | 2020-03-24 | 2020-03-25 | John Fastabend | bpf: Verifer, adjust_scalar_min_max_vals to always call update_reg_bounds() | 0 | 0 | F |  |
| `0fc31b10cfb7` | 2020-03-30 | 2020-03-30 | Jann Horn | bpf: Simplify reg_set_min_max_inv handling | 0 | 0 | F |  |
| `3f50f132d840` | 2020-03-30 | 2020-03-30 | John Fastabend | bpf: Verifier, do explicit ALU32 bounds tracking | 0 | 0 | WF |  |
| `604dca5e3af1` | 2020-03-30 | 2020-03-30 | Jann Horn | bpf: Fix tnum constraints for 32-bit comparisons | 1 | 0 | F |  |
| `f2d67fec0b43` | 2020-03-30 | 2020-03-30 | Daniel Borkmann | bpf: Undo incorrect __reg_bound_offset32 handling | 1 | 0 | F |  |
| `b0b3fb675922` | 2020-04-18 | 2020-04-26 | Mao Wenan | bpf: Remove set but not used variable 'dst_known' | 0 | 0 | F |  |
| `3a71dc366d4a` | 2020-05-29 | 2020-05-29 | John Fastabend | bpf: Fix a verifier issue when assigning 32bit reg states to 64bit ones | 1 | 0 | F |  |
| `2921c90d4718` | 2020-08-24 | 2020-08-26 | Yonghong Song | bpf: Fix a verifier failure with xor | 0 | 0 | F |  |
| `4fbb38a3b2cc` | 2020-09-24 | 2020-09-25 | John Fastabend | bpf, verifier: Remove redundant var_off.value ops in scalar known reg cases | 0 | 0 | F |  |
| `5b9fbeb75b6a` | 2020-10-07 | 2020-10-08 | Daniel Borkmann | bpf: Fix scalar32_min_max_or bounds tracking | 1 | 0 | F |  |
| `e688c3db7ca6` | 2020-10-14 | 2020-10-15 | Alexei Starovoitov | bpf: Fix register equivalence tracking. | 1 | 0 | F |  |
| `6d94e741a8ff` | 2020-11-10 | 2020-11-13 | Alexei Starovoitov | bpf: Support for pointers beyond pkt_end. | 0 | 0 | F |  |
| `b02709587ea3` | 2020-12-08 | 2020-12-10 | Alexei Starovoitov | bpf: Fix propagation of 32-bit signed bounds from 64-bit bounds. | 1 | 0 | F |  |
| `18b24d78d537` | 2021-01-21 | 2021-01-23 | Tobias Klauser | bpf: Fix typo in scalar{,32}_min_max_rsh comments | 0 | 0 | F |  |
| `ee114dd64c00` | 2021-02-05 | 2021-02-10 | Daniel Borkmann | bpf: Fix verifier jsgt branch analysis on max bound | 2 | 0 | F |  |
| `fd675184fc7a` | 2021-02-05 | 2021-02-10 | Daniel Borkmann | bpf: Fix verifier jmp32 pruning decision logic | 1 | 0 | F |  |
| `69c087ba6225` | 2021-02-26 | 2021-02-26 | Yonghong Song | bpf: Add bpf_for_each_map_elem() helper | 0 | 0 | F |  |
| `a6aaece00a57` | 2021-03-23 | 2021-04-16 | Daniel Borkmann | bpf: Improve verifier error messages for users | 0 | 0 | F |  |
| `f52881933488` | 2021-03-24 | 2021-04-16 | Daniel Borkmann | bpf: Move sanitize_val_alu out of op switch | 0 | 0 | F |  |
| `10bf4e83167c` | 2021-04-23 | 2021-04-27 | Daniel Borkmann | bpf: Fix propagation of 32 bit unsigned bounds from 64 bit bounds | 1 | 0 | F |  |
| `c9e73e3d2b1e` | 2021-04-29 | 2021-05-10 | Lorenz Bauer | bpf: verifier: Allocate idmap scratch in verifier env | 0 | 0 | F |  |
| `049c4e13714e` | 2021-05-10 | 2021-05-11 | Daniel Borkmann | bpf: Fix alu32 const subreg bound tracking on bitwise operations | 2 | 0 | F |  |
| `05924717ac70` | 2021-05-30 | 2021-06-01 | Harishankar Vishwanathan | bpf, tnums: Provably sound, faster, and more precise algorithm for tnum_mul | 0 | 0 | W |  |
| `e042aa532c84` | 2021-07-16 | 2021-07-16 | Daniel Borkmann | bpf: Fix pointer arithmetic mask tightening under state pruning | 0 | 0 | F |  |
| `388e2c0b9783` | 2021-11-01 | 2021-11-01 | Alexei Starovoitov | bpf: Fix propagation of signed bounds from 64-bit min/max into 32-bit. | 1 | 0 | F |  |
| `b9979db83401` | 2021-11-01 | 2021-11-01 | Alexei Starovoitov | bpf: Fix propagation of bounds from 64-bit min/max into 32-bit and var_off. | 1 | 0 | F |  |
| `e572ff80f05c` | 2021-12-15 | 2021-12-16 | Daniel Borkmann | bpf: Make 32->64 bounds propagation slightly more robust | 0 | 0 | F |  |
| `c25b2ae13603` | 2021-12-16 | 2021-12-18 | Hao Luo | bpf: Replace PTR_TO_XXX_OR_NULL with PTR_TO_XXX \| PTR_MAYBE_NULL | 0 | 0 | F |  |
| `3844d153a41a` | 2022-07-01 | 2022-07-01 | Daniel Borkmann | bpf: Fix insufficient bounds propagation from adjust_scalar_min_max_vals | 1 | 0 | F |  |
| `a12ca6277eca` | 2022-07-01 | 2022-07-01 | Daniel Borkmann | bpf: Fix incorrect verifier simulation around jmp32's jeq/jne | 1 | 0 | F |  |
| `dc84dbbcc97b` | 2022-08-31 | 2022-09-02 | Shung-Hsi Yu | bpf, tnums: Warn against the usage of tnum_in(tnum_range(), ...) | 0 | 0 | W |  |
| `f63181b6ae79` | 2022-11-04 | 2022-11-04 | Andrii Nakryiko | bpf: stop setting precise in current state | 0 | 0 | F |  |
| `ef66c5475d7f` | 2022-11-19 | 2022-11-20 | David Vernet | bpf: Allow multiple modifiers in reg_type_str() prefix | 0 | 0 | F |  |
| `4ea2bb158bec` | 2022-12-09 | 2022-12-10 | Eduard Zingerman | bpf: use check_ids() for active_lock comparison | 0 | 0 | F |  |
| `7c884339bbff` | 2022-12-09 | 2022-12-10 | Eduard Zingerman | bpf: regsafe() must not skip check_ids() | 0 | 0 | F |  |
| `4633a0068258` | 2022-12-22 | 2022-12-27 | Andrii Nakryiko | bpf: fix regs_exact() logic in regsafe() to remap IDs correctly | 0 | 0 | F |  |
| `4a95c85c9948` | 2022-12-22 | 2022-12-27 | Andrii Nakryiko | bpf: perform byte-by-byte comparison only when necessary in regsafe() | 0 | 0 | F |  |
| `7f4ce97cd5ed` | 2022-12-22 | 2022-12-27 | Andrii Nakryiko | bpf: generalize MAYBE_NULL vs non-MAYBE_NULL rule | 0 | 0 | F |  |
| `910f69996674` | 2022-12-22 | 2022-12-27 | Andrii Nakryiko | bpf: reject non-exact register type matches in regsafe() | 0 | 0 | F |  |
| `a73bf9f2d969` | 2022-12-22 | 2022-12-27 | Andrii Nakryiko | bpf: reorganize struct bpf_reg_state fields | 0 | 0 | F |  |
| `6a3cd3318ff6` | 2023-02-12 | 2023-02-13 | Dave Marchevsky | bpf: Migrate release_on_unlock logic to non-owning ref semantics | 0 | 0 | F |  |
| `567da5d253cd` | 2023-03-02 | 2023-03-04 | Andrii Nakryiko | bpf: improve regsafe() checks for PTR_TO_{MEM,BUF,TP_BUFFER} | 0 | 0 | F |  |
| `215bf4962f6c` | 2023-03-08 | 2023-03-08 | Andrii Nakryiko | bpf: add iterator kfuncs registration and validation logic | 0 | 0 | F |  |
| `7be14c1c9030` | 2023-03-22 | 2023-03-22 | Daniel Borkmann | bpf: Fix __reg_bound_offset 64->32 var_off subreg propagation | 1 | 0 | F |  |
| `13fbcee55706` | 2023-04-06 | 2023-04-06 | Yonghong Song | bpf: Improve verifier JEQ/JNE insn branch taken checking | 0 | 0 | F |  |
| `d9439c21a9e4` | 2023-05-04 | 2023-05-04 | Andrii Nakryiko | bpf: improve precision backtrack logging | 0 | 0 | F |  |
| `1ffc85d9298e` | 2023-06-13 | 2023-06-13 | Eduard Zingerman | bpf: Verify scalar ids mapping in regsafe() using check_ids() | 1 | 0 | F |  |
| `42d31dd601fa` | 2023-10-22 | 2023-10-24 | Andrii Nakryiko | bpf: Improve JEQ/JNE branch taken logic | 0 | 0 | F |  |
| `2793a8b015f7` | 2023-10-24 | 2023-10-23 | Eduard Zingerman | bpf: exact states comparison for iterator convergence checks | 0 | 0 | F |  |
| `4621202adc5b` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: generalize reg_set_min_max() to handle two sets of two registers | 0 | 0 | F |  |
| `4d345887d2e5` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: unify 32-bit and 64-bit is_branch_taken logic | 0 | 0 | F |  |
| `6593f2e6741f` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: add special smin32/smax32 derivation from 64-bit bounds | 0 | 0 | F |  |
| `811476e9cc57` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: prepare reg_set_min_max for second set of registers | 0 | 0 | F |  |
| `93f7378734b5` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: derive smin/smax from umin/max bounds | 0 | 0 | F |  |
| `9e314f5d8682` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: drop knowledge-losing __reg_combine_{32,64}_into_{64,32} logic | 0 | 0 | F |  |
| `c1efab6468fd` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: derive subreg bounds from full bounds when upper 32 bits are constant | 0 | 0 | F |  |
| `c2a3ab094683` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: rename is_branch_taken reg arguments to prepare for the second one | 0 | 0 | F |  |
| `c31534267c18` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: generalize is_branch_taken() to work with two registers | 0 | 0 | F |  |
| `c51d5ad6543c` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: improve deduction of 64-bit bounds from 32-bit bounds | 0 | 0 | F |  |
| `d540517990a9` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: derive smin32/smax32 from umin32/umax32 bounds | 0 | 0 | F |  |
| `d7f008738171` | 2023-11-01 | 2023-11-09 | Andrii Nakryiko | bpf: try harder to deduce register bounds from different numeric domains | 0 | 0 | F |  |
| `82ce364c6087` | 2023-11-08 | 2023-11-09 | Shung-Hsi Yu | bpf: replace register_is_const() with is_reg_const() | 0 | 0 | F |  |
| `3cf98cf594ea` | 2023-11-11 | 2023-11-15 | Andrii Nakryiko | bpf: remove redundant s{32,64} -> u{32,64} deduction logic | 0 | 0 | F |  |
| `5f99f312bd3b` | 2023-11-11 | 2023-11-15 | Andrii Nakryiko | bpf: add register bounds sanity checks and sanitization | 0 | 0 | F |  |
| `67420501e868` | 2023-11-11 | 2023-11-15 | Andrii Nakryiko | bpf: generalize reg_set_min_max() to handle non-const register comparisons | 0 | 0 | WF |  |
| `96381879a370` | 2023-11-11 | 2023-11-15 | Andrii Nakryiko | bpf: generalize is_scalar_branch_taken() logic | 0 | 0 | F |  |
| `be41a203bb9e` | 2023-11-11 | 2023-11-15 | Andrii Nakryiko | bpf: enhance BPF_JEQ/BPF_JNE is_branch_taken logic | 0 | 0 | F |  |
| `cf5fe3c71c5a` | 2023-11-11 | 2023-11-15 | Andrii Nakryiko | bpf: make __reg{32,64}_deduce_bounds logic more robust | 0 | 0 | F |  |
| `ff8867af01da` | 2023-11-17 | 2023-11-17 | Andrii Nakryiko | bpf: rename BPF_F_TEST_SANITY_STRICT to BPF_F_TEST_REG_INVARIANTS | 0 | 0 | F |  |
| `81eff2e36481` | 2023-12-02 | 2023-12-02 | Andrii Nakryiko | bpf: simplify tnum output if a fully known constant | 0 | 0 | W |  |
| `d028f87517d6` | 2023-12-19 | 2023-12-19 | Menglong Dong | bpf: make the verifier tracks the "not equal" for regs | 0 | 0 | F |  |
| `c1e6148cb4f8` | 2024-01-27 | 2024-02-02 | Maxim Mikityanskiy | bpf: Preserve boundaries and track scalars on narrowing fill | 0 | 0 | F |  |
| `4f81c16f50ba` | 2024-03-05 | 2024-03-06 | Alexei Starovoitov | bpf: Recognize that two registers are safe when their ranges match | 0 | 0 | F |  |
| `6082b6c328b5` | 2024-03-07 | 2024-03-11 | Alexei Starovoitov | bpf: Recognize addr_space_cast instruction in the verifier. | 0 | 0 | F |  |
| `4c2a26fc80bc` | 2024-03-20 | 2024-03-21 | Harishankar Vishwanathan | bpf-next: Avoid goto in regs_refine_cond_op() | 0 | 0 | F |  |
| `1f586614f3ff` | 2024-04-16 | 2024-04-16 | Harishankar Vishwanathan | bpf: Harden and/or/xor value tracking in verifier | 0 | 0 | F |  |
| `a7de265cb2d8` | 2024-04-17 | 2024-04-22 | Rafael Passos | bpf: Fix typos in comments | 0 | 0 | F |  |
| `0922c78f592c` | 2024-05-06 | 2024-05-06 | Cupertino Miranda | bpf/verifier: refactor checks for range computation | 0 | 0 | F |  |
| `138cc42c05d1` | 2024-05-06 | 2024-05-06 | Cupertino Miranda | bpf/verifier: improve XOR and OR range computation | 0 | 0 | F |  |
| `41d047a87106` | 2024-05-06 | 2024-05-06 | Cupertino Miranda | bpf/verifier: relax MUL range computation check | 0 | 0 | F |  |
| `d786957ebd3f` | 2024-05-06 | 2024-05-06 | Cupertino Miranda | bpf/verifier: replace calls to mark_reg_unknown. | 0 | 0 | F |  |
| `98d7ca374ba4` | 2024-06-12 | 2024-06-14 | Alexei Starovoitov | bpf: Track delta between "linked" registers. | 0 | 0 | F |  |
| `28a4411076b2` | 2024-07-12 | 2024-07-12 | Shung-Hsi Yu | bpf: use check_add_overflow() to check for addition overflows | 0 | 0 | F |  |
| `deac5871eb07` | 2024-07-12 | 2024-07-12 | Shung-Hsi Yu | bpf: use check_sub_overflow() to check for subtraction overflows | 0 | 0 | F |  |
| `4bf79f9be434` | 2024-07-18 | 2024-07-29 | Eduard Zingerman | bpf: Track equal scalars history on per-instruction level | 1 | 0 | F |  |
| `9f5469b84577` | 2024-07-23 | 2024-07-29 | Yonghong Song | bpf: Get better reg range with ldsx and 32bit compare | 0 | 0 | F |  |
| `6f606ffd6dd7` | 2024-08-29 | 2024-08-29 | Martin KaFai Lau | bpf: Move insn_buf[16] to bpf_verifier_env | 0 | 0 | F |  |
| `940ce73bdec5` | 2024-09-04 | 2024-09-04 | Martin KaFai Lau | bpf: Remove the insn_buf array stack usage from the inline_bpf_loop() | 0 | 0 | F |  |
| `f6b9a69a9e56` | 2024-11-09 | 2024-11-11 | Kumar Kartikeya Dwivedi | bpf: Refactor active lock management | 0 | 0 | F |  |
| `9aa0ebde0014` | 2024-12-17 | 2024-12-30 | Matan Shachnai | bpf, verifier: Improve precision of BPF_MUL | 0 | 0 | F |  |
| `7a998a731627` | 2025-06-23 | 2025-06-24 | Harishankar Vishwanathan | bpf, verifier: Improve precision for BPF_ADD and BPF_SUB | 0 | 0 | F |  |
| `aced132599b3` | 2025-06-25 | 2025-06-25 | Song Liu | bpf: Add range tracking for BPF_NEG | 0 | 0 | WF |  |
| `0df1a55afa83` | 2025-07-01 | 2025-07-01 | Paul Chaignon | bpf: Warn on internal verifier errors | 0 | 0 | F |  |
| `6279846b9b25` | 2025-07-10 | 2025-07-11 | Paul Chaignon | bpf: Forget ranges when refining tnum after JSET | 0 | 0 | F |  |
| `5345e64760d3` | 2025-07-24 | 2025-07-27 | Paul Chaignon | bpf: Simplify bounds refinement from s32 | 0 | 0 | F |  |
| `00bf8d0c6c9b` | 2025-07-28 | 2025-07-28 | Paul Chaignon | bpf: Improve bounds when s64 crosses sign boundary | 0 | 0 | F |  |
| `5dbb19b16ac4` | 2025-07-28 | 2025-07-28 | Paul Chaignon | bpf: Add third round of bounds deduction | 0 | 0 | F |  |
| `f41345f47fb2` | 2025-08-20 | 2025-08-22 | Paul Chaignon | bpf: Use tnums for JEQ/JNE is_branch_taken logic | 0 | 0 | WF |  |
| `1df7dad4d5c4` | 2025-08-26 | 2025-08-27 | Nandakumar Edamana | bpf: Improve the general precision of tnum_mul | 0 | 0 | W |  |
| `107e16979905` | 2025-09-18 | 2025-09-19 | Eduard Zingerman | bpf: disable and remove registers chain based liveness | 0 | 0 | F |  |
| `daf4c2929fb7` | 2025-09-18 | 2025-09-19 | Eduard Zingerman | bpf: bpf_verifier_state->cleaned flag instead of REG_LIVE_DONE | 0 | 0 | F |  |
| `e41c237953b3` | 2025-09-18 | 2025-09-19 | Eduard Zingerman | bpf: enable callchain sensitive stack liveness tracking | 0 | 0 | F |  |
| `d43ad9da8052` | 2025-11-03 | 2025-11-03 | KaFai Wan | bpf: Skip bounds adjustment for conditional jumps on same scalar register | 0 | 0 | F |  |
| `493d9e0d6083` | 2025-11-05 | 2025-11-05 | Anton Protopopov | bpf, x86: add support for indirect jumps | 0 | 0 | F |  |
| `d18dec4b8990` | 2025-12-02 | 2025-12-10 | Cupertino Miranda | bpf: verifier improvement in 32bit shift sign extension pattern | 0 | 0 | F |  |
| `840692326e92` | 2025-12-30 | 2025-12-31 | Eduard Zingerman | bpf: allow states pruning for misc/invalid slots in iterator loops | 0 | 0 | F |  |
| `bffacdb80b93` | 2026-01-12 | 2026-01-13 | Alexei Starovoitov | bpf: Recognize special arithmetic shift in the verifier | 0 | 0 | F |  |
| `44fdd581d273` | 2026-01-19 | 2026-01-20 | Yazhou Tang | bpf: Add range tracking for BPF_DIV and BPF_MOD | 0 | 0 | F |  |
| `b0388bafa494` | 2026-02-03 | 2026-02-03 | Puranjay Mohan | bpf: Relax scalar id equivalence for state pruning | 0 | 0 | F |  |
| `9d2119984224` | 2026-02-04 | 2026-02-04 | Tianci Cao | bpf: Add bitwise tracking for BPF_END | 0 | 0 | WF |  |
| `022ac0750883` | 2026-02-12 | 2026-02-13 | Eduard Zingerman | bpf: use reg->var_off instead of reg->off for pointers | 0 | 0 | F |  |
| `3d91c618aca4` | 2026-02-12 | 2026-02-13 | Eduard Zingerman | bpf: rename bpf_reg_state->off to bpf_reg_state->delta | 0 | 0 | F |  |
| `76e954155b45` | 2026-02-27 | 2026-02-27 | Harishankar Vishwanathan | bpf: Introduce tnum_step to step through tnum's members | 0 | 0 | W |  |
| `efc11a667878` | 2026-02-27 | 2026-02-27 | Paul Chaignon | bpf: Improve bounds when tnum has a single possible value | 1 | 0 | F |  |
| `fbc7aef517d8` | 2026-03-06 | 2026-03-06 | Eduard Zingerman | bpf: Fix u32/s32 bounds when ranges cross min/max boundary | 0 | 0 | F |  |
| `879cace97667` | 2026-03-13 | 2026-03-13 | Eduard Zingerman | bpf: better naming for __reg_deduce_bounds() parts | 0 | 0 | F |  |
| `9e5fcb003aec` | 2026-03-13 | 2026-03-13 | Paul Chaignon | bpf: Avoid one round of bounds deduction | 0 | 0 | F |  |
| `bc308be380c1` | 2026-03-19 | 2026-03-21 | Daniel Borkmann | bpf: Fix sync_linked_regs regarding BPF_ADD_CONST32 zext propagation | 1 | 0 | F |  |
| `833ef4a954e1` | 2026-03-20 | 2026-03-24 | Hao Sun | bpf: Simplify tnum_step() | 0 | 0 | W |  |
| `bfec8e88ff60` | 2026-03-22 | 2026-03-22 | Alexei Starovoitov | Merge git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf 7.0-rc5 | 0 | 0 | F | merge |
| `a8502a79e832` | 2026-03-31 | 2026-03-31 | Alexei Starovoitov | bpf: Fix regsafe() for pointers to packet | 1 | 0 | F |  |
| `a1311b94ef85` | 2026-04-02 | 2026-04-02 | Harishankar Vishwanathan | bpf: Refactor reg_bounds_sanity_check | 0 | 0 | F |  |
| `a2a14e874b4e` | 2026-04-02 | 2026-04-02 | Harishankar Vishwanathan | bpf: Exit early if reg_bounds_sync gets invalid inputs | 0 | 0 | F |  |
| `b254c6d816e5` | 2026-04-02 | 2026-04-02 | Harishankar Vishwanathan | bpf: Simulate branches to prune based on range violations | 0 | 0 | F |  |
| `891a05ccba92` | 2026-04-03 | 2026-04-03 | Alexei Starovoitov | Merge git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf 7.0-rc6+ | 0 | 0 | F | merge |
| `c82834a5a11f` | 2026-04-12 | 2026-04-12 | Alexei Starovoitov | bpf: Move state equivalence logic to states.c | 0 | 0 | F |  |
| `256f0071f9b6` | 2026-04-24 | 2026-04-24 | Eduard Zingerman | bpf: representation and basic operations on circular numbers | 0 | 0 | W |  |
| `b93f7180f0bc` | 2026-04-24 | 2026-04-24 | Eduard Zingerman | bpf: use accessor functions for bpf_reg_state min/max fields | 0 | 0 | F |  |
| `bbc631085503` | 2026-04-24 | 2026-04-24 | Eduard Zingerman | bpf: replace min/max fields with struct cnum{32,64} | 0 | 0 | F |  |
| `cd5b460ed1ec` | 2026-04-25 | 2026-04-27 | Eduard Zingerman | bpf: range_within() must check cnum ranges instead of min/max pairs | 1 | 0 | WF |  |
| `79b8ebcbe483` | 2026-04-27 | 2026-04-27 | Alan Maguire | bpf: Export cnum_umin/umax() helpers for netronome driver | 1 | 0 | W |  |
| `308c7a0ae885` | 2026-05-28 | 2026-06-01 | Amery Hung | bpf: Refactor object relationship tracking and fix dynptr UAF bug | 1 | 0 | F |  |
| `a15970d916b3` | 2026-07-29 | 2026-07-31 | Eduard Zingerman | bpf: Simplify sanitize_err() signature | 0 | 0 | F |  |
| `4e3fb5bba680` | 2026-07-30 | 2026-08-20 | Vinicius Sampaio | bpf: Simplify cnum contains() by removing redundant branches | 0 | 0 | W |  |
| `705249119d94` | 2026-07-30 | 2026-08-20 | Vinicius Sampaio | bpf: Avoid redundant min()/max() in cnum signed bounds | 0 | 0 | W |  |
| `b601a4ecbe67` | 2026-07-30 | 2026-08-20 | Vinicius Sampaio | bpf: Simplify cnum normalize() by dropping unnecessary comparisons | 0 | 0 | W |  |
| `c0e091f30f0d` | 2026-08-01 | 2026-08-03 | Amery Hung | bpf: Rename ARG_CONST_SIZE{,_OR_ZERO} to ARG_MEM_SIZE{,_OR_ZERO} | 0 | 0 | F |  |
| `71919742c83c` | 2026-09-18 | 2026-09-17 | Kumar Kartikeya Dwivedi | bpf: Assign lock identity to callback map values | 1 | 0 | F |  |
| `fd16449a9b3b` | 2026-09-18 | 2026-09-17 | Kumar Kartikeya Dwivedi | bpf: Preserve packet pointer class displacement in regsafe() | 1 | 0 | F |  |
| `8901cee9316d` | 2026-09-19 | 2026-09-19 | Kumar Kartikeya Dwivedi | bpf: Compare stack frames in regs_exact() | 1 | 0 | F |  |
| `ecc441fc774e` | 2026-09-24 | 2026-09-24 | Kumar Kartikeya Dwivedi | bpf: Size the per-frame verifier structures for a 2 KiB stack | 0 | 0 | F |  |
| `0892ef2a7ef3` | 2026-10-09 | 2026-10-09 | Eduard Zingerman | bpf: Representation for intervals with steps | 0 | 0 | F |  |
| `366b4c68d830` | 2026-10-09 | 2026-10-09 | Eduard Zingerman | bpf: Allow subrange relations for PTR_TO_STACK in regsafe() | 0 | 0 | F |  |
| `4072d7f56b44` | 2026-10-09 | 2026-10-09 | Eduard Zingerman | bpf: Add tnum_alignment() | 0 | 0 | W |  |
| `685ac494443e` | 2026-10-09 | 2026-10-09 | Eduard Zingerman | bpf: Expose bpf_rev_opcode() and bpf_flip_opcode() | 0 | 0 | F |  |
| `78e61c01a760` | 2026-10-09 | 2026-10-09 | Eduard Zingerman | bpf: Add cnum64_intersect_linear() | 0 | 0 | WF |  |
| `89e72f81a455` | 2026-10-09 | 2026-10-09 | Eduard Zingerman | bpf: Varying offset access support for PTR_TO_BTF_ID pointers | 0 | 0 | F |  |
| `a8e9a53f6df6` | 2026-10-09 | 2026-10-09 | Eduard Zingerman | bpf: Add cnum{32,64}_union() | 0 | 0 | W |  |
| `4d274f1ef049` | 2026-10-13 | 2026-10-15 | Eduard Zingerman | bpf: Reg_bounds_sync() comment fixup | 1 | 0 | F |  |
| `ee4f44e0e3c8` | 2026-10-17 | 2026-10-17 | Josef Bacik | bpf: Look at all 64 bits of a BPF_JSET mask on 32-bit | 1 | 0 | F |  |

## Appendix B. Per-job hash counts (`wc -l L/<job>.hashes`), v5.0..HEAD unless noted

| job (file__function) | spec | range | commits |
|---|---|---|---|
| `verifier.c__reg_bounds_sync` | `:reg_bounds_sync:kernel/bpf/verifier.c` | `v5.0..HEAD` | 7 |
| `verifier.c__range_bounds_violation` | `2398,2401:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c____update_reg_bounds` | `:__update_reg_bounds:kernel/bpf/verifier.c` | `v5.0..HEAD` | 1 |
| `verifier.c____update_reg32_bounds` | `:__update_reg32_bounds:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c____update_reg64_bounds` | `:__update_reg64_bounds:kernel/bpf/verifier.c` | `v5.0..HEAD` | 4 |
| `verifier.c__cnum32_from_tnum` | `:cnum32_from_tnum:kernel/bpf/verifier.c` | `v5.0..HEAD` | 2 |
| `verifier.c__cnum64_from_tnum` | `:cnum64_from_tnum:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c____reg_deduce_bounds` | `:__reg_deduce_bounds:kernel/bpf/verifier.c` | `v5.0..HEAD` | 5 |
| `verifier.c__deduce_bounds_32_from_64` | `:deduce_bounds_32_from_64:kernel/bpf/verifier.c` | `v5.0..HEAD` | 12 |
| `verifier.c__deduce_bounds_64_from_32` | `:deduce_bounds_64_from_32:kernel/bpf/verifier.c` | `v5.0..HEAD` | 7 |
| `verifier.c____reg_bound_offset` | `:__reg_bound_offset:kernel/bpf/verifier.c` | `v5.0..HEAD` | 4 |
| `verifier.c____update_bounds_from_step` | `:__update_bounds_from_step:kernel/bpf/verifier.c` | `v5.0..HEAD` | 1 |
| `verifier.c_____mark_reg_known` | `:___mark_reg_known:kernel/bpf/verifier.c` | `v5.0..HEAD` | 5 |
| `verifier.c__reg_step_reset` | `:reg_step_reset:kernel/bpf/verifier.c` | `v5.0..HEAD` | 1 |
| `verifier.c__const_tnum_range_mismatch` | `:const_tnum_range_mismatch:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__const_tnum_range_mismatch_32` | `:const_tnum_range_mismatch_32:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__reg_bounds_sanity_check` | `:reg_bounds_sanity_check:kernel/bpf/verifier.c` | `v5.0..HEAD` | 18 |
| `verifier.c____mark_reg_known` | `2074,2083:kernel/bpf/verifier.c` | `v5.0..HEAD` | 4 |
| `verifier.c____mark_reg32_known` | `:__mark_reg32_known:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c____mark_reg32_unbounded` | `:__mark_reg32_unbounded:kernel/bpf/verifier.c` | `v5.0..HEAD` | 2 |
| `verifier.c____mark_reg64_unbounded` | `:__mark_reg64_unbounded:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c____mark_reg_unbounded` | `:__mark_reg_unbounded:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__reset_reg64_and_tnum` | `:reset_reg64_and_tnum:kernel/bpf/verifier.c` | `v5.0..HEAD` | 1 |
| `verifier.c__reset_reg32_and_tnum` | `:reset_reg32_and_tnum:kernel/bpf/verifier.c` | `v5.0..HEAD` | 1 |
| `verifier.c__scalar_min_max_add` | `16458,16462:kernel/bpf/verifier.c` | `v5.0..HEAD` | 6 |
| `verifier.c__scalar_min_max_sub` | `:scalar_min_max_sub:kernel/bpf/verifier.c` | `v5.0..HEAD` | 6 |
| `verifier.c__scalar_min_max_and` | `:scalar_min_max_and:kernel/bpf/verifier.c` | `v5.0..HEAD` | 6 |
| `verifier.c__scalar_min_max_or` | `:scalar_min_max_or:kernel/bpf/verifier.c` | `v5.0..HEAD` | 6 |
| `verifier.c__scalar_min_max_xor` | `:scalar_min_max_xor:kernel/bpf/verifier.c` | `v5.0..HEAD` | 4 |
| `verifier.c__scalar_min_max_lsh` | `:scalar_min_max_lsh:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar_min_max_rsh` | `:scalar_min_max_rsh:kernel/bpf/verifier.c` | `v5.0..HEAD` | 5 |
| `verifier.c__scalar_min_max_arsh` | `:scalar_min_max_arsh:kernel/bpf/verifier.c` | `v5.0..HEAD` | 4 |
| `verifier.c__scalar32_min_max_add` | `16452,16456:kernel/bpf/verifier.c` | `v5.0..HEAD` | 5 |
| `verifier.c__scalar32_min_max_sub` | `:scalar32_min_max_sub:kernel/bpf/verifier.c` | `v5.0..HEAD` | 6 |
| `verifier.c__scalar32_min_max_and` | `:scalar32_min_max_and:kernel/bpf/verifier.c` | `v5.0..HEAD` | 5 |
| `verifier.c__scalar32_min_max_or` | `:scalar32_min_max_or:kernel/bpf/verifier.c` | `v5.0..HEAD` | 6 |
| `verifier.c__scalar32_min_max_xor` | `:scalar32_min_max_xor:kernel/bpf/verifier.c` | `v5.0..HEAD` | 5 |
| `verifier.c__scalar32_min_max_lsh` | `16886,16902:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar32_min_max_rsh` | `:scalar32_min_max_rsh:kernel/bpf/verifier.c` | `v5.0..HEAD` | 4 |
| `verifier.c__scalar32_min_max_arsh` | `:scalar32_min_max_arsh:kernel/bpf/verifier.c` | `v5.0..HEAD` | 4 |
| `verifier.c____scalar32_min_max_lsh` | `:__scalar32_min_max_lsh:kernel/bpf/verifier.c` | `v5.0..HEAD` | 4 |
| `verifier.c____scalar64_min_max_lsh` | `:__scalar64_min_max_lsh:kernel/bpf/verifier.c` | `v5.0..HEAD` | 5 |
| `verifier.c__scalar_min_max_mul` | `:scalar_min_max_mul:kernel/bpf/verifier.c` | `v5.0..HEAD` | 5 |
| `verifier.c__scalar_min_max_udiv` | `:scalar_min_max_udiv:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar_min_max_sdiv` | `:scalar_min_max_sdiv:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar_min_max_umod` | `:scalar_min_max_umod:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar_min_max_smod` | `:scalar_min_max_smod:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar32_min_max_mul` | `:scalar32_min_max_mul:kernel/bpf/verifier.c` | `v5.0..HEAD` | 5 |
| `verifier.c__scalar32_min_max_udiv` | `:scalar32_min_max_udiv:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar32_min_max_sdiv` | `:scalar32_min_max_sdiv:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar32_min_max_umod` | `:scalar32_min_max_umod:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar32_min_max_smod` | `:scalar32_min_max_smod:kernel/bpf/verifier.c` | `v5.0..HEAD` | 3 |
| `verifier.c__scalar_step_add` | `:scalar_step_add:kernel/bpf/verifier.c` | `v5.0..HEAD` | 1 |
| `verifier.c__scalar_step_scale` | `:scalar_step_scale:kernel/bpf/verifier.c` | `v5.0..HEAD` | 1 |
| `verifier.c__scalar_step_mul` | `:scalar_step_mul:kernel/bpf/verifier.c` | `v5.0..HEAD` | 1 |
| `verifier.c__scalar_step_lsh` | `:scalar_step_lsh:kernel/bpf/verifier.c` | `v5.0..HEAD` | 1 |
| `verifier.c__reg_step_check_unsigned` | `:reg_step_check_unsigned:kernel/bpf/verifier.c` | `v5.0..HEAD` | 2 |
| `verifier.c__adjust_scalar_min_max_vals` | `:adjust_scalar_min_max_vals:kernel/bpf/verifier.c` | `v5.0..HEAD` | 19 |
| `verifier.c__is_safe_to_compute_dst_reg_range` | `:is_safe_to_compute_dst_reg_range:kernel/bpf/verifier.c` | `v5.0..HEAD` | 7 |
| `verifier.c__zext_32_to_64` | `:zext_32_to_64:kernel/bpf/verifier.c` | `v5.0..HEAD` | 4 |
| `verifier.c__coerce_reg_to_size` | `:coerce_reg_to_size:kernel/bpf/verifier.c` | `v5.0..HEAD` | 6 |
| `verifier.c__regs_refine_cond_op` | `18252,18388:kernel/bpf/verifier.c` | `v5.0..HEAD` | 25 |
| `verifier.c__is_reg_const` | `:is_reg_const:kernel/bpf/verifier.c` | `v5.0..HEAD` | 2 |
| `verifier.c__reg_const_value` | `:reg_const_value:kernel/bpf/verifier.c` | `v5.0..HEAD` | 2 |
| `verifier.c__bpf_flip_opcode` | `:bpf_flip_opcode:kernel/bpf/verifier.c` | `v5.0..HEAD` | 2 |
| `verifier.c__bpf_rev_opcode` | `:bpf_rev_opcode:kernel/bpf/verifier.c` | `v5.0..HEAD` | 8 |
| `verifier.c__simulate_both_branches_taken` | `:simulate_both_branches_taken:kernel/bpf/verifier.c` | `v5.0..HEAD` | 6 |
| `verifier.c__is_scalar_branch_taken` | `:is_scalar_branch_taken:kernel/bpf/verifier.c` | `v5.0..HEAD` | 15 |
| `bpf_verifier.h__imod` | `:imod:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 14 |
| `bpf_verifier.h__reg_smin` | `:reg_smin:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_smax` | `:reg_smax:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_umin` | `:reg_umin:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_umax` | `:reg_umax:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_s32_min` | `:reg_s32_min:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_s32_max` | `:reg_s32_max:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_u32_min` | `:reg_u32_min:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_u32_max` | `:reg_u32_max:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_set_srange32` | `:reg_set_srange32:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_set_urange32` | `:reg_set_urange32:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_set_srange64` | `:reg_set_srange64:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `bpf_verifier.h__reg_set_urange64` | `:reg_set_urange64:include/linux/bpf_verifier.h` | `v5.0..HEAD` | 2 |
| `states.c__range_within` | `:range_within:kernel/bpf/states.c` | `v5.0..HEAD` | 4 |
| `verifier.c-premove__range_within` | `19000,19011:kernel/bpf/verifier.c` | `v5.0..c82834a5a11f^` | 2 |
| `states.c__regsafe` | `:regsafe:kernel/bpf/states.c` | `v5.0..HEAD` | 7 |
| `verifier.c-premove__regsafe` | `:regsafe:kernel/bpf/verifier.c` | `v5.0..c82834a5a11f^` | 34 |
