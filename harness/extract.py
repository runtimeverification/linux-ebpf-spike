#!/usr/bin/env python3
"""Copy kernel C verbatim into extracted/.

Usage: extract.py <kernel-tree> <out-dir>

Whole files are copied as-is with a provenance header.  Individual functions
are located by name: the definition line is the first line matching
'^(static )?[a-z0-9_ ]*\\bNAME\\(' that is followed (possibly after the
parameter list) by a line that is exactly '{'; the function ends at the first
following line that is exactly '}'.  Forward declarations (ending in ';') are
skipped.  Leading comment blocks directly above the definition are included.
"""
import os, re, subprocess, sys

KERNEL, OUT = sys.argv[1], sys.argv[2]
COMMIT = subprocess.check_output(["git", "-C", KERNEL, "rev-parse", "HEAD"]).decode().strip()

WHOLE_FILES = [
    "kernel/bpf/tnum.c", "include/linux/tnum.h",
    "kernel/bpf/cnum.c", "kernel/bpf/cnum_defs.h", "include/linux/cnum.h",
]

# (output file, source file, [function names in the order they appear in the output])
FUNCTION_SETS = [
    ("verifier_bounds.c", "kernel/bpf/verifier.c", [
        "reg_step_reset", "scalar_step_add", "scalar_step_scale", "reg_step_check_unsigned",
        "___mark_reg_known", "__mark_reg_known", "__mark_reg32_known",
        "__mark_reg32_unbounded", "__mark_reg64_unbounded", "__mark_reg_unbounded",
        "reset_reg64_and_tnum", "reset_reg32_and_tnum",
        "cnum32_from_tnum", "cnum64_from_tnum",
        "__update_reg32_bounds", "__update_reg64_bounds", "__update_reg_bounds",
        "deduce_bounds_32_from_64", "deduce_bounds_64_from_32", "__reg_deduce_bounds",
        "__reg_bound_offset", "__update_bounds_from_step",
        "reg_bounds_sync",
        "const_tnum_range_mismatch", "const_tnum_range_mismatch_32", "range_bounds_violation",
        "zext_32_to_64", "coerce_reg_to_size",
        "scalar_step_mul", "scalar_step_lsh",
        "scalar32_min_max_add", "scalar_min_max_add",
        "scalar32_min_max_sub", "scalar_min_max_sub",
        "scalar32_min_max_mul", "scalar_min_max_mul",
        "scalar32_min_max_udiv", "scalar_min_max_udiv",
        "scalar32_min_max_sdiv", "scalar_min_max_sdiv",
        "scalar32_min_max_umod", "scalar_min_max_umod",
        "scalar32_min_max_smod", "scalar_min_max_smod",
        "scalar32_min_max_and", "scalar_min_max_and",
        "scalar32_min_max_or", "scalar_min_max_or",
        "scalar32_min_max_xor", "scalar_min_max_xor",
        "__scalar32_min_max_lsh", "scalar32_min_max_lsh", "__scalar64_min_max_lsh", "scalar_min_max_lsh",
        "scalar32_min_max_rsh", "scalar_min_max_rsh",
        "scalar32_min_max_arsh", "scalar_min_max_arsh",
    ]),
    ("verifier_refine.c", "kernel/bpf/verifier.c", [
        "is_reg_const", "reg_const_value", "bpf_flip_opcode", "bpf_rev_opcode", "regs_refine_cond_op",
    ]),
    ("states_range_within.c", "kernel/bpf/states.c", ["range_within"]),
    ("bpf_verifier_h_accessors.c", "include/linux/bpf_verifier.h", [
        "imod", "reg_smin", "reg_smax", "reg_umin", "reg_umax",
        "reg_s32_min", "reg_s32_max", "reg_u32_min", "reg_u32_max",
        "reg_set_srange32", "reg_set_urange32", "reg_set_srange64", "reg_set_urange64",
    ]),
]

def header(src, ranges):
    r = ", ".join(f"{a}-{b}" for a, b in ranges)
    return (f"/* Extracted verbatim from {src}\n * lines {r}\n * commit {COMMIT}\n"
            f" * by harness/extract.py; do not edit. */\n")

def find_function(lines, name):
    pat = re.compile(r"^(static\s+)?(inline\s+)?[A-Za-z0-9_ \*]*\b" + re.escape(name) + r"\(")
    for i, line in enumerate(lines):
        if not pat.match(line):
            continue
        # skip prototypes: scan to the end of the parameter list
        j = i
        while ")" not in lines[j]:
            j += 1
        tail = lines[j].split(")")[-1].strip()
        if tail.endswith(";"):
            continue
        if tail == "{":
            body_start = j
        elif lines[j + 1].strip() == "{":
            body_start = j + 1
        else:
            continue
        k = body_start
        while lines[k].rstrip("\n") != "}":
            k += 1
        # include a comment block immediately above
        s = i
        if s > 0 and lines[s - 1].rstrip().endswith("*/"):
            while s > 0 and not lines[s - 1].lstrip().startswith("/*"):
                s -= 1
            s -= 1
        return s, k  # 0-based inclusive
    raise SystemExit(f"function {name} not found")

os.makedirs(OUT, exist_ok=True)
for f in WHOLE_FILES:
    src = open(os.path.join(KERNEL, f)).read()
    n = src.count("\n")
    with open(os.path.join(OUT, os.path.basename(f)), "w") as o:
        o.write(header(f, [(1, n)]))
        o.write(src)
    print(f"{f}: whole file, {n} lines")

for outname, src, names in FUNCTION_SETS:
    lines = open(os.path.join(KERNEL, src)).readlines()
    chunks, ranges = [], []
    for name in names:
        s, e = find_function(lines, name)
        ranges.append((s + 1, e + 1))
        chunks.append("".join(lines[s:e + 1]))
    with open(os.path.join(OUT, outname), "w") as o:
        o.write(header(src, ranges))
        o.write("\n".join(chunks))
    print(f"{outname}: {len(names)} functions from {src}: " +
          " ".join(f"{n}@{a}-{b}" for n, (a, b) in zip(names, ranges)))
