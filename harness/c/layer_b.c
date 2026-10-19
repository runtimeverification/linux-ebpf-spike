/* Compiles the Layer B kernel functions (extracted verbatim) in user space
 * and exports non-static wrappers with a k_ prefix for the harness. */
#include <linux/bpf_verifier.h>
/* forward declaration present in verifier.c (line 2352) ahead of reg_bounds_sync() */
static bool range_bounds_violation(struct bpf_reg_state *reg);
#include "extracted/verifier_bounds.c"
#include "extracted/states_range_within.c"

#define WRAP1(name) void k_##name(struct bpf_reg_state *r) { name(r); }
#define WRAP2(name) void k_##name(struct bpf_reg_state *d, struct bpf_reg_state *s) { name(d, s); }
WRAP1(reg_bounds_sync)
WRAP1(__update_reg_bounds)
WRAP1(__update_reg32_bounds)
WRAP1(__update_reg64_bounds)
WRAP1(__reg_deduce_bounds)
WRAP1(__reg_bound_offset)
WRAP1(__update_bounds_from_step)
WRAP1(zext_32_to_64)
WRAP2(scalar32_min_max_add)
WRAP2(scalar_min_max_add)
WRAP2(scalar32_min_max_sub)
WRAP2(scalar_min_max_sub)
WRAP2(scalar32_min_max_mul)
WRAP2(scalar_min_max_mul)
WRAP2(scalar32_min_max_and)
WRAP2(scalar_min_max_and)
WRAP2(scalar32_min_max_or)
WRAP2(scalar_min_max_or)
WRAP2(scalar32_min_max_xor)
WRAP2(scalar_min_max_xor)
WRAP2(scalar32_min_max_lsh)
WRAP2(scalar_min_max_lsh)
WRAP2(scalar32_min_max_rsh)
WRAP2(scalar_min_max_rsh)
WRAP2(scalar32_min_max_arsh)
WRAP2(scalar_min_max_arsh)
WRAP2(scalar_step_mul)
WRAP2(scalar_step_lsh)
void k_scalar_step_add(struct bpf_reg_state *d, const struct bpf_reg_state *a, const struct bpf_reg_state *b) { scalar_step_add(d, a, b); }
void k_scalar_step_scale(struct bpf_reg_state *d, u64 amount) { scalar_step_scale(d, amount); }
void k_coerce_reg_to_size(struct bpf_reg_state *r, int size) { coerce_reg_to_size(r, size); }
bool k_range_within(const struct bpf_reg_state *o, const struct bpf_reg_state *c) { return range_within(o, c); }
bool k_range_bounds_violation(struct bpf_reg_state *r) { return range_bounds_violation(r); }
bool k_const_tnum_range_mismatch(struct bpf_reg_state *r) { return const_tnum_range_mismatch(r); }
bool k_const_tnum_range_mismatch_32(struct bpf_reg_state *r) { return const_tnum_range_mismatch_32(r); }
struct cnum32 k_cnum32_from_tnum(struct tnum t) { return cnum32_from_tnum(t); }
struct cnum64 k_cnum64_from_tnum(struct tnum t) { return cnum64_from_tnum(t); }
u16 k_imod(s64 v, u16 step) { return imod(v, step); }
/* layout checks for the Rust FFI mirror */
size_t k_sizeof_reg(void) { return sizeof(struct bpf_reg_state); }
size_t k_offsetof_var_off(void) { return offsetof(struct bpf_reg_state, var_off); }
size_t k_offsetof_base(void) { return offsetof(struct bpf_reg_state, base); }
size_t k_offsetof_id(void) { return offsetof(struct bpf_reg_state, id); }
