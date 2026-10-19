/* Extracted verbatim from kernel/bpf/states.c
 * lines 301-329
 * commit 4f842631f178f41baa2d2d444a277d54c07666a1
 * by harness/extract.py; do not edit. */
/* check %cur's range satisfies %old's */
static bool range_within(const struct bpf_reg_state *old,
			 const struct bpf_reg_state *cur)
{
	if (!cnum64_is_subset(old->r64, cur->r64) ||
	    !cnum32_is_subset(old->r32, cur->r32))
		return false;

	if (old->step <= 1)
		return true;

	if (cnum64_is_const(cur->r64))
		return imod((s64)cnum64_smin(cur->r64), old->step) == old->base;

	/*
	 * Both `old` and `cur` define some sets of points.
	 * Return true, if points defined by `cur` are a subset of points defined by `old`:
	 * - bounds for `cur` should be within bounds for `old`;
	 * - cur->step should be dividable by old->step;
	 * - cur->base should start at integer number of old->step
	 *   steps from old->base.
	 *
	 * E.g. the following ranges are compatible:
	 * - old [0, 10] step 2
	 * - new [2, 10] step 4
	 */
	return cur->step % old->step == 0 &&
	       (cur->base - old->base) % old->step == 0;
}
