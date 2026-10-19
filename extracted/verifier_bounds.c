/* Extracted verbatim from kernel/bpf/verifier.c
 * lines 1951-1955, 1957-1999, 2001-2034, 2036-2060, 2062-2069, 2071-2083, 2091-2095, 2209-2212, 2214-2217, 2219-2224, 2226-2230, 2232-2236, 2238-2248, 2250-2259, 2261-2264, 2266-2299, 2301-2305, 2307-2310, 2312-2315, 2317-2321, 2323-2344, 2346-2350, 2354-2380, 2382-2388, 2390-2396, 2398-2401, 6090-6096, 6098-6124, 16135-16141, 16143-16151, 16452-16456, 16458-16462, 16464-16468, 16470-16474, 16476-16505, 16507-16536, 16538-16548, 16550-16560, 16562-16596, 16598-16632, 16634-16651, 16653-16670, 16672-16709, 16711-16748, 16750-16769, 16771-16792, 16794-16813, 16815-16836, 16838-16852, 16854-16870, 16872-16884, 16886-16902, 16904-16928, 16930-16943, 16945-16973, 16975-17005, 17007-17025, 17027-17046
 * commit 4f842631f178f41baa2d2d444a277d54c07666a1
 * by harness/extract.py; do not edit. */
static void reg_step_reset(struct bpf_reg_state *reg)
{
	reg->base = 0;
	reg->step = 1;
}

static void scalar_step_add(struct bpf_reg_state *dst_reg,
			    const struct bpf_reg_state *a,
			    const struct bpf_reg_state *b)
{
	const struct bpf_reg_state *reg;
	s64 amount, tmp;

	if (tnum_is_const(b->var_off)) {
		reg = a;
		amount = (s64)b->var_off.value;
	} else if (tnum_is_const(a->var_off)) {
		reg = b;
		amount = (s64)a->var_off.value;
	} else {
		reg_step_reset(dst_reg);
		return;
	}

	/*
	 * Let x be a possible signed value of the register,
	 * d = amount, s = reg->step, and b = reg->base.
	 * Then x mod s = b, with s > 0 and 0 <= b < s.
	 * If the addition causes signed underflow, the resulting value
	 * is x + d + 2**64.
	 *
	 * Taking the result modulo s and substituting x mod s = b gives:
	 *   (x + d + 2**64) mod s = (b + d + (2**64 mod s)) mod s      (1)
	 * Keeping reg->step = s and updating reg->base to (b + d) mod s
	 * requires (1) to equal (b + d) mod s, which holds if and only
	 * if 2**64 mod s = 0.
	 * Signed overflow subtracts 2**64 and has the same requirement.
	 *
	 * Conservatively reset the stride if either wrap is possible.
	 */
	if (check_add_overflow(reg_smin(reg), amount, &tmp) ||
	    check_add_overflow(reg_smax(reg), amount, &tmp)) {
		reg_step_reset(dst_reg);
		return;
	}

	dst_reg->base = (reg->base + imod(amount, reg->step)) % reg->step;
	dst_reg->step = reg->step;
}

static void scalar_step_scale(struct bpf_reg_state *dst_reg, u64 amount)
{
	u16 step;
	s64 tmp;

	/*
	 * Using the same notation as scalar_step_add(), with d > 0,
	 * the scaled value satisfies (x * d) mod (s * d) = b * d.
	 * If the multiplication wraps, its signed result can be represented
	 * as x * d - n * 2**64 for some nonzero integer n.
	 *
	 * Taking the result modulo s * d gives:
	 *   (x * d - n * 2**64) mod (s * d) =
	 *   (b * d - (n * 2**64 mod (s * d))) mod (s * d)              (1)
	 * Updating dst_reg->base to b * d and dst_reg->step to s * d
	 * requires (1) to equal b * d, which holds if and only if
	 * n * 2**64 mod (s * d) = 0.
	 *
	 * Conservatively reset the stride if a wrap is possible.
	 */
	if (amount == 0 || check_mul_overflow(dst_reg->step, amount, &step) ||
	    check_mul_overflow(reg_smin(dst_reg), (s64)amount, &tmp) ||
	    check_mul_overflow(reg_smax(dst_reg), (s64)amount, &tmp)) {
		reg_step_reset(dst_reg);
		return;
	}
	/*
	 * The above established that `step = dst_reg->step * amount`
	 * does not overflow, therefore the base < step invariant holds
	 * after assignments below.
	 */
	dst_reg->base = dst_reg->base * amount;
	dst_reg->step = step;
}

/*
 * Let x be a possible signed value of the register,
 * s = reg->step, and b = reg->base.
 * Then x mod s = b, with s > 0 and 0 <= b < s.
 * Truncating to N bits and then zero- or sign-extending x
 * is equivalent to computing x + k * 2**N for some integer k.
 * For example, sign-extending the low 8 bits of x = 255 can
 * be expressed as 255 - 2**8 = -1.
 *
 * Taking the result modulo s and substituting x mod s = b gives:
 *   (x + k * 2**N) mod s = (b + (k * 2**N mod s)) mod s
 * Keeping reg->base = b and reg->step = s requires this to equal b,
 * which holds if and only if k * 2**N mod s = 0.
 * Continuing the example with s = 3 and b = 0, we have 255 mod 3 = 0,
 * but (-1) mod 3 = 2, so the original base and step no longer hold.
 *
 * Conservatively reset the stride unless all possible values fit in
 * the range where the conversion leaves them unchanged.
 * Call before updating the register's bounds. Requires 0 < bits < 64.
 */
static void reg_step_check_unsigned(struct bpf_reg_state *reg, u32 bits)
{
	if (reg_umax(reg) >= (1ULL << bits))
		reg_step_reset(reg);
}

/* This helper doesn't clear reg->id */
static void ___mark_reg_known(struct bpf_reg_state *reg, u64 imm)
{
	reg->var_off = tnum_const(imm);
	reg->r64 = cnum64_from_urange(imm, imm);
	reg->r32 = cnum32_from_urange((u32)imm, (u32)imm);
	reg_step_reset(reg);
}

/* Mark the unknown part of a register (variable offset or scalar value) as
 * known to have the value @imm.
 */
static void __mark_reg_known(struct bpf_reg_state *reg, u64 imm)
{
	/* Clear off and union(map_ptr, range) */
	memset(((u8 *)reg) + sizeof(reg->type), 0,
	       offsetof(struct bpf_reg_state, var_off) - sizeof(reg->type));
	reg->id = 0;
	reg->parent_id = 0;
	reg->map_uid = 0;
	___mark_reg_known(reg, imm);
}

static void __mark_reg32_known(struct bpf_reg_state *reg, u64 imm)
{
	reg->var_off = tnum_const_subreg(reg->var_off, imm);
	reg->r32 = cnum32_from_urange((u32)imm, (u32)imm);
}

static void __mark_reg32_unbounded(struct bpf_reg_state *reg)
{
	reg->r32 = CNUM32_UNBOUNDED;
}

static void __mark_reg64_unbounded(struct bpf_reg_state *reg)
{
	reg->r64 = CNUM64_UNBOUNDED;
}

/* Reset the min/max bounds of a register */
static void __mark_reg_unbounded(struct bpf_reg_state *reg)
{
	__mark_reg64_unbounded(reg);
	__mark_reg32_unbounded(reg);
}

static void reset_reg64_and_tnum(struct bpf_reg_state *reg)
{
	__mark_reg64_unbounded(reg);
	reg->var_off = tnum_unknown;
}

static void reset_reg32_and_tnum(struct bpf_reg_state *reg)
{
	__mark_reg32_unbounded(reg);
	reg->var_off = tnum_unknown;
}

static struct cnum32 cnum32_from_tnum(struct tnum tnum)
{
	tnum = tnum_subreg(tnum);
	if ((tnum.mask & S32_MIN) || (tnum.value & S32_MIN))
		/* min signed is max(sign bit) | min(other bits) */
		/* max signed is min(sign bit) | max(other bits) */
		return cnum32_from_srange(tnum.value | (tnum.mask & S32_MIN),
					  tnum.value | (tnum.mask & S32_MAX));
	else
		return cnum32_from_urange(tnum.value, (tnum.value | tnum.mask));
}

static struct cnum64 cnum64_from_tnum(struct tnum tnum)
{
	if ((tnum.mask & S64_MIN) || (tnum.value & S64_MIN))
		/* min signed is max(sign bit) | min(other bits) */
		/* max signed is min(sign bit) | max(other bits) */
		return cnum64_from_srange(tnum.value | (tnum.mask & S64_MIN),
					  tnum.value | (tnum.mask & S64_MAX));
	else
		return cnum64_from_urange(tnum.value, (tnum.value | tnum.mask));
}

static void __update_reg32_bounds(struct bpf_reg_state *reg)
{
	cnum32_intersect_with(&reg->r32, cnum32_from_tnum(reg->var_off));
}

static void __update_reg64_bounds(struct bpf_reg_state *reg)
{
	u64 tnum_next, tmax;
	bool umin_in_tnum;

	cnum64_intersect_with(&reg->r64, cnum64_from_tnum(reg->var_off));

	/* Check if u64 and tnum overlap in a single value */
	tnum_next = tnum_step(reg->var_off, reg_umin(reg));
	umin_in_tnum = (reg_umin(reg) & ~reg->var_off.mask) == reg->var_off.value;
	tmax = reg->var_off.value | reg->var_off.mask;
	if (umin_in_tnum && tnum_next > reg_umax(reg)) {
		/* The u64 range and the tnum only overlap in umin.
		 * u64:  ---[xxxxxx]-----
		 * tnum: --xx----------x-
		 */
		___mark_reg_known(reg, reg_umin(reg));
	} else if (!umin_in_tnum && tnum_next == tmax) {
		/* The u64 range and the tnum only overlap in the maximum value
		 * represented by the tnum, called tmax.
		 * u64:  ---[xxxxxx]-----
		 * tnum: xx-----x--------
		 */
		___mark_reg_known(reg, tmax);
	} else if (!umin_in_tnum && tnum_next <= reg_umax(reg) &&
		   tnum_step(reg->var_off, tnum_next) > reg_umax(reg)) {
		/* The u64 range and the tnum only overlap in between umin
		 * (excluded) and umax.
		 * u64:  ---[xxxxxx]-----
		 * tnum: xx----x-------x-
		 */
		___mark_reg_known(reg, tnum_next);
	}
}

static void __update_reg_bounds(struct bpf_reg_state *reg)
{
	__update_reg32_bounds(reg);
	__update_reg64_bounds(reg);
}

static void deduce_bounds_32_from_64(struct bpf_reg_state *reg)
{
	cnum32_intersect_with(&reg->r32, cnum32_from_cnum64(reg->r64));
}

static void deduce_bounds_64_from_32(struct bpf_reg_state *reg)
{
	reg->r64 = cnum64_cnum32_intersect(reg->r64, reg->r32);
}

static void __reg_deduce_bounds(struct bpf_reg_state *reg)
{
	deduce_bounds_32_from_64(reg);
	deduce_bounds_64_from_32(reg);
}

/* Attempts to improve var_off based on unsigned min/max information */
static void __reg_bound_offset(struct bpf_reg_state *reg)
{
	struct tnum var64_off = tnum_intersect(reg->var_off,
					       tnum_range(reg_umin(reg),
							  reg_umax(reg)));
	struct tnum var32_off = tnum_intersect(tnum_subreg(var64_off),
					       tnum_range(reg_u32_min(reg),
							  reg_u32_max(reg)));
	u32 trailing_zero_bits;
	u16 base = reg->base;
	u16 step = reg->step;

	reg->var_off = tnum_or(tnum_clear_subreg(var64_off), var32_off);

	if (base == 0)
		trailing_zero_bits = count_trailing_zeros(step);
	else
		trailing_zero_bits = min(count_trailing_zeros(base),
					 count_trailing_zeros(step));
	reg->var_off = tnum_and(reg->var_off, tnum_const(~0ULL << trailing_zero_bits));
}

static void __update_bounds_from_step(struct bpf_reg_state *reg)
{
	reg->r64 = cnum64_intersect_linear(reg->r64, reg->base, reg->step);
	deduce_bounds_32_from_64(reg);
}

static void reg_bounds_sync(struct bpf_reg_state *reg)
{
	/* If the input reg_state is invalid, we can exit early */
	if (range_bounds_violation(reg))
		return;
	/* We might have learned new bounds from the var_off. */
	__update_reg_bounds(reg);
	/* We might have learned something about the sign bit. */
	__reg_deduce_bounds(reg);
	__reg_deduce_bounds(reg);
	/* We might have learned some bits from the bounds. */
	__reg_bound_offset(reg);
	/* Intersecting with the old var_off might have improved our bounds
	 * slightly, e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),
	 * then new var_off is (0; 0x7f...fc) which improves our umax.
	 */
	__update_reg_bounds(reg);
	/*
	 * Both tnum and base+step define a sequence of points,
	 * potentially w/o intersection, or intersecting after N
	 * tnum_step()'s, where N can be large. On the other hand,
	 * step+base *must* be in sync with r64 in order for
	 * array traversal logic starting at reg_smin() to be sound.
	 * Hence, place this as a final step in the reg_bounds_sync().
	 */
	__update_bounds_from_step(reg);
}

static bool const_tnum_range_mismatch(struct bpf_reg_state *reg)
{
	if (!tnum_is_const(reg->var_off))
		return false;

	return !cnum64_is_const(reg->r64) || reg->r64.base != reg->var_off.value;
}

static bool const_tnum_range_mismatch_32(struct bpf_reg_state *reg)
{
	if (!tnum_subreg_is_const(reg->var_off))
		return false;

	return !cnum32_is_const(reg->r32) || reg->r32.base != tnum_subreg(reg->var_off).value;
}

static bool range_bounds_violation(struct bpf_reg_state *reg)
{
	return cnum32_is_empty(reg->r32) || cnum64_is_empty(reg->r64);
}

/* BPF architecture zero extends alu32 ops into 64-bit registesr */
static void zext_32_to_64(struct bpf_reg_state *reg)
{
	reg_step_check_unsigned(reg, 32);
	reg->var_off = tnum_subreg(reg->var_off);
	reg_set_urange64(reg, reg_u32_min(reg), reg_u32_max(reg));
}

/* truncate register to smaller size (in bytes)
 * must be called with size < BPF_REG_SIZE
 */
static void coerce_reg_to_size(struct bpf_reg_state *reg, int size)
{
	u64 mask = (1ULL << (size * 8)) - 1;

	reg_step_check_unsigned(reg, size * 8);

	/* clear high bits in bit representation */
	reg->var_off = tnum_cast(reg->var_off, size);

	/* fix arithmetic bounds */
	if ((reg_umin(reg) & ~mask) == (reg_umax(reg) & ~mask))
		reg_set_urange64(reg, reg_umin(reg) & mask, reg_umax(reg) & mask);
	else
		reg_set_urange64(reg, 0, mask);

	/* If size is smaller than 32bit register the 32bit register
	 * values are also truncated so we push 64-bit bounds into
	 * 32-bit bounds. Above were truncated < 32-bits already.
	 */
	if (size < 4)
		__mark_reg32_unbounded(reg);

	reg_bounds_sync(reg);
}

static void scalar_step_mul(struct bpf_reg_state *dst_reg, struct bpf_reg_state *src_reg)
{
	if (tnum_is_const(src_reg->var_off))
		scalar_step_scale(dst_reg, src_reg->var_off.value);
	else
		reg_step_reset(dst_reg);
}

static void scalar_step_lsh(struct bpf_reg_state *dst_reg, struct bpf_reg_state *src_reg)
{
	u64 amount = src_reg->var_off.value;

	if (tnum_is_const(src_reg->var_off) && amount < 64)
		scalar_step_scale(dst_reg, 1ULL << amount);
	else
		reg_step_reset(dst_reg);
}

static void scalar32_min_max_add(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	dst_reg->r32 = cnum32_add(dst_reg->r32, src_reg->r32);
}

static void scalar_min_max_add(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	dst_reg->r64 = cnum64_add(dst_reg->r64, src_reg->r64);
}

static void scalar32_min_max_sub(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	dst_reg->r32 = cnum32_add(dst_reg->r32, cnum32_negate(src_reg->r32));
}

static void scalar_min_max_sub(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	dst_reg->r64 = cnum64_add(dst_reg->r64, cnum64_negate(src_reg->r64));
}

static void scalar32_min_max_mul(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	s32 smin = reg_s32_min(dst_reg);
	s32 smax = reg_s32_max(dst_reg);
	u32 umin = reg_u32_min(dst_reg);
	u32 umax = reg_u32_max(dst_reg);
	s32 tmp_prod[4];

	if (check_mul_overflow(umax, reg_u32_max(src_reg), &umax) ||
	    check_mul_overflow(umin, reg_u32_min(src_reg), &umin)) {
		/* Overflow possible, we know nothing */
		umin = 0;
		umax = U32_MAX;
	}
	if (check_mul_overflow(smin, reg_s32_min(src_reg), &tmp_prod[0]) ||
	    check_mul_overflow(smin, reg_s32_max(src_reg), &tmp_prod[1]) ||
	    check_mul_overflow(smax, reg_s32_min(src_reg), &tmp_prod[2]) ||
	    check_mul_overflow(smax, reg_s32_max(src_reg), &tmp_prod[3])) {
		/* Overflow possible, we know nothing */
		smin = S32_MIN;
		smax = S32_MAX;
	} else {
		smin = min_array(tmp_prod, 4);
		smax = max_array(tmp_prod, 4);
	}

	dst_reg->r32 = cnum32_intersect(cnum32_from_urange(umin, umax),
					cnum32_from_srange(smin, smax));
}

static void scalar_min_max_mul(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	s64 smin = reg_smin(dst_reg);
	s64 smax = reg_smax(dst_reg);
	u64 umin = reg_umin(dst_reg);
	u64 umax = reg_umax(dst_reg);
	s64 tmp_prod[4];

	if (check_mul_overflow(umax, reg_umax(src_reg), &umax) ||
	    check_mul_overflow(umin, reg_umin(src_reg), &umin)) {
		/* Overflow possible, we know nothing */
		umin = 0;
		umax = U64_MAX;
	}
	if (check_mul_overflow(smin, reg_smin(src_reg), &tmp_prod[0]) ||
	    check_mul_overflow(smin, reg_smax(src_reg), &tmp_prod[1]) ||
	    check_mul_overflow(smax, reg_smin(src_reg), &tmp_prod[2]) ||
	    check_mul_overflow(smax, reg_smax(src_reg), &tmp_prod[3])) {
		/* Overflow possible, we know nothing */
		smin = S64_MIN;
		smax = S64_MAX;
	} else {
		smin = min_array(tmp_prod, 4);
		smax = max_array(tmp_prod, 4);
	}

	dst_reg->r64 = cnum64_intersect(cnum64_from_urange(umin, umax),
					cnum64_from_srange(smin, smax));
}

static void scalar32_min_max_udiv(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	u32 src_val = reg_u32_min(src_reg); /* non-zero, const divisor */

	reg_set_urange32(dst_reg, reg_u32_min(dst_reg) / src_val,
			 reg_u32_max(dst_reg) / src_val);

	/* Reset other ranges/tnum to unbounded/unknown. */
	reset_reg64_and_tnum(dst_reg);
}

static void scalar_min_max_udiv(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	u64 src_val = reg_umin(src_reg); /* non-zero, const divisor */

	reg_set_urange64(dst_reg, div64_u64(reg_umin(dst_reg), src_val),
			 div64_u64(reg_umax(dst_reg), src_val));

	/* Reset other ranges/tnum to unbounded/unknown. */
	reset_reg32_and_tnum(dst_reg);
}

static void scalar32_min_max_sdiv(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	s32 smin = reg_s32_min(dst_reg);
	s32 smax = reg_s32_max(dst_reg);
	s32 src_val = reg_s32_min(src_reg); /* non-zero, const divisor */
	s32 res1, res2;

	/* BPF div specification: S32_MIN / -1 = S32_MIN */
	if (smin == S32_MIN && src_val == -1) {
		/*
		 * If the dividend range contains more than just S32_MIN,
		 * we cannot precisely track the result, so it becomes unbounded.
		 * e.g., [S32_MIN, S32_MIN+10]/(-1),
		 *     = {S32_MIN} U [-(S32_MIN+10), -(S32_MIN+1)]
		 *     = {S32_MIN} U [S32_MAX-9, S32_MAX] = [S32_MIN, S32_MAX]
		 * Otherwise (if dividend is exactly S32_MIN), result remains S32_MIN.
		 */
		if (smax != S32_MIN) {
			smin = S32_MIN;
			smax = S32_MAX;
		}
		goto reset;
	}

	res1 = smin / src_val;
	res2 = smax / src_val;
	smin = min(res1, res2);
	smax = max(res1, res2);

reset:
	reg_set_srange32(dst_reg, smin, smax);
	/* Reset other ranges/tnum to unbounded/unknown. */
	reset_reg64_and_tnum(dst_reg);
}

static void scalar_min_max_sdiv(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	s64 smin = reg_smin(dst_reg);
	s64 smax = reg_smax(dst_reg);
	s64 src_val = reg_smin(src_reg); /* non-zero, const divisor */
	s64 res1, res2;

	/* BPF div specification: S64_MIN / -1 = S64_MIN */
	if (smin == S64_MIN && src_val == -1) {
		/*
		 * If the dividend range contains more than just S64_MIN,
		 * we cannot precisely track the result, so it becomes unbounded.
		 * e.g., [S64_MIN, S64_MIN+10]/(-1),
		 *     = {S64_MIN} U [-(S64_MIN+10), -(S64_MIN+1)]
		 *     = {S64_MIN} U [S64_MAX-9, S64_MAX] = [S64_MIN, S64_MAX]
		 * Otherwise (if dividend is exactly S64_MIN), result remains S64_MIN.
		 */
		if (smax != S64_MIN) {
			smin = S64_MIN;
			smax = S64_MAX;
		}
		goto reset;
	}

	res1 = div64_s64(smin, src_val);
	res2 = div64_s64(smax, src_val);
	smin = min(res1, res2);
	smax = max(res1, res2);

reset:
	reg_set_srange64(dst_reg, smin, smax);
	/* Reset other ranges/tnum to unbounded/unknown. */
	reset_reg32_and_tnum(dst_reg);
}

static void scalar32_min_max_umod(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	u32 src_val = reg_u32_min(src_reg); /* non-zero, const divisor */
	u32 res_max = src_val - 1;

	/*
	 * If dst_umax <= res_max, the result remains unchanged.
	 * e.g., [2, 5] % 10 = [2, 5].
	 */
	if (reg_u32_max(dst_reg) <= res_max)
		return;

	reg_set_urange32(dst_reg, 0, min(reg_u32_max(dst_reg), res_max));

	/* Reset other ranges/tnum to unbounded/unknown. */
	reset_reg64_and_tnum(dst_reg);
}

static void scalar_min_max_umod(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	u64 src_val = reg_umin(src_reg); /* non-zero, const divisor */
	u64 res_max = src_val - 1;

	/*
	 * If dst_umax <= res_max, the result remains unchanged.
	 * e.g., [2, 5] % 10 = [2, 5].
	 */
	if (reg_umax(dst_reg) <= res_max)
		return;

	reg_set_urange64(dst_reg, 0, min(reg_umax(dst_reg), res_max));

	/* Reset other ranges/tnum to unbounded/unknown. */
	reset_reg32_and_tnum(dst_reg);
}

static void scalar32_min_max_smod(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	s32 src_val = reg_s32_min(src_reg); /* non-zero, const divisor */

	/*
	 * Safe absolute value calculation:
	 * If src_val == S32_MIN (-2147483648), src_abs becomes 2147483648.
	 * Here use unsigned integer to avoid overflow.
	 */
	u32 src_abs = (src_val > 0) ? (u32)src_val : -(u32)src_val;

	/*
	 * Calculate the maximum possible absolute value of the result.
	 * Even if src_abs is 2147483648 (S32_MIN), subtracting 1 gives
	 * 2147483647 (S32_MAX), which fits perfectly in s32.
	 */
	s32 res_max_abs = src_abs - 1;

	/*
	 * If the dividend is already within the result range,
	 * the result remains unchanged. e.g., [-2, 5] % 10 = [-2, 5].
	 */
	if (reg_s32_min(dst_reg) >= -res_max_abs && reg_s32_max(dst_reg) <= res_max_abs)
		return;

	/* General case: result has the same sign as the dividend. */
	if (reg_s32_min(dst_reg) >= 0) {
		reg_set_srange32(dst_reg, 0, min(reg_s32_max(dst_reg), res_max_abs));
	} else if (reg_s32_max(dst_reg) <= 0) {
		reg_set_srange32(dst_reg, max(reg_s32_min(dst_reg), -res_max_abs), 0);
	} else {
		reg_set_srange32(dst_reg, -res_max_abs, res_max_abs);
	}

	/* Reset other ranges/tnum to unbounded/unknown. */
	reset_reg64_and_tnum(dst_reg);
}

static void scalar_min_max_smod(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	s64 src_val = reg_smin(src_reg); /* non-zero, const divisor */

	/*
	 * Safe absolute value calculation:
	 * If src_val == S64_MIN (-2^63), src_abs becomes 2^63.
	 * Here use unsigned integer to avoid overflow.
	 */
	u64 src_abs = (src_val > 0) ? (u64)src_val : -(u64)src_val;

	/*
	 * Calculate the maximum possible absolute value of the result.
	 * Even if src_abs is 2^63 (S64_MIN), subtracting 1 gives
	 * 2^63 - 1 (S64_MAX), which fits perfectly in s64.
	 */
	s64 res_max_abs = src_abs - 1;

	/*
	 * If the dividend is already within the result range,
	 * the result remains unchanged. e.g., [-2, 5] % 10 = [-2, 5].
	 */
	if (reg_smin(dst_reg) >= -res_max_abs && reg_smax(dst_reg) <= res_max_abs)
		return;

	/* General case: result has the same sign as the dividend. */
	if (reg_smin(dst_reg) >= 0) {
		reg_set_srange64(dst_reg, 0, min(reg_smax(dst_reg), res_max_abs));
	} else if (reg_smax(dst_reg) <= 0) {
		reg_set_srange64(dst_reg, max(reg_smin(dst_reg), -res_max_abs), 0);
	} else {
		reg_set_srange64(dst_reg, -res_max_abs, res_max_abs);
	}

	/* Reset other ranges/tnum to unbounded/unknown. */
	reset_reg32_and_tnum(dst_reg);
}

static void scalar32_min_max_and(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_subreg_is_const(src_reg->var_off);
	bool dst_known = tnum_subreg_is_const(dst_reg->var_off);
	struct tnum var32_off = tnum_subreg(dst_reg->var_off);
	u32 umax_val = reg_u32_max(src_reg);

	if (src_known && dst_known) {
		__mark_reg32_known(dst_reg, var32_off.value);
		return;
	}

	/* We get our minimum from the var_off, since that's inherently
	 * bitwise.  Our maximum is the minimum of the operands' maxima.
	 */
	reg_set_urange32(dst_reg,
			 var32_off.value,
			 min(reg_u32_max(dst_reg), umax_val));
}

static void scalar_min_max_and(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_is_const(src_reg->var_off);
	bool dst_known = tnum_is_const(dst_reg->var_off);
	u64 umax_val = reg_umax(src_reg);

	if (src_known && dst_known) {
		__mark_reg_known(dst_reg, dst_reg->var_off.value);
		return;
	}

	/* We get our minimum from the var_off, since that's inherently
	 * bitwise.  Our maximum is the minimum of the operands' maxima.
	 */
	reg_set_urange64(dst_reg,
			 dst_reg->var_off.value,
			 min(reg_umax(dst_reg), umax_val));

	/* We may learn something more from the var_off */
	__update_reg_bounds(dst_reg);
}

static void scalar32_min_max_or(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_subreg_is_const(src_reg->var_off);
	bool dst_known = tnum_subreg_is_const(dst_reg->var_off);
	struct tnum var32_off = tnum_subreg(dst_reg->var_off);
	u32 umin_val = reg_u32_min(src_reg);

	if (src_known && dst_known) {
		__mark_reg32_known(dst_reg, var32_off.value);
		return;
	}

	/* We get our maximum from the var_off, and our minimum is the
	 * maximum of the operands' minima
	 */
	reg_set_urange32(dst_reg,
			 max(reg_u32_min(dst_reg), umin_val),
			 var32_off.value | var32_off.mask);
}

static void scalar_min_max_or(struct bpf_reg_state *dst_reg,
			      struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_is_const(src_reg->var_off);
	bool dst_known = tnum_is_const(dst_reg->var_off);
	u64 umin_val = reg_umin(src_reg);

	if (src_known && dst_known) {
		__mark_reg_known(dst_reg, dst_reg->var_off.value);
		return;
	}

	/* We get our maximum from the var_off, and our minimum is the
	 * maximum of the operands' minima
	 */
	reg_set_urange64(dst_reg,
			 max(reg_umin(dst_reg), umin_val),
			 dst_reg->var_off.value | dst_reg->var_off.mask);

	/* We may learn something more from the var_off */
	__update_reg_bounds(dst_reg);
}

static void scalar32_min_max_xor(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_subreg_is_const(src_reg->var_off);
	bool dst_known = tnum_subreg_is_const(dst_reg->var_off);
	struct tnum var32_off = tnum_subreg(dst_reg->var_off);

	if (src_known && dst_known) {
		__mark_reg32_known(dst_reg, var32_off.value);
		return;
	}

	/* We get both minimum and maximum from the var32_off. */
	reg_set_urange32(dst_reg, var32_off.value, var32_off.value | var32_off.mask);
}

static void scalar_min_max_xor(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_is_const(src_reg->var_off);
	bool dst_known = tnum_is_const(dst_reg->var_off);

	if (src_known && dst_known) {
		/* dst_reg->var_off.value has been updated earlier */
		__mark_reg_known(dst_reg, dst_reg->var_off.value);
		return;
	}

	/* We get both minimum and maximum from the var_off. */
	reg_set_urange64(dst_reg,
			 dst_reg->var_off.value,
			 dst_reg->var_off.value | dst_reg->var_off.mask);
}

static void __scalar32_min_max_lsh(struct bpf_reg_state *dst_reg,
				   u64 umin_val, u64 umax_val)
{
	/* If we might shift our top bit out, then we know nothing */
	if (umax_val > 31 || reg_u32_max(dst_reg) > 1ULL << (31 - umax_val))
		reg_set_urange32(dst_reg, 0, U32_MAX);
	else
		/* We lose all sign bit information (except what we can pick
		 * up from var_off)
		 */
		reg_set_urange32(dst_reg, reg_u32_min(dst_reg) << umin_val,
				 reg_u32_max(dst_reg) << umax_val);
}

static void scalar32_min_max_lsh(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	u32 umax_val = reg_u32_max(src_reg);
	u32 umin_val = reg_u32_min(src_reg);
	/* u32 alu operation will zext upper bits */
	struct tnum subreg = tnum_subreg(dst_reg->var_off);

	__scalar32_min_max_lsh(dst_reg, umin_val, umax_val);
	dst_reg->var_off = tnum_subreg(tnum_lshift(subreg, umin_val));
	/* Not required but being careful mark reg64 bounds as unknown so
	 * that we are forced to pick them up from tnum and zext later and
	 * if some path skips this step we are still safe.
	 */
	__mark_reg64_unbounded(dst_reg);
	__update_reg32_bounds(dst_reg);
}

static void __scalar64_min_max_lsh(struct bpf_reg_state *dst_reg,
				   u64 umin_val, u64 umax_val)
{
	struct cnum64 u, s;

	/* Special case <<32 because it is a common compiler pattern to sign
	 * extend subreg by doing <<32 s>>32. smin/smax assignments are correct
	 * because s32 bounds don't flip sign when shifting to the left by
	 * 32bits.
	 */
	if (umin_val == 32 && umax_val == 32)
		s = cnum64_from_srange((s64)reg_s32_min(dst_reg) << 32,
				       (s64)reg_s32_max(dst_reg) << 32);
	else
		s = CNUM64_UNBOUNDED;

	/* If we might shift our top bit out, then we know nothing */
	if (reg_umax(dst_reg) > 1ULL << (63 - umax_val))
		u = CNUM64_UNBOUNDED;
	else
		u = cnum64_from_urange(reg_umin(dst_reg) << umin_val,
				       reg_umax(dst_reg) << umax_val);

	dst_reg->r64 = cnum64_intersect(u, s);
}

static void scalar_min_max_lsh(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	u64 umax_val = reg_umax(src_reg);
	u64 umin_val = reg_umin(src_reg);

	/* scalar64 calc uses 32bit unshifted bounds so must be called first */
	__scalar64_min_max_lsh(dst_reg, umin_val, umax_val);
	__scalar32_min_max_lsh(dst_reg, umin_val, umax_val);

	dst_reg->var_off = tnum_lshift(dst_reg->var_off, umin_val);
	/* We may learn something more from the var_off */
	__update_reg_bounds(dst_reg);
}

static void scalar32_min_max_rsh(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	struct tnum subreg = tnum_subreg(dst_reg->var_off);
	u32 umax_val = reg_u32_max(src_reg);
	u32 umin_val = reg_u32_min(src_reg);

	/* BPF_RSH is an unsigned shift.  If the value in dst_reg might
	 * be negative, then either:
	 * 1) src_reg might be zero, so the sign bit of the result is
	 *    unknown, so we lose our signed bounds
	 * 2) it's known negative, thus the unsigned bounds capture the
	 *    signed bounds
	 * 3) the signed bounds cross zero, so they tell us nothing
	 *    about the result
	 * If the value in dst_reg is known nonnegative, then again the
	 * unsigned bounds capture the signed bounds.
	 * Thus, in all cases it suffices to blow away our signed bounds
	 * and rely on inferring new ones from the unsigned bounds and
	 * var_off of the result.
	 */

	dst_reg->var_off = tnum_rshift(subreg, umin_val);
	reg_set_urange32(dst_reg, reg_u32_min(dst_reg) >> umax_val,
			 reg_u32_max(dst_reg) >> umin_val);

	__mark_reg64_unbounded(dst_reg);
	__update_reg32_bounds(dst_reg);
}

static void scalar_min_max_rsh(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	u64 umax_val = reg_umax(src_reg);
	u64 umin_val = reg_umin(src_reg);

	/* BPF_RSH is an unsigned shift.  If the value in dst_reg might
	 * be negative, then either:
	 * 1) src_reg might be zero, so the sign bit of the result is
	 *    unknown, so we lose our signed bounds
	 * 2) it's known negative, thus the unsigned bounds capture the
	 *    signed bounds
	 * 3) the signed bounds cross zero, so they tell us nothing
	 *    about the result
	 * If the value in dst_reg is known nonnegative, then again the
	 * unsigned bounds capture the signed bounds.
	 * Thus, in all cases it suffices to blow away our signed bounds
	 * and rely on inferring new ones from the unsigned bounds and
	 * var_off of the result.
	 */
	dst_reg->var_off = tnum_rshift(dst_reg->var_off, umin_val);
	reg_set_urange64(dst_reg, reg_umin(dst_reg) >> umax_val,
			 reg_umax(dst_reg) >> umin_val);

	/* Its not easy to operate on alu32 bounds here because it depends
	 * on bits being shifted in. Take easy way out and mark unbounded
	 * so we can recalculate later from tnum.
	 */
	__mark_reg32_unbounded(dst_reg);
	__update_reg_bounds(dst_reg);
}

static void scalar32_min_max_arsh(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	u64 umin_val = reg_u32_min(src_reg);

	/* Upon reaching here, src_known is true and
	 * umax_val is equal to umin_val.
	 * Blow away the dst_reg umin_value/umax_value and rely on
	 * dst_reg var_off to refine the result.
	 */
	reg_set_srange32(dst_reg,
			 (u32)(((s32)reg_s32_min(dst_reg)) >> umin_val),
			 (u32)(((s32)reg_s32_max(dst_reg)) >> umin_val));

	dst_reg->var_off = tnum_arshift(tnum_subreg(dst_reg->var_off), umin_val, 32);

	__mark_reg64_unbounded(dst_reg);
	__update_reg32_bounds(dst_reg);
}

static void scalar_min_max_arsh(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	u64 umin_val = reg_umin(src_reg);

	/* Upon reaching here, src_known is true and umax_val is equal
	 * to umin_val.
	 */
	reg_set_srange64(dst_reg, reg_smin(dst_reg) >> umin_val,
			 reg_smax(dst_reg) >> umin_val);

	dst_reg->var_off = tnum_arshift(dst_reg->var_off, umin_val, 64);

	/* Its not easy to operate on alu32 bounds here because it depends
	 * on bits being shifted in from upper 32-bits. Take easy way out
	 * and mark unbounded so we can recalculate later from tnum.
	 */
	__mark_reg32_unbounded(dst_reg);
	__update_reg_bounds(dst_reg);
}
