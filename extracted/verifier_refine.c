/* Extracted verbatim from kernel/bpf/verifier.c
 * lines 3747-3752, 3754-3758, 18109-18128, 18226-18249, 18251-18388
 * commit 4f842631f178f41baa2d2d444a277d54c07666a1
 * by harness/extract.py; do not edit. */
/* check if register is a constant scalar value */
static bool is_reg_const(struct bpf_reg_state *reg, bool subreg32)
{
	return reg->type == SCALAR_VALUE &&
	       tnum_is_const(subreg32 ? tnum_subreg(reg->var_off) : reg->var_off);
}

/* assuming is_reg_const() is true, return constant value of a register */
static u64 reg_const_value(struct bpf_reg_state *reg, bool subreg32)
{
	return subreg32 ? tnum_subreg(reg->var_off).value : reg->var_off.value;
}

int bpf_flip_opcode(u32 opcode)
{
	/* How can we transform "a <op> b" into "b <op> a"? */
	static const u8 opcode_flip[16] = {
		/* these stay the same */
		[BPF_JEQ  >> 4] = BPF_JEQ,
		[BPF_JNE  >> 4] = BPF_JNE,
		[BPF_JSET >> 4] = BPF_JSET,
		/* these swap "lesser" and "greater" (L and G in the opcodes) */
		[BPF_JGE  >> 4] = BPF_JLE,
		[BPF_JGT  >> 4] = BPF_JLT,
		[BPF_JLE  >> 4] = BPF_JGE,
		[BPF_JLT  >> 4] = BPF_JGT,
		[BPF_JSGE >> 4] = BPF_JSLE,
		[BPF_JSGT >> 4] = BPF_JSLT,
		[BPF_JSLE >> 4] = BPF_JSGE,
		[BPF_JSLT >> 4] = BPF_JSGT
	};
	return opcode_flip[opcode >> 4];
}

/* Opcode that corresponds to a *false* branch condition.
 * E.g., if r1 < r2, then reverse (false) condition is r1 >= r2
 */
u8 bpf_rev_opcode(u8 opcode)
{
	switch (opcode) {
	case BPF_JEQ:		return BPF_JNE;
	case BPF_JNE:		return BPF_JEQ;
	/* JSET doesn't have it's reverse opcode in BPF, so add
	 * BPF_X flag to denote the reverse of that operation
	 */
	case BPF_JSET:		return BPF_JSET | BPF_X;
	case BPF_JSET | BPF_X:	return BPF_JSET;
	case BPF_JGE:		return BPF_JLT;
	case BPF_JGT:		return BPF_JLE;
	case BPF_JLE:		return BPF_JGT;
	case BPF_JLT:		return BPF_JGE;
	case BPF_JSGE:		return BPF_JSLT;
	case BPF_JSGT:		return BPF_JSLE;
	case BPF_JSLE:		return BPF_JSGT;
	case BPF_JSLT:		return BPF_JSGE;
	default:		return 0;
	}
}

/* Refine range knowledge for <reg1> <op> <reg>2 conditional operation. */
static void regs_refine_cond_op(struct bpf_reg_state *reg1, struct bpf_reg_state *reg2,
				u8 opcode, bool is_jmp32)
{
	struct tnum t;
	u64 val;

	/* In case of GE/GT/SGE/JST, reuse LE/LT/SLE/SLT logic from below */
	switch (opcode) {
	case BPF_JGE:
	case BPF_JGT:
	case BPF_JSGE:
	case BPF_JSGT:
		opcode = bpf_flip_opcode(opcode);
		swap(reg1, reg2);
		break;
	default:
		break;
	}

	switch (opcode) {
	case BPF_JEQ:
		if (is_jmp32) {
			reg1->r32 = cnum32_intersect(reg1->r32, reg2->r32);
			reg2->r32 = reg1->r32;

			t = tnum_intersect(tnum_subreg(reg1->var_off), tnum_subreg(reg2->var_off));
			reg1->var_off = tnum_with_subreg(reg1->var_off, t);
			reg2->var_off = tnum_with_subreg(reg2->var_off, t);
		} else {
			reg1->r64 = cnum64_intersect(reg1->r64, reg2->r64);
			reg2->r64 = reg1->r64;

			reg1->var_off = tnum_intersect(reg1->var_off, reg2->var_off);
			reg2->var_off = reg1->var_off;
		}
		break;
	case BPF_JNE:
		if (!is_reg_const(reg2, is_jmp32))
			swap(reg1, reg2);
		if (!is_reg_const(reg2, is_jmp32))
			break;

		/* try to recompute the bound of reg1 if reg2 is a const and
		 * is exactly the edge of reg1.
		 */
		val = reg_const_value(reg2, is_jmp32);
		if (is_jmp32) {
			/* Complement of the range [val, val] as cnum32. */
			cnum32_intersect_with(&reg1->r32, (struct cnum32){ val + 1, U32_MAX - 1 });
		} else {
			/* Complement of the range [val, val] as cnum64. */
			cnum64_intersect_with(&reg1->r64, (struct cnum64){ val + 1, U64_MAX - 1 });
		}
		break;
	case BPF_JSET:
		if (!is_reg_const(reg2, is_jmp32))
			swap(reg1, reg2);
		if (!is_reg_const(reg2, is_jmp32))
			break;
		val = reg_const_value(reg2, is_jmp32);
		/* BPF_JSET (i.e., TRUE branch, *not* BPF_JSET | BPF_X)
		 * requires single bit to learn something useful. E.g., if we
		 * know that `r1 & 0x3` is true, then which bits (0, 1, or both)
		 * are actually set? We can learn something definite only if
		 * it's a single-bit value to begin with.
		 *
		 * BPF_JSET | BPF_X (i.e., negation of BPF_JSET) doesn't have
		 * this restriction. I.e., !(r1 & 0x3) means neither bit 0 nor
		 * bit 1 is set, which we can readily use in adjustments.
		 */
		if (hweight64(val) != 1)
			break;
		if (is_jmp32) {
			t = tnum_or(tnum_subreg(reg1->var_off), tnum_const(val));
			reg1->var_off = tnum_with_subreg(reg1->var_off, t);
		} else {
			reg1->var_off = tnum_or(reg1->var_off, tnum_const(val));
		}
		break;
	case BPF_JSET | BPF_X: /* reverse of BPF_JSET, see bpf_rev_opcode() */
		if (!is_reg_const(reg2, is_jmp32))
			swap(reg1, reg2);
		if (!is_reg_const(reg2, is_jmp32))
			break;
		val = reg_const_value(reg2, is_jmp32);
		/* Forget the ranges before narrowing tnums, to avoid invariant
		 * violations if we're on a dead branch.
		 */
		__mark_reg_unbounded(reg1);
		reg_step_reset(reg1);
		if (is_jmp32) {
			t = tnum_and(tnum_subreg(reg1->var_off), tnum_const(~val));
			reg1->var_off = tnum_with_subreg(reg1->var_off, t);
		} else {
			reg1->var_off = tnum_and(reg1->var_off, tnum_const(~val));
		}
		break;
	case BPF_JLE:
		if (is_jmp32) {
			cnum32_intersect_with_urange(&reg1->r32, 0, reg_u32_max(reg2));
			cnum32_intersect_with_urange(&reg2->r32, reg_u32_min(reg1), U32_MAX);
		} else {
			cnum64_intersect_with_urange(&reg1->r64, 0, reg_umax(reg2));
			cnum64_intersect_with_urange(&reg2->r64, reg_umin(reg1), U64_MAX);
		}
		break;
	case BPF_JLT:
		if (is_jmp32) {
			cnum32_intersect_with_urange(&reg1->r32, 0, reg_u32_max(reg2) - 1);
			cnum32_intersect_with_urange(&reg2->r32, reg_u32_min(reg1) + 1, U32_MAX);
		} else {
			cnum64_intersect_with_urange(&reg1->r64, 0, reg_umax(reg2) - 1);
			cnum64_intersect_with_urange(&reg2->r64, reg_umin(reg1) + 1, U64_MAX);
		}
		break;
	case BPF_JSLE:
		if (is_jmp32) {
			cnum32_intersect_with_srange(&reg1->r32, S32_MIN, reg_s32_max(reg2));
			cnum32_intersect_with_srange(&reg2->r32, reg_s32_min(reg1), S32_MAX);
		} else {
			cnum64_intersect_with_srange(&reg1->r64, S64_MIN, reg_smax(reg2));
			cnum64_intersect_with_srange(&reg2->r64, reg_smin(reg1), S64_MAX);
		}
		break;
	case BPF_JSLT:
		if (is_jmp32) {
			cnum32_intersect_with_srange(&reg1->r32, S32_MIN, reg_s32_max(reg2) - 1);
			cnum32_intersect_with_srange(&reg2->r32, reg_s32_min(reg1) + 1, S32_MAX);
		} else {
			cnum64_intersect_with_srange(&reg1->r64, S64_MIN, reg_smax(reg2) - 1);
			cnum64_intersect_with_srange(&reg2->r64, reg_smin(reg1) + 1, S64_MAX);
		}
		break;
	default:
		return;
	}
}
