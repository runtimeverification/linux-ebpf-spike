/* Extracted verbatim from include/linux/bpf_verifier.h
 * lines 14-25, 192-195, 197-200, 202-205, 207-210, 212-215, 217-220, 222-225, 227-230, 232-235, 237-240, 242-245, 247-250
 * commit 4f842631f178f41baa2d2d444a277d54c07666a1
 * by harness/extract.py; do not edit. */
/*
 * Mathematical modulo, the residue of 'v' modulo 'step', normalized to [0, step).
 * This differs from C's '%' operator, which truncates the quotient toward zero
 * and so returns a remainder with the sign of the dividend (e.g. -1 % 3 == -1, not 2).
 */
static inline u16 imod(s64 v, u16 step)
{
	s32 rem;

	div_s64_rem(v, step, &rem);
	return rem < 0 ? rem + step : rem;
}

static inline s64 reg_smin(const struct bpf_reg_state *reg)
{
	return cnum64_smin(reg->r64);
}

static inline s64 reg_smax(const struct bpf_reg_state *reg)
{
	return cnum64_smax(reg->r64);
}

static inline u64 reg_umin(const struct bpf_reg_state *reg)
{
	return cnum64_umin(reg->r64);
}

static inline u64 reg_umax(const struct bpf_reg_state *reg)
{
	return cnum64_umax(reg->r64);
}

static inline s32 reg_s32_min(const struct bpf_reg_state *reg)
{
	return cnum32_smin(reg->r32);
}

static inline s32 reg_s32_max(const struct bpf_reg_state *reg)
{
	return cnum32_smax(reg->r32);
}

static inline u32 reg_u32_min(const struct bpf_reg_state *reg)
{
	return cnum32_umin(reg->r32);
}

static inline u32 reg_u32_max(const struct bpf_reg_state *reg)
{
	return cnum32_umax(reg->r32);
}

static inline void reg_set_srange32(struct bpf_reg_state *reg, s32 smin, s32 smax)
{
	reg->r32 = cnum32_from_srange(smin, smax);
}

static inline void reg_set_urange32(struct bpf_reg_state *reg, u32 umin, u32 umax)
{
	reg->r32 = cnum32_from_urange(umin, umax);
}

static inline void reg_set_srange64(struct bpf_reg_state *reg, s64 smin, s64 smax)
{
	reg->r64 = cnum64_from_srange(smin, smax);
}

static inline void reg_set_urange64(struct bpf_reg_state *reg, u64 umin, u64 umax)
{
	reg->r64 = cnum64_from_urange(umin, umax);
}
