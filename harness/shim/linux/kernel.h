/* Shim for <linux/kernel.h>: pulls in what tnum.c / cnum_defs.h use. */
#ifndef _SHIM_LINUX_KERNEL_H
#define _SHIM_LINUX_KERNEL_H
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/minmax.h>
#include <linux/bits.h>
#include <string.h>
#define EXPORT_SYMBOL_GPL(sym)
#undef __attribute_const__
#define __attribute_const__ __attribute__((const))
#define BITS_PER_LONG 64
#define BITS_PER_LONG_LONG 64
/* include/asm-generic/bitops/fls64.h (64-bit variant) */
static inline int fls64(u64 x)
{
	if (x == 0)
		return 0;
	return 64 - __builtin_clzll(x);
}
/* include/asm-generic/bitops/__ffs.h */
static inline unsigned int __ffs(unsigned long word)
{
	return __builtin_ctzl(word);
}
static inline __attribute_const__ unsigned int __ffs64(u64 word)
{
	return __ffs((unsigned long)word);
}
/* include/linux/count_zeros.h */
static inline int count_trailing_zeros(unsigned long x)
{
	return x ? __ffs(x) : BITS_PER_LONG;
}
#define hweight64(w) __builtin_popcountll(w)
/* include/linux/overflow.h */
#define check_add_overflow(a, b, d) __builtin_add_overflow(a, b, d)
#define check_mul_overflow(a, b, d) __builtin_mul_overflow(a, b, d)
/* include/linux/math64.h (64-bit variants) */
static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}
static inline u64 div64_u64(u64 dividend, u64 divisor) { return dividend / divisor; }
static inline s64 div64_s64(s64 dividend, s64 divisor) { return dividend / divisor; }
#endif
