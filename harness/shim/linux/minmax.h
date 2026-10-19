/* Shim for include/linux/minmax.h: the kernel's min/max are type-checked
 * macros; semantically plain comparisons on the promoted operands. */
#ifndef _SHIM_LINUX_MINMAX_H
#define _SHIM_LINUX_MINMAX_H
#define __cmp(op, x, y) ((x) op (y) ? (x) : (y))
#define min(x, y) ({ __typeof__(x) __x = (x); __typeof__(y) __y = (y); __x < __y ? __x : __y; })
#define max(x, y) ({ __typeof__(x) __x = (x); __typeof__(y) __y = (y); __x > __y ? __x : __y; })
#define min_t(type, x, y) min((type)(x), (type)(y))
#define max_t(type, x, y) max((type)(x), (type)(y))
/* verbatim from include/linux/minmax.h */
#define __minmax_array(op, array, len) ({				\
	__typeof__(&(array)[0]) __array = (array);			\
	__typeof__(len) __len = (len);					\
	__typeof__(__array[0]) __element = __array[--__len];		\
	while (__len--)							\
		__element = op(__element, __array[__len]);		\
	__element; })
#define min_array(array, len) __minmax_array(min, array, len)
#define max_array(array, len) __minmax_array(max, array, len)
#define swap(a, b) \
	do { __typeof__(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#endif
