/* Shim for <linux/bpf_verifier.h>: the value-tracking part of struct
 * bpf_reg_state (field order as in the kernel, pointer members of the union
 * replaced by the 'raw' member they alias) plus imod() and the bound
 * accessors, which are compiled verbatim from extracted/. */
#ifndef _SHIM_LINUX_BPF_VERIFIER_H
#define _SHIM_LINUX_BPF_VERIFIER_H
#include <linux/kernel.h>
#include <linux/tnum.h>
#include <linux/cnum.h>

enum bpf_reg_type { NOT_INIT = 0, SCALAR_VALUE };

struct bpf_reg_state {
	enum bpf_reg_type type;
	s32 delta;
	union {
		int range;
		u8 frameno;
		struct { unsigned long raw1; unsigned long raw2; } raw;
		u32 subprogno;
	};
	struct tnum var_off;
	struct cnum64 r64;
	struct cnum32 r32;
	u16 base;
	u16 step;
	u32 id;
	u32 parent_id;
	u32 map_uid:31;
	u32 precise:1;
};

#include "extracted/bpf_verifier_h_accessors.c"
#endif
