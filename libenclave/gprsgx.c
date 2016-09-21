#include <stdint.h>
struct GPRSGX {
	uint64_t RAX;
	uint64_t RCX;
	uint64_t RDX;
	uint64_t RBX;
	uint64_t RSP;
	uint64_t RBP;
	uint64_t RSI;
	uint64_t RDI;
	uint64_t R8;
	uint64_t R9;
	uint64_t R10;
	uint64_t R11;
	uint64_t R12;
	uint64_t R13;
	uint64_t R14;
	uint64_t R15;
	uint64_t RFLAGS;
	uint64_t RIP;
	uint64_t URSP;
	uint64_t URBP;
	uint32_t EXITINFO;
	uint32_t RESERVED;
	uint64_t FSBASE;
	uint64_t GSBASE;
};
struct SSA {
	char padding[4096-sizeof(struct GPRSGX)];
	struct GPRSGX GPRSGX;
};
extern struct SSA __ssa__;
