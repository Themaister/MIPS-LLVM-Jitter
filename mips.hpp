#pragma once

#include "ir_recompile.hpp"
#include "ir_function.hpp"
#include "jitter.hpp"
#include "mips_opcode.hpp"
#include "linuxvm.hpp"
#include <setjmp.h>

//#define DEBUG_CALLSTACK

namespace JITTIR
{
enum Registers
{
	REG_ZERO = 0,
	REG_AT,
	REG_V0,
	REG_V1,
	REG_A0,
	REG_A1,
	REG_A2,
	REG_A3,
	REG_T0,
	REG_T1,
	REG_T2,
	REG_T3,
	REG_T4,
	REG_T5,
	REG_T6,
	REG_T7,
	REG_S0,
	REG_S1,
	REG_S2,
	REG_S3,
	REG_S4,
	REG_S5,
	REG_S6,
	REG_S7,
	REG_T8,
	REG_T9,
	REG_K0,
	REG_K1,
	REG_GP,
	REG_SP,
	REG_FP,
	REG_RA,

	REG_LO,
	REG_HI,
	REG_PC,
	REG_TLS,
	REG_COUNT
};

enum FloatRegisters
{
	FREG_F0 = 0,
	FREG_F1,
	FREG_F2,
	FREG_F3,
	FREG_F4,
	FREG_F5,
	FREG_F6,
	FREG_F7,
	FREG_F8,
	FREG_F9,
	FREG_F10,
	FREG_F11,
	FREG_F12,
	FREG_F13,
	FREG_F14,
	FREG_F15,
	FREG_F16,
	FREG_F17,
	FREG_F18,
	FREG_F19,
	FREG_F20,
	FREG_F21,
	FREG_F22,
	FREG_F23,
	FREG_F24,
	FREG_F25,
	FREG_F26,
	FREG_F27,
	FREG_F28,
	FREG_F29,
	FREG_F30,
	FREG_F31,
	FREG_FCSR,
	FREG_COUNT
};

enum Syscalls
{
	SYSCALL_EXIT = 1,
	SYSCALL_READ = 3,
	SYSCALL_WRITE = 4,
	SYSCALL_OPEN = 5,
	SYSCALL_CLOSE = 6,
	SYSCALL_BRK = 45,
	SYSCALL_READLINK = 85,
	SYSCALL_MMAP = 90,
	SYSCALL_MUNMAP = 91,
	SYSCALL_UNAME = 122,
	SYSCALL_LLSEEK = 140,
	SYSCALL_READV = 145,
	SYSCALL_WRITEV = 146,
	SYSCALL_MREMAP = 167,
	SYSCALL_MMAP2 = 210,
	SYSCALL_TKILL = 236,
	SYSCALL_EXIT_GROUP = 246,
	SYSCALL_SET_THREAD_AREA = 283,
	SYSCALL_OPENAT = 288,
	SYSCALL_COUNT
};


class RegisterTracker;

using StubCallPtr = void (*)(RegisterState *);

class MIPS : public JITTIR::RegisterState, public JITTIR::RecompilerBackend, public JITTIR::BlockAnalysisBackend
{
public:
	MIPS();
	~MIPS();
	VirtualAddressSpace &get_address_space();
	SymbolTable &get_symbol_table();

	enum class ExitCondition : int
	{
		Invalid = 0,
		ExitTooDeepStack = 1,
		ExitTooDeepJumpStack = 2,
		ExitBreak = 3,
		JumpToZero = 4
	};

	struct ExitState
	{
		Address pc;
		ExitCondition condition;
	};

	ExitState enter(Address addr) noexcept;

	uint32_t lwl(Address addr, uint32_t old_value) const noexcept;
	uint32_t lwr(Address addr, uint32_t old_value) const noexcept;
	void swl(Address addr, uint32_t value) noexcept;
	void swr(Address addr, uint32_t value) noexcept;
	void step() noexcept;
	void step_after() noexcept;

	void store32(Address addr, uint32_t value) noexcept;
	void store16(Address addr, uint32_t value) noexcept;
	void store8(Address addr, uint32_t value) noexcept;
	uint32_t load32(Address addr) const noexcept;
	uint16_t load16(Address addr) const noexcept;
	uint8_t load8(Address addr) const noexcept;
	void sigill(Address addr) const noexcept;
	void op_break(Address addr, uint32_t code) noexcept;
	void op_syscall(Address addr, uint32_t code) noexcept;
	StubCallPtr call_addr(Address addr, Address expected_addr) noexcept;
	void predict_return(Address addr, Address expected_addr) noexcept;
	StubCallPtr jump_addr(Address addr) noexcept;

	void set_external_ir_dump_directory(const std::string &dir);
	void set_external_symbol(Address addr, void (*symbol)(RegisterState *));

private:
	VirtualAddressSpace addr_space;
	SymbolTable symbol_table;

	void get_block_from_address(Address addr, Block &block) override;

	void recompile_basic_block(
		Address start_addr, Address end_addr,
		Recompiler *recompiler, const Block &block, llvm::BasicBlock *bb, llvm::Value *args) override;

	Jitter jitter;
	jmp_buf jump_buffer;
	Address return_stack[1024];
	unsigned return_stack_count = 0;
	unsigned stack_depth = 0;
	Address exit_pc = 0;

	std::unordered_map<Address, void (*)(RegisterState *)> blocks;
	StubCallPtr call(Address addr) noexcept;
	MIPSInstruction load_instr(Address addr);
	void recompile_instruction(Recompiler *recompiler, llvm::BasicBlock *&bb,
	                           llvm::IRBuilder<> &builder, RegisterTracker &tracker, Address addr);

	llvm::Value *create_call(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, Address addr, Address expected_return);
	llvm::Value *create_call(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr, Address expected_return);
	llvm::Value *create_jump_indirect(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr);
	void create_store32(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr, llvm::Value *value);
	void create_store16(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr, llvm::Value *value);
	void create_store8(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr, llvm::Value *value);
	llvm::Value *create_load32(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr);
	llvm::Value *create_load16(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr);
	llvm::Value *create_load8(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr);
	void create_sigill(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, Address addr);
	void create_break(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, Address addr, uint32_t code);
	void create_syscall(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, Address addr, uint32_t code);

	llvm::Value *create_lwl(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *old_value, llvm::Value *addr);
	llvm::Value *create_lwr(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *old_value, llvm::Value *addr);
	void create_swl(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr, llvm::Value *value);
	void create_swr(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb, llvm::Value *addr, llvm::Value *value);
	void call_step(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb);
	void call_step_after(Recompiler *recompiler, llvm::Value *argument, llvm::BasicBlock *bb);

	struct
	{
		llvm::Function *lwl = nullptr;
		llvm::Function *lwr = nullptr;
		llvm::Function *swl = nullptr;
		llvm::Function *swr = nullptr;
		llvm::Function *store32 = nullptr;
		llvm::Function *store16 = nullptr;
		llvm::Function *store8 = nullptr;
		llvm::Function *load32 = nullptr;
		llvm::Function *load16 = nullptr;
		llvm::Function *load8 = nullptr;
		llvm::Function *call = nullptr;
		llvm::Function *predict_return = nullptr;
		llvm::Function *jump_indirect = nullptr;
		llvm::Function *sigill = nullptr;
		llvm::Function *op_break = nullptr;
		llvm::Function *op_syscall = nullptr;
		llvm::Function *step = nullptr;
		llvm::Function *step_after = nullptr;
	} calls;

	using SyscallPtr = void (MIPS::*)();
	SyscallPtr syscall_table[SYSCALL_COUNT] = {};
	void syscall_exit();
	void syscall_write();
	void syscall_open();
	void syscall_openat();
	void syscall_close();
	void syscall_brk();
	void syscall_writev();
	void syscall_set_thread_area();
	void syscall_unimplemented();
	void syscall_read();
	void syscall_readv();
	void syscall_mmap();
	void syscall_mremap();
	void syscall_mmap_impl(int page_mult);
	void syscall_mmap2();
	void syscall_munmap();
	void syscall_llseek();
	void syscall_tkill();
	void syscall_uname();
	void syscall_readlink();

	RegisterState old_state = {};

#ifdef DEBUG_CALLSTACK
	std::vector<std::string> call_stack_name;
#endif

	std::string llvm_dump_dir;
	void dump_symbol_addresses(const std::string &path) const;
};

}