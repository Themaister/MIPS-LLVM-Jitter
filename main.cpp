#include <setjmp.h>
#include "ir_function.hpp"
#include "ir_recompile.hpp"

using namespace JITTIR;
using namespace llvm;

enum class Op
{
	Add,
	Sub,

	Or,
	Xor,
	And,

	AddImm,
	OrImm,
	XorImm,
	AndImm,

	ShiftLeft,
	ShiftRightLogical,
	ShiftRightArithmetic,
	ShiftLeftImm,
	ShiftRightLogicalImm,
	ShiftRightArithmeticImm,

	Mul,
	MulImm,

	LoadImmediate,
	LoadImmediateUpper,

	BZ,
	BNZ,
	CMPULessThan,
	CMPULessThanImm,
	CMPSLessThan,
	CMPSLessThanImm,

	Call,
	BranchRegister,
	CallRegister
};

struct Instr
{
	Op op;
	uint32_t arg;

	uint8_t get_3op_ra() const
	{
		return (arg >> 6) & 63;
	}

	uint8_t get_3op_rb() const
	{
		return (arg >> 0) & 63;
	}

	uint8_t get_3op_rc() const
	{
		return (arg >> 12) & 63;
	}

	uint8_t get_2op_imm_ra() const
	{
		return (arg >> 16) & 63;
	}

	uint8_t get_2op_imm_rc() const
	{
		return (arg >> 22) & 63;
	}

	uint8_t get_1op_imm_rc() const
	{
		return (arg >> 16) & 63;
	}

	uint8_t get_1op_rc() const
	{
		return (arg >> 0) & 63;
	}
};

#define OP_3REG(rc, ra, rb) \
	((((rc) & 63) << 12) | \
	(((ra) & 63) << 6) | \
	(((rb) & 63) << 0))
#define OP_2REG_IMM(rc, ra, imm) \
	((((rc) & 63) << 22) | \
	(((ra) & 63) << 16) | \
	(((imm) & 0xffff) << 0))
#define OP_1REG_IMM(rc, imm) \
	((((rc) & 63) << 16) | \
	(((imm) & 0xffff) << 0))
#define OP_ABS(imm) (imm)
#define OP_1REG(rc) ((rc) & 63)

static const Instr IDAT[] = {
	{ Op::LoadImmediate, OP_1REG_IMM(1, 0) },
	{ Op::Mul, OP_3REG(60, 2, 2) },
	{ Op::Add, OP_3REG(1, 1, 60) },
	{ Op::AddImm, OP_2REG_IMM(60, 60, 1) },
	{ Op::CMPSLessThan, OP_3REG(61, 60, 3) },
	{ Op::BNZ, OP_1REG_IMM(61, -4) },
	{ Op::Call, OP_ABS(9 * 4) },
	{ Op::Call, OP_ABS(11 * 4) },
	{ Op::BranchRegister, OP_1REG(63) },

	{ Op::AddImm, OP_2REG_IMM(1, 1, 1000) }, // 9
	{ Op::BranchRegister, OP_1REG(63) },

	{ Op::AddImm, OP_2REG_IMM(1, 1, 2000) }, // 11
	{ Op::BranchRegister, OP_1REG(63) },
};

static bool opcode_ends_block(Address addr)
{
	if (addr >= 4 * (sizeof(IDAT) / sizeof(*IDAT)))
		return true;

	switch (IDAT[addr >> 2].op)
	{
	case Op::BNZ:
	case Op::BZ:
	case Op::BranchRegister:
		return true;

	default:
		return false;
	}
}

using StubCallPtr = void (*)(RegisterState *);

extern "C" {
static StubCallPtr backend_call_addr(RegisterState *regs, Address addr, Address expected_addr);
static StubCallPtr backend_jump_addr(RegisterState *regs, Address addr);
static void backend_store32(RegisterState *regs, Address addr, uint32_t value);
static void backend_store16(RegisterState *regs, Address addr, uint32_t value);
static void backend_store8(RegisterState *regs, Address addr, uint32_t value);
static uint32_t backend_load32(RegisterState *regs, Address addr);
static uint16_t backend_load16(RegisterState *regs, Address addr);
static uint8_t backend_load8(RegisterState *regs, Address addr);
}

struct Backend : RegisterState, BlockAnalysisBackend, RecompilerBackend
{
	Backend();

	union
	{
		uint32_t mem32[4096 / 4];
		uint16_t mem16[4096 / 2];
		uint8_t mem8[4096];
	} mem;

	void store32(Address addr, uint32_t value) noexcept
	{
		mem.mem32[addr >> 2] = value;
	}

	void store16(Address addr, uint32_t value) noexcept
	{
		mem.mem16[addr >> 1] = uint16_t(value);
	}

	void store8(Address addr, uint32_t value) noexcept
	{
		mem.mem8[addr] = uint8_t(value);
	}

	uint32_t load32(Address addr) const noexcept
	{
		return mem.mem32[addr >> 2];
	}

	uint16_t load16(Address addr) const noexcept
	{
		return mem.mem16[addr >> 1];
	}

	uint8_t load8(Address addr) const noexcept
	{
		return mem.mem8[addr];
	}

	enum { ExitTooDeepStack = 1, ExitTooDeepJumpStack = 2 };

	Address enter(Address addr) noexcept
	{
		exit_pc = addr;

		if (setjmp(jump_buffer))
			return exit_pc;

		auto *ptr = call(addr);
		ptr(this);

		// Should not be reached.
		return exit_pc;
	}

	StubCallPtr call(Address addr) noexcept
	{
		auto itr = blocks.find(addr);
		if (itr != end(blocks))
		{
			return itr->second.call;
		}
		else
		{
			JITTIR::Function func;
			JITTIR::Recompiler recompiler;
			func.set_backend(this);
			recompiler.set_backend(this);
			recompiler.set_jitter(&jitter);
			func.analyze_from_entry(addr);
			auto result = recompiler.recompile_function(func);
			if (!result.call)
				std::abort();
			blocks.emplace(addr, result);
			return result.call;
		}
	}

	StubCallPtr call_addr(Address addr, Address expected_addr) noexcept
	{
		if (return_stack_count >= 1024)
		{
			exit_pc = addr;
			longjmp(jump_buffer, ExitTooDeepStack);
		}

		return_stack[return_stack_count++] = expected_addr;
		stack_depth++;
		return call(addr);
	}

	StubCallPtr jump_addr(Address addr) noexcept
	{
		if (return_stack_count > 0 && return_stack[return_stack_count - 1] == addr)
		{
			stack_depth--;
			return_stack[return_stack_count--];
			return nullptr;
		}
		else
		{
			stack_depth++;
			if (stack_depth > 2048)
			{
				exit_pc = addr;
				longjmp(jump_buffer, ExitTooDeepJumpStack);
			}
			return call(addr);
		}
	}

	void get_block_from_address(Address addr, Block &block) override;
	void recompile_basic_block(
		Address start_addr, Address end_addr,
		Recompiler *recompiler, const Block &block, BasicBlock *bb, Value *args) override;

	JITTIR::Jitter jitter;
	std::unordered_map<Address, JITTIR::Recompiler::Result> blocks;
	jmp_buf jump_buffer;
	Address return_stack[1024];
	unsigned return_stack_count = 0;
	unsigned stack_depth = 0;
	Address exit_pc = 0;
};

Backend::Backend()
{
	jitter.add_external_symbol("__recompiler_call_addr", backend_call_addr);
	jitter.add_external_symbol("__recompiler_jump_indirect", backend_jump_addr);
	jitter.add_external_symbol("__recompiler_store32", backend_store32);
	jitter.add_external_symbol("__recompiler_store16", backend_store16);
	jitter.add_external_symbol("__recompiler_store8", backend_store8);
	jitter.add_external_symbol("__recompiler_load32", backend_load32);
	jitter.add_external_symbol("__recompiler_load16", backend_load16);
	jitter.add_external_symbol("__recompiler_load8", backend_load8);
	memset(&mem, 0, sizeof(mem));
}

void Backend::get_block_from_address(Address addr, Block &block)
{
	block.block_start = addr;
	bool ends_block;

	do
	{
		auto &instr = IDAT[addr >> 2];
		ends_block = opcode_ends_block(addr);

		if (instr.op == Op::BZ)
		{
			if (instr.get_1op_imm_rc() == 0)
			{
				block.terminator = Terminator::DirectBranch;
				block.static_address_targets[0] =
					addr + 4 + int16_t(instr.arg & 0xffff) * 4;
			}
			else
			{
				block.terminator = Terminator::SelectionBranch;
				block.static_address_targets[0] =
					addr + 4 + int16_t(instr.arg & 0xffff);
				block.static_address_targets[1] =
					addr + 4;
			}
		}
		else if (instr.op == Op::BNZ)
		{
			block.terminator = Terminator::SelectionBranch;
			block.static_address_targets[0] =
				addr + 4 + int16_t(instr.arg & 0xffff) * 4;
			block.static_address_targets[1] =
				addr + 4;
		}
		else if (instr.op == Op::BranchRegister || instr.op == Op::CallRegister)
			block.terminator = Terminator::Unwind;

		// Conditional backwards branch into our current block. Split the block so we can get a clean loop.
		if (ends_block &&
		    block.terminator == Terminator::SelectionBranch &&
		    block.static_address_targets[0] > block.block_start &&
		    block.static_address_targets[0] < addr)
		{
			// Split the block.
			block.block_end = block.static_address_targets[0];
			block.terminator = Terminator::DirectBranch;
			return;
		}

		addr += 4;
	} while (!ends_block);

	block.block_end = addr;
}

void Backend::recompile_basic_block(
	Address start_addr, Address end_addr,
	Recompiler *recompiler, const Block &block, BasicBlock *bb, Value *args)
{
	IRBuilder<> builder(bb);
	auto &ctx = bb->getContext();
	RegisterTracker tracker(builder, args);

	for (Address addr = start_addr; addr < end_addr; addr += 4)
	{
		auto &instr = IDAT[addr >> 2];

		switch (instr.op)
		{
		case Op::Add:
			tracker.write(instr.get_3op_rc(), builder.CreateAdd(
				tracker.read(instr.get_3op_ra()),
				tracker.read(instr.get_3op_rb())));
			break;

		case Op::Sub:
			tracker.write(instr.get_3op_rc(), builder.CreateSub(
				tracker.read(instr.get_3op_ra()),
				tracker.read(instr.get_3op_rb())));
			break;

		case Op::Or:
			tracker.write(instr.get_3op_rc(), builder.CreateOr(
				tracker.read(instr.get_3op_ra()),
				tracker.read(instr.get_3op_rb())));
			break;

		case Op::Xor:
			tracker.write(instr.get_3op_rc(), builder.CreateXor(
				tracker.read(instr.get_3op_ra()),
				tracker.read(instr.get_3op_rb())));
			break;

		case Op::And:
			tracker.write(instr.get_3op_rc(), builder.CreateAnd(
				tracker.read(instr.get_3op_ra()),
				tracker.read(instr.get_3op_rb())));
			break;

		case Op::Mul:
			tracker.write(instr.get_3op_rc(), builder.CreateMul(
				tracker.read(instr.get_3op_ra()),
				tracker.read(instr.get_3op_rb())));
			break;

		case Op::ShiftLeft:
			tracker.write(instr.get_3op_rc(), builder.CreateShl(
				tracker.read(instr.get_3op_ra()),
				builder.CreateAnd(tracker.read(instr.get_3op_rb()), ConstantInt::get(Type::getInt32Ty(ctx), 31))));
			break;

		case Op::ShiftRightLogical:
			tracker.write(instr.get_3op_rc(), builder.CreateLShr(
				tracker.read(instr.get_3op_ra()),
				builder.CreateAnd(tracker.read(instr.get_3op_rb()), ConstantInt::get(Type::getInt32Ty(ctx), 31))));
			break;

		case Op::ShiftRightArithmetic:
			tracker.write(instr.get_3op_rc(), builder.CreateAShr(
				tracker.read(instr.get_3op_ra()),
				builder.CreateAnd(tracker.read(instr.get_3op_rb()), ConstantInt::get(Type::getInt32Ty(ctx), 31))));
			break;

		case Op::CMPSLessThan:
			tracker.write(instr.get_3op_rc(),
			              builder.CreateSelect(builder.CreateICmpSLT(tracker.read(instr.get_3op_ra()), tracker.read(instr.get_3op_rb())),
			                                   ConstantInt::get(Type::getInt32Ty(ctx), 1),
			                                   ConstantInt::get(Type::getInt32Ty(ctx), 0)));
			break;

		case Op::CMPULessThan:
			tracker.write(instr.get_3op_rc(),
			              builder.CreateSelect(builder.CreateICmpULT(tracker.read(instr.get_3op_ra()), tracker.read(instr.get_3op_rb())),
			                                   ConstantInt::get(Type::getInt32Ty(ctx), 1),
			                                   ConstantInt::get(Type::getInt32Ty(ctx), 0)));
			break;

		case Op::AddImm:
			tracker.write(instr.get_2op_imm_rc(), builder.CreateAdd(
				tracker.read(instr.get_2op_imm_ra()),
				ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.arg & 0xffff))));
			break;

		case Op::OrImm:
			tracker.write(instr.get_2op_imm_rc(), builder.CreateOr(
				tracker.read(instr.get_2op_imm_ra()),
				ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff))));
			break;

		case Op::AndImm:
			tracker.write(instr.get_2op_imm_rc(), builder.CreateAnd(
				tracker.read(instr.get_2op_imm_ra()),
				ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff))));
			break;

		case Op::XorImm:
			tracker.write(instr.get_2op_imm_rc(), builder.CreateXor(
				tracker.read(instr.get_2op_imm_ra()),
				ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff))));
			break;

		case Op::ShiftLeftImm:
			tracker.write(instr.get_2op_imm_rc(), builder.CreateShl(
				tracker.read(instr.get_2op_imm_ra()),
				ConstantInt::get(Type::getInt32Ty(ctx), instr.arg & 31)));
			break;

		case Op::ShiftRightLogicalImm:
			tracker.write(instr.get_2op_imm_rc(), builder.CreateLShr(
				tracker.read(instr.get_2op_imm_ra()),
				ConstantInt::get(Type::getInt32Ty(ctx), instr.arg & 31)));
			break;

		case Op::ShiftRightArithmeticImm:
			tracker.write(instr.get_2op_imm_rc(), builder.CreateAShr(
				tracker.read(instr.get_2op_imm_ra()),
				ConstantInt::get(Type::getInt32Ty(ctx), instr.arg & 31)));
			break;

		case Op::MulImm:
			tracker.write(instr.get_2op_imm_rc(), builder.CreateMul(
				tracker.read(instr.get_2op_imm_ra()),
				ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.arg & 0xffff))));
			break;

		case Op::CMPSLessThanImm:
			tracker.write(instr.get_2op_imm_rc(),
			              builder.CreateSelect(builder.CreateICmpSLT(tracker.read(instr.get_2op_imm_ra()), ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.arg & 0xffff))),
			                                   ConstantInt::get(Type::getInt32Ty(ctx), 1),
			                                   ConstantInt::get(Type::getInt32Ty(ctx), 0)));
			break;

		case Op::CMPULessThanImm:
			tracker.write(instr.get_2op_imm_rc(),
			              builder.CreateSelect(builder.CreateICmpULT(tracker.read(instr.get_2op_imm_ra()), ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff))),
			                                   ConstantInt::get(Type::getInt32Ty(ctx), 1),
			                                   ConstantInt::get(Type::getInt32Ty(ctx), 0)));
			break;

		case Op::LoadImmediate:
			tracker.write(instr.get_1op_imm_rc(), ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff)));
			break;

		case Op::LoadImmediateUpper:
			tracker.write(instr.get_1op_imm_rc(), ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff) << 16));
			break;

		case Op::BNZ:
			tracker.flush();
			BranchInst::Create(recompiler->get_block_for_address(addr + 4 + int16_t(instr.arg & 0xffff) * 4),
			                   recompiler->get_block_for_address(addr + 4),
			                   builder.CreateICmpNE(tracker.read(instr.get_1op_imm_rc()), ConstantInt::get(Type::getInt32Ty(ctx), 0)), bb);
			break;

		case Op::BZ:
			tracker.flush();
			BranchInst::Create(recompiler->get_block_for_address(addr + 4 + int16_t(instr.arg & 0xffff) * 4),
			                   recompiler->get_block_for_address(addr + 4),
			                   builder.CreateICmpEQ(tracker.read(instr.get_1op_imm_rc()), ConstantInt::get(Type::getInt32Ty(ctx), 0)), bb);
			break;

		case Op::Call:
		{
			tracker.write(63, ConstantInt::get(Type::getInt32Ty(ctx), addr + 4));
			tracker.flush();
			auto *call = recompiler->create_call(instr.arg, addr + 4);
			Value *values[] = { args };
			builder.SetInsertPoint(bb);
			builder.CreateCall(call, values);
			tracker.invalidate();
			break;
		}

		case Op::CallRegister:
		{
			tracker.write(63, ConstantInt::get(Type::getInt32Ty(ctx), addr + 4));
			tracker.flush();
			auto *call = recompiler->create_call(tracker.read(instr.get_1op_rc()), addr + 4);
			Value *values[] = { args };
			builder.SetInsertPoint(bb);
			builder.CreateCall(call, values);
			tracker.invalidate();
			break;
		}

		case Op::BranchRegister:
			tracker.flush();
			auto *call = recompiler->create_jump_indirect(tracker.read(instr.get_1op_rc()));
			auto *bb_call = BasicBlock::Create(ctx, "IndirectJumpPath", recompiler->get_current_function());
			auto *bb_return = BasicBlock::Create(ctx, "IndirectJumpReturn", recompiler->get_current_function());
			builder.SetInsertPoint(bb);
			builder.CreateCondBr(builder.CreateICmpNE(call, ConstantPointerNull::get(static_cast<PointerType *>(call->getType()))),
			                     bb_call, bb_return);

			builder.SetInsertPoint(bb_call);
			Value *values[] = { args };
			builder.CreateCall(call, values);
			BranchInst::Create(bb_return, bb_call);

			builder.SetInsertPoint(bb_return);
			builder.CreateRetVoid();
			break;
		}
	}

	if (block.terminator == Terminator::DirectBranch)
		BranchInst::Create(recompiler->get_block_for_address(block.static_address_targets[0]), bb);
}

extern "C" {
static StubCallPtr backend_call_addr(RegisterState *regs, Address addr, Address expected_addr)
{
	return static_cast<Backend *>(regs)->call_addr(addr, expected_addr);
}

static StubCallPtr backend_jump_addr(RegisterState *regs, Address addr)
{
	return static_cast<Backend *>(regs)->jump_addr(addr);
}

static void backend_store32(RegisterState *regs, Address addr, uint32_t value)
{
	static_cast<Backend *>(regs)->store32(addr, value);
}

static void backend_store16(RegisterState *regs, Address addr, uint32_t value)
{
	static_cast<Backend *>(regs)->store16(addr, value);
}

static void backend_store8(RegisterState *regs, Address addr, uint32_t value)
{
	static_cast<Backend *>(regs)->store8(addr, value);
}

static uint32_t backend_load32(RegisterState *regs, Address addr)
{
	return static_cast<Backend *>(regs)->load32(addr);
}

static uint16_t backend_load16(RegisterState *regs, Address addr)
{
	return static_cast<Backend *>(regs)->load16(addr);
}

static uint8_t backend_load8(RegisterState *regs, Address addr)
{
	return static_cast<Backend *>(regs)->load8(addr);
}
}

int main()
{
	Backend back;
	back.scalar_registers[3] = 100;
	back.enter(0);
}
