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
	{ Op::Call, OP_ABS(256) },
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
	case Op::CallRegister:
	case Op::BranchRegister:
		return true;

	default:
		return false;
	}
}

struct RegisterTracker
{
	RegisterTracker(IRBuilder<> &builder_, Value *arg_)
		: builder(builder_), arg(arg_)
	{
	}

	void write(unsigned index, Value *value)
	{
		registers[index] = value;
		dirty |= 1ull << index;
	}

	Value *read(unsigned index)
	{
		if (registers[index])
			return registers[index];

		auto *ptr = builder.CreateConstInBoundsGEP1_64(arg, index);
		registers[index] = builder.CreateLoad(ptr);
		return registers[index];
	}

	void flush()
	{
		for (int i = 0; i < MaxRegisters; i++)
		{
			if (dirty & (1ull << i))
			{
				auto *ptr = builder.CreateConstInBoundsGEP1_64(arg, i);
				builder.CreateStore(registers[i], ptr);
			}
		}
		dirty = 0;
	}

	void invalidate()
	{
		memset(registers, 0, sizeof(registers));
	}

	IRBuilder<> &builder;
	Value *arg;
	Value *registers[MaxRegisters] = {};
	uint64_t dirty = 0;
};

struct Backend : BlockAnalysisBackend, RecompilerBackend
{
	void get_block_from_address(Address addr, Block &block) override
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

	void recompile_basic_block(
		Address start_addr, Address end_addr,
		Recompiler *recompiler, const Block &block, BasicBlock *bb, Value *args) override
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
				tracker.write(63, ConstantInt::get(Type::getInt32Ty(ctx), addr + 4));
				tracker.flush();
				// Call
				tracker.invalidate();
				break;

			case Op::CallRegister:
				tracker.write(63, ConstantInt::get(Type::getInt32Ty(ctx), addr + 4));
				// Fallthrough.
			case Op::BranchRegister:
				tracker.flush();
				// Call
				builder.CreateRetVoid();
				break;
			}
		}

		if (block.terminator == Terminator::DirectBranch)
			BranchInst::Create(recompiler->get_block_for_address(block.static_address_targets[0]), bb);
	}
};

int main()
{
	Jitter::init_global();
	JITTIR::Function func;
	JITTIR::Recompiler recompiler;
	JITTIR::Jitter jitter;
	Backend back;
	func.set_backend(&back);
	recompiler.set_backend(&back);
	recompiler.set_jitter(&jitter);

	func.analyze_from_entry(0);
	auto result = recompiler.recompile_function(func);

	int32_t registers[MaxRegisters] = {};
	registers[3] = 100;
	result.call(registers);
	result.call(registers);
}
