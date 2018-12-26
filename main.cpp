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

static void read_register(Block &block, uint32_t reg)
{
	if (!(block.write_registers & (1ull << reg)))
		block.preserve_registers |= 1ull << reg;
}

static void write_register(Block &block, uint32_t reg)
{
	block.write_registers |= 1ull << reg;
}

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

			switch (instr.op)
			{
			case Op::Add:
			case Op::Sub:
			case Op::Or:
			case Op::Xor:
			case Op::And:
			case Op::ShiftLeft:
			case Op::ShiftRightArithmetic:
			case Op::ShiftRightLogical:
			case Op::Mul:
			case Op::CMPSLessThan:
			case Op::CMPULessThan:
			{
				read_register(block, instr.get_3op_ra());
				read_register(block, instr.get_3op_rb());
				write_register(block, instr.get_3op_rc());
				break;
			}

			case Op::AddImm:
			case Op::OrImm:
			case Op::AndImm:
			case Op::XorImm:
			case Op::ShiftLeftImm:
			case Op::ShiftRightArithmeticImm:
			case Op::ShiftRightLogicalImm:
			case Op::CMPULessThanImm:
			case Op::CMPSLessThanImm:
			case Op::MulImm:
			{
				read_register(block, instr.get_2op_imm_ra());
				write_register(block, instr.get_2op_imm_rc());
				break;
			}

			case Op::LoadImmediate:
			case Op::LoadImmediateUpper:
			{
				write_register(block, instr.get_1op_imm_rc());
				break;
			}

			case Op::BZ:
			case Op::BNZ:
			{
				read_register(block, instr.get_1op_imm_rc());
				break;
			}

			case Op::Call:
				write_register(block, 63);
				break;

			case Op::BranchRegister:
				read_register(block, instr.get_1op_rc());
				break;

			case Op::CallRegister:
				read_register(block, instr.get_1op_rc());
				write_register(block, 63);
				break;

			default:
				std::abort();
			}

			addr += 4;

			if (instr.op == Op::BZ)
			{
				if (instr.get_1op_imm_rc() == 0)
				{
					block.terminator = Terminator::DirectBranch;
					block.static_address_targets[0] =
						addr + int16_t(instr.arg & 0xffff) * 4;
				}
				else
				{
					block.terminator = Terminator::SelectionBranch;
					block.static_address_targets[0] =
						addr + int16_t(instr.arg & 0xffff);
					block.static_address_targets[1] =
						addr;
				}
			}
			else if (instr.op == Op::BNZ)
			{
				block.terminator = Terminator::SelectionBranch;
				block.static_address_targets[0] =
					addr + int16_t(instr.arg & 0xffff) * 4;
				block.static_address_targets[1] =
					addr;
			}
			else if (instr.op == Op::BranchRegister || instr.op == Op::CallRegister)
				block.terminator = Terminator::Unwind;
		} while (!ends_block);

		block.block_end = addr;
	}

	void recompile_basic_block(
		Address start_addr, Address end_addr, uint64_t dirty_registers,
		Recompiler *recompiler, BasicBlock *block, Value *arg, Value **registers) override
	{
		IRBuilder<> builder(block);
		auto &ctx = block->getContext();

		for (Address addr = start_addr; addr < end_addr; addr += 4)
		{
			auto &instr = IDAT[addr >> 2];

			switch (instr.op)
			{
			case Op::Add:
				registers[instr.get_3op_rc()] = builder.CreateAdd(
					registers[instr.get_3op_ra()],
					registers[instr.get_3op_rb()]);
				break;

			case Op::Sub:
				registers[instr.get_3op_rc()] = builder.CreateSub(
					registers[instr.get_3op_ra()],
					registers[instr.get_3op_rb()]);
				break;

			case Op::Or:
				registers[instr.get_3op_rc()] = builder.CreateOr(
					registers[instr.get_3op_ra()],
					registers[instr.get_3op_rb()]);
				break;

			case Op::Xor:
				registers[instr.get_3op_rc()] = builder.CreateXor(
					registers[instr.get_3op_ra()],
					registers[instr.get_3op_rb()]);
				break;

			case Op::And:
				registers[instr.get_3op_rc()] = builder.CreateAnd(
					registers[instr.get_3op_ra()],
					registers[instr.get_3op_rb()]);
				break;

			case Op::Mul:
				registers[instr.get_3op_rc()] = builder.CreateMul(
					registers[instr.get_3op_ra()],
					registers[instr.get_3op_rb()]);
				break;

			case Op::ShiftLeft:
				registers[instr.get_3op_rc()] = builder.CreateShl(
					registers[instr.get_3op_ra()],
					builder.CreateAnd(registers[instr.get_3op_rb()], ConstantInt::get(Type::getInt32Ty(ctx), 31)));
				break;

			case Op::ShiftRightLogical:
				registers[instr.get_3op_rc()] = builder.CreateLShr(
					registers[instr.get_3op_ra()],
					builder.CreateAnd(registers[instr.get_3op_rb()], ConstantInt::get(Type::getInt32Ty(ctx), 31)));
				break;

			case Op::ShiftRightArithmetic:
				registers[instr.get_3op_rc()] = builder.CreateAShr(
					registers[instr.get_3op_ra()],
					builder.CreateAnd(registers[instr.get_3op_rb()], ConstantInt::get(Type::getInt32Ty(ctx), 31)));
				break;

			case Op::CMPSLessThan:
				registers[instr.get_3op_rc()] =
					builder.CreateSelect(builder.CreateICmpSLT(registers[instr.get_3op_ra()], registers[instr.get_3op_rb()]),
					                     ConstantInt::get(Type::getInt32Ty(ctx), 1),
					                     ConstantInt::get(Type::getInt32Ty(ctx), 0));
				break;

			case Op::CMPULessThan:
				registers[instr.get_3op_rc()] =
					builder.CreateSelect(builder.CreateICmpULT(registers[instr.get_3op_ra()], registers[instr.get_3op_rb()]),
					                     ConstantInt::get(Type::getInt32Ty(ctx), 1),
					                     ConstantInt::get(Type::getInt32Ty(ctx), 0));
				break;

			case Op::AddImm:
				registers[instr.get_2op_imm_rc()] = builder.CreateAdd(
					registers[instr.get_2op_imm_ra()],
					ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.arg & 0xffff)));
				break;

			case Op::OrImm:
				registers[instr.get_2op_imm_rc()] = builder.CreateOr(
					registers[instr.get_2op_imm_ra()],
					ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff)));
				break;

			case Op::AndImm:
				registers[instr.get_2op_imm_rc()] = builder.CreateAnd(
					registers[instr.get_2op_imm_ra()],
					ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff)));
				break;

			case Op::XorImm:
				registers[instr.get_2op_imm_rc()] = builder.CreateXor(
					registers[instr.get_2op_imm_ra()],
					ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff)));
				break;

			case Op::ShiftLeftImm:
				registers[instr.get_2op_imm_rc()] = builder.CreateShl(
					registers[instr.get_2op_imm_ra()],
					ConstantInt::get(Type::getInt32Ty(ctx), instr.arg & 31));
				break;

			case Op::ShiftRightLogicalImm:
				registers[instr.get_2op_imm_rc()] = builder.CreateLShr(
					registers[instr.get_2op_imm_ra()],
					ConstantInt::get(Type::getInt32Ty(ctx), instr.arg & 31));
				break;

			case Op::ShiftRightArithmeticImm:
				registers[instr.get_2op_imm_rc()] = builder.CreateAShr(
					registers[instr.get_2op_imm_ra()],
					ConstantInt::get(Type::getInt32Ty(ctx), instr.arg & 31));
				break;

			case Op::MulImm:
				registers[instr.get_2op_imm_rc()] = builder.CreateMul(
					registers[instr.get_2op_imm_ra()],
					ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.arg & 0xffff)));
				break;

			case Op::CMPSLessThanImm:
				registers[instr.get_2op_imm_rc()] =
					builder.CreateSelect(builder.CreateICmpSLT(registers[instr.get_2op_imm_ra()], ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.arg & 0xffff))),
					                     ConstantInt::get(Type::getInt32Ty(ctx), 1),
					                     ConstantInt::get(Type::getInt32Ty(ctx), 0));
				break;

			case Op::CMPULessThanImm:
				registers[instr.get_3op_rc()] =
					builder.CreateSelect(builder.CreateICmpULT(registers[instr.get_2op_imm_ra()], ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff))),
					                     ConstantInt::get(Type::getInt32Ty(ctx), 1),
					                     ConstantInt::get(Type::getInt32Ty(ctx), 0));
				break;

			case Op::LoadImmediate:
				registers[instr.get_1op_imm_rc()] = ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff));
				break;

			case Op::LoadImmediateUpper:
				registers[instr.get_1op_imm_rc()] = ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.arg & 0xffff) << 16);
				break;

			case Op::BNZ:
				BranchInst::Create(recompiler->get_block_for_address(addr + 4 + int16_t(instr.arg & 0xffff) * 4),
				                   recompiler->get_block_for_address(addr + 4),
				                   builder.CreateICmpNE(registers[instr.get_1op_imm_rc()], ConstantInt::get(Type::getInt32Ty(ctx), 0)), block);
				break;

			case Op::BZ:
				BranchInst::Create(recompiler->get_block_for_address(addr + 4 + int16_t(instr.arg & 0xffff) * 4),
				                   recompiler->get_block_for_address(addr + 4),
				                   builder.CreateICmpEQ(registers[instr.get_1op_imm_rc()], ConstantInt::get(Type::getInt32Ty(ctx), 0)), block);
				break;

			case Op::Call:
				registers[63] = ConstantInt::get(Type::getInt32Ty(ctx), addr + 4);
				break;

			case Op::BranchRegister:
			case Op::CallRegister:
				for (int i = 0; i < MaxRegisters; i++)
				{
					if (dirty_registers & (1ull << i))
					{
						assert(registers[i]);
						auto *ptr = builder.CreateConstInBoundsGEP1_64(arg, i);
						builder.CreateStore(registers[i], ptr);
					}
				}
				builder.CreateRetVoid();
				break;
			}
		}
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
