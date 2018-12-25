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

	SMul,
	UMul,
	SMulImm,
	UMulImm,

	LoadImmediate,
	LoadImmediateUpper,

	BZ,
	BNZ,
	CMPULessThan,
	CMPUGreaterThanEqual,
	CMPULessThanImm,
	CMPUGreaterThanEqualImm,
	CMPSLessThan,
	CMPSGreaterThanEqual,
	CMPSLessThanImm,
	CMPSGreaterThanEqualImm,

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
	{ Op::LoadImmediate, OP_1REG_IMM(60, 0) },
	{ Op::Add, OP_3REG(1, 2, 60) },
	{ Op::AddImm, OP_1REG_IMM(60, 1) },
	{ Op::CMPSLessThanImm, OP_2REG_IMM(61, 60, 10) },
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
			case Op::SMul:
			case Op::UMul:
			case Op::CMPSLessThan:
			case Op::CMPSGreaterThanEqual:
			case Op::CMPULessThan:
			case Op::CMPUGreaterThanEqual:
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
			case Op::CMPUGreaterThanEqualImm:
			case Op::CMPULessThanImm:
			case Op::CMPSGreaterThanEqualImm:
			case Op::CMPSLessThanImm:
			case Op::SMulImm:
			case Op::UMulImm:
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
		Address start_addr, Address end_addr,
		Recompiler *recompiler, BasicBlock *block, Value **registers) override
	{

	}
};

int main()
{
	Jitter::init_global();
	JITTIR::Function func;
	JITTIR::Recompiler recompiler;
	Backend back;
	func.set_backend(&back);
	recompiler.set_backend(&back);

	func.analyze_from_entry(0);
}
