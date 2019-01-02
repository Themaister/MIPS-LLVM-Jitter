#include "mips_opcode.hpp"

namespace JITTIR
{
// Technically undefined to run a branch instruction inside a basic block.
// At the very least, it must not branch, so ... it's effectively a no-op.
bool mips_opcode_is_branch(Op op)
{
	switch (op)
	{
	case Op::J:
	case Op::JAL:
	case Op::JR:
	case Op::JALR:
	case Op::BEQ:
	case Op::BNE:
	case Op::BLEZ:
	case Op::BGTZ:
	case Op::BLTZ:
	case Op::BGEZ:
	case Op::BLTZAL:
	case Op::BGEZAL:
		return true;

	default:
		return false;
	}
}

bool mips_opcode_ends_basic_block(Op op)
{
	switch (op)
	{
	case Op::J:
	case Op::JR:
	case Op::BEQ:
	case Op::BNE:
	case Op::BLEZ:
	case Op::BGTZ:
	case Op::BLTZ:
	case Op::BGEZ:
	case Op::BREAK:
	case Op::Invalid:
		return true;

	default:
		return false;
	}
}
}