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

MIPSInstruction decode_mips_instruction(uint32_t pc, uint32_t word)
{
	MIPSInstruction instr = {};
	instr.op = Op::Invalid;
	uint8_t rs = (word >> 21) & 31;
	uint8_t rt = (word >> 16) & 31;
	uint8_t rd = (word >> 11) & 31;
	uint8_t shamt = (word >> 6) & 31;
	uint16_t imm16 = word & 0xffff;
	uint32_t imm26 = word & ((1u << 26) - 1u);
	uint8_t low_op = word & ((1u << 6) - 1u);

	instr.rs = rs;
	instr.rt = rt;
	instr.rd = rd;

	switch (word >> 26)
	{
	case 0:
	{
		switch (low_op)
		{
		case 0:
			instr.op = Op::SLL;
			instr.imm = shamt;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 2:
			instr.op = Op::SRL;
			instr.imm = shamt;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 3:
			instr.op = Op::SRA;
			instr.imm = shamt;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 4:
			instr.op = Op::SLLV;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 6:
			instr.op = Op::SRLV;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 7:
			instr.op = Op::SRAV;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 8:
			instr.op = Op::JR;
			break;

		case 9:
			instr.op = Op::JALR;
			break;

		case 0xc:
			instr.op = Op::SYSCALL;
			instr.imm = imm26 >> 6;
			break;

		case 0xd:
			instr.op = Op::BREAK;
			instr.imm = imm26 >> 6;
			break;

		case 0xf:
			instr.op = Op::SYNC;
			break;

		case 0x10:
			instr.op = Op::MFHI;
			break;

		case 0x11:
			instr.op = Op::MTHI;
			break;

		case 0x12:
			instr.op = Op::MFLO;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x13:
			instr.op = Op::MTLO;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x18:
			instr.op = Op::MULT;
			break;

		case 0x19:
			instr.op = Op::MULTU;
			break;

		case 0x1a:
			instr.op = Op::DIV;
			break;

		case 0x1b:
			instr.op = Op::DIVU;
			break;

		case 0x20:
			instr.op = Op::ADD;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x21:
			instr.op = Op::ADDU;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x22:
			instr.op = Op::SUB;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x23:
			instr.op = Op::SUBU;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x24:
			instr.op = Op::AND;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x25:
			instr.op = Op::OR;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x26:
			instr.op = Op::XOR;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x27:
			instr.op = Op::NOR;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x2a:
			instr.op = Op::SLT;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x2b:
			instr.op = Op::SLTU;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		default:
			instr.op = Op::Invalid;
			break;
		}
		break;
	}

	case 1:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		switch (rt)
		{
		case 0:
			if (rs == 0)
				instr.op = Op::NOP;
			else
				instr.op = Op::BLTZ;
			break;

		case 1:
			if (rs == 0)
				instr.op = Op::J;
			else
				instr.op = Op::BGEZ;
			break;

		case 16:
			if (rs == 0)
				instr.op = Op::NOP;
			else
				instr.op = Op::BLTZAL;
			break;

		case 17:
			if (rs == 0)
				instr.op = Op::JAL;
			else
				instr.op = Op::BGEZAL;
			break;

		default:
			break;
		}
		break;

	case 2:
		instr.imm = ((pc + 4) & 0xf0000000) + 4 * imm26;
		instr.op = Op::J;
		break;

	case 3:
		instr.imm = ((pc + 4) & 0xf0000000) + 4 * imm26;
		instr.op = Op::JAL;
		break;

	case 4:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		if (instr.rs == instr.rt)
			instr.op = Op::J;
		else
			instr.op = Op::BEQ;
		break;

	case 5:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		if (instr.rs == instr.rt)
			instr.op = Op::NOP;
		else
			instr.op = Op::BNE;
		break;

	case 6:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		if (instr.rs == 0)
			instr.op = Op::J;
		else
			instr.op = Op::BLEZ;
		break;

	case 7:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		if (instr.rs == 0)
			instr.op = Op::NOP;
		else
			instr.op = Op::BGTZ;
		break;

	case 8:
		instr.op = Op::ADDI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 9:
		instr.op = Op::ADDIU;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xa:
		instr.op = Op::SLTI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xb:
		instr.op = Op::SLTIU;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xc:
		instr.op = Op::ANDI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xd:
		instr.op = Op::ORI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xe:
		instr.op = Op::XORI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xf:
		instr.op = Op::LUI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x20:
		instr.op = Op::LB;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x21:
		instr.op = Op::LH;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x22:
		instr.op = Op::LWL;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x23:
		instr.op = Op::LW;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x24:
		instr.op = Op::LBU;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x25:
		instr.op = Op::LHU;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x26:
		instr.op = Op::LWR;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x28:
		instr.op = Op::SB;
		instr.imm = imm16;
		break;

	case 0x29:
		instr.op = Op::SH;
		instr.imm = imm16;
		break;

	case 0x2a:
		instr.op = Op::SWL;
		instr.imm = imm16;
		break;

	case 0x2b:
		instr.op = Op::SW;
		instr.imm = imm16;
		break;

	case 0x2e:
		instr.op = Op::SWR;
		instr.imm = imm16;
		break;

	case 0x38:
		instr.op = Op::SC;
		instr.imm = imm16;
		break;

	case 0x30:
		instr.op = Op::LL;
		instr.imm = imm16;
		break;

	case 0x39:
		instr.op = Op::SWC1;
		instr.imm = imm16;
		break;

	case 0x31:
		instr.op = Op::LWC1;
		instr.imm = imm16;
		break;

	case 0x1f:
		if (low_op == 0x3b && rd == 29)
			instr.op = Op::RDHWR_TLS;
		break;

	default:
		break;
	}

	return instr;
}

}