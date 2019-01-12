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
	case Op::BC1F:
	case Op::BC1T:
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
	case Op::BC1F:
	case Op::BC1T:
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

	case 0x1f:
		if (low_op == 0x3b && rd == 29)
			instr.op = Op::RDHWR_TLS;
		break;

	case 0x39:
		instr.op = Op::SWC1;
		instr.imm = imm16;
		break;

	case 0x31:
		instr.op = Op::LWC1;
		instr.imm = imm16;
		break;

	case 0x11:
	{
		// COP1 - floating point fun!
		uint8_t fmt = (word >> 21) & 31;
		uint8_t fd = (word >> 6) & 31;
		uint8_t fs = (word >> 11) & 31;
		uint8_t ft = (word >> 16) & 31;
		enum fmt { FMT_S = 16, FMT_D = 17, FMT_W = 20, FMT_L = 21 };
		enum fmt3 { FMT3_S = 0, FMT3_D = 1, FMT3_W = 4, FMT3_L = 5 };

		if (fmt == 8)
		{
			// Branch instructions.
			instr.imm = pc + 4 + int16_t(imm16) * 4;
			instr.op = (word & 0x10000) ? Op::BC1T : Op::BC1F;
			break;
		}

		instr.rt = ft;
		instr.rs = fs;
		instr.rd = fd;

		switch (low_op)
		{
		case 0:
			switch (fmt)
			{
			case 0:
				instr.op = Op::MFC1;
				break;

			case 2:
				instr.op = Op::CFC1;
				break;

			case 4:
				instr.op = Op::MTC1;
				break;

			case 6:
				instr.op = Op::CTC1;
				break;

			case FMT_S:
				instr.op = Op::ADD_F32;
				break;

			case FMT_D:
				instr.op = Op::ADD_F64;
				break;
			}
			break;

		case 0x01:
			instr.op = fmt == FMT_S ? Op::SUB_F32 : Op::SUB_F64;
			break;

		case 0x02:
			instr.op = fmt == FMT_S ? Op::MUL_F32 : Op::MUL_F64;
			break;

		case 0x03:
			instr.op = fmt == FMT_S ? Op::DIV_F32 : Op::DIV_F64;
			break;

		case 0x05:
			instr.op = fmt == FMT_S ? Op::ABS_F32 : Op::ABS_F64;
			break;

		case 0x06:
			instr.op = fmt == FMT_S ? Op::MOV_F32 : Op::MOV_F64;
			break;

		case 0x07:
			instr.op = fmt == FMT_S ? Op::NEG_F32 : Op::NEG_F64;
			break;

		case 0x21:
			if (fmt == FMT_S)
				instr.op = Op::CVT_F64_F32;
			else if (fmt == FMT_W)
				instr.op = Op::CVT_F64_I32;
			break;

		case 0x20:
			if (fmt == FMT_D)
				instr.op = Op::CVT_F32_F64;
			else if (fmt == FMT_W)
				instr.op = Op::CVT_F32_I32;
			break;

		case 0x24:
			if (fmt == FMT_S)
				instr.op = Op::CVT_I32_F32;
			else if (fmt == FMT_D)
				instr.op = Op::CVT_I32_F64;
			break;

		case 0x30:
		case 0x38:
			instr.op = fmt == FMT_S ? Op::COMP_F_F32 : Op::COMP_F_F64;
			break;

		case 0x31:
		case 0x39:
			instr.op = fmt == FMT_S ? Op::COMP_UN_F32 : Op::COMP_UN_F64;
			break;

		case 0x32:
		case 0x3a:
			instr.op = fmt == FMT_S ? Op::COMP_EQ_F32 : Op::COMP_EQ_F64;
			break;

		case 0x33:
		case 0x3b:
			instr.op = fmt == FMT_S ? Op::COMP_UEQ_F32 : Op::COMP_UEQ_F64;
			break;

		case 0x34:
		case 0x3c:
			instr.op = fmt == FMT_S ? Op::COMP_OLT_F32 : Op::COMP_OLT_F64;
			break;

		case 0x35:
		case 0x3d:
			instr.op = fmt == FMT_S ? Op::COMP_ULT_F32 : Op::COMP_ULT_F64;
			break;

		case 0x36:
		case 0x3e:
			instr.op = fmt == FMT_S ? Op::COMP_OLE_F32 : Op::COMP_OLE_F64;
			break;

		case 0x37:
		case 0x3f:
			instr.op = fmt == FMT_S ? Op::COMP_ULE_F32 : Op::COMP_ULE_F64;
			break;
		}
	}

	default:
		break;
	}

	return instr;
}

}