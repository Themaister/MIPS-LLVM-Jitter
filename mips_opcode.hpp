#pragma once

#include <stdint.h>

namespace JITTIR
{
enum class Op
{
	Invalid,
	NOP,
	SLL,
	SRL,
	SRA,
	SLLV,
	SRLV,
	SRAV,
	JR,
	JALR,
	SYSCALL,
	BREAK,
	MFHI,
	MFLO,
	MTHI,
	MTLO,
	MULT,
	MULTU,
	DIV,
	DIVU,
	ADD,
	ADDU,
	SUB,
	SUBU,
	AND,
	OR,
	XOR,
	NOR,
	SLT,
	SLTU,
	BLTZ,
	BGEZ,
	BLTZAL,
	BGEZAL,
	J,
	JAL,
	BEQ,
	BNE,
	BLEZ,
	BGTZ,
	ADDI,
	ADDIU,
	SLTI,
	SLTIU,
	ANDI,
	ORI,
	XORI,
	LUI,
	LB,
	LH,
	LWL,
	LW,
	LBU,
	LHU,
	LWR,
	SB,
	SH,
	SWL,
	SW,
	SWR,

	LL,
	SC,
	LWC1,
	SWC1,
#if 0
	LWC0,
	LWC2,
	LWC3,
	SWC0,
	SWC2,
	SWC3,
	COP0,
	COP1,
	COP2,
	COP3,
#endif
	RDHWR_TLS,
	SYNC,
};

struct MIPSInstruction
{
	Op op;
	uint8_t rs, rt, rd;
	uint32_t imm;
};

bool mips_opcode_is_branch(Op op);
bool mips_opcode_ends_basic_block(Op op);
MIPSInstruction decode_mips_instruction(uint32_t pc, uint32_t word);
}