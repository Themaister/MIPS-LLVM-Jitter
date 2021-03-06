/* Copyright (c) 2018-2019 Hans-Kristian Arntzen
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

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
	RDHWR_TLS,
	SYNC,

	// COP1
	LWC1,
	SWC1,
	BC1F,
	BC1T,
	COMP_F_F32,
	COMP_F_F64,
	COMP_UN_F32,
	COMP_UN_F64,
	COMP_EQ_F32,
	COMP_EQ_F64,
	COMP_UEQ_F32,
	COMP_UEQ_F64,
	COMP_OLT_F32,
	COMP_OLT_F64,
	COMP_ULT_F32,
	COMP_ULT_F64,
	COMP_OLE_F32,
	COMP_OLE_F64,
	COMP_ULE_F32,
	COMP_ULE_F64,
	CFC1,
	CTC1,
	MFC1,
	MTC1,
	CVT_F64_F32,
	CVT_F64_I32,
	CVT_F32_F64,
	CVT_F32_I32,
	CVT_I32_F32,
	CVT_I32_F64,
	ABS_F32,
	ABS_F64,
	ADD_F32,
	ADD_F64,
	DIV_F32,
	DIV_F64,
	MOV_F32,
	MOV_F64,
	MUL_F32,
	MUL_F64,
	NEG_F32,
	NEG_F64,
	SUB_F32,
	SUB_F64,
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
