#pragma once

#include "mips.hpp"

namespace JITTIR
{
bool mips_opcode_is_branch(Op op);
bool mips_opcode_ends_basic_block(Op op);
MIPSInstruction decode_mips_instruction(Address pc, uint32_t word);
}