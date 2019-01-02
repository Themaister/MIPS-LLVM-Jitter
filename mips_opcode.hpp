#pragma once

#include "mips.hpp"

namespace JITTIR
{
bool mips_opcode_is_branch(Op op);
bool mips_opcode_ends_basic_block(Op op);
}