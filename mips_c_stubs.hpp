#pragma once

#include "mips.hpp"
#include <stdint.h>

extern "C"
{
JITTIR::StubCallPtr __recompiler_call_addr(JITTIR::RegisterState *regs, JITTIR::Address addr, JITTIR::Address expected_addr);
void __recompiler_predict_return(JITTIR::RegisterState *regs, JITTIR::Address addr, JITTIR::Address expected_addr);
JITTIR::StubCallPtr __recompiler_jump_indirect(JITTIR::RegisterState *regs, JITTIR::Address addr);
void __recompiler_store32(JITTIR::RegisterState *regs, JITTIR::Address addr, uint32_t value);
void __recompiler_store16(JITTIR::RegisterState *regs, JITTIR::Address addr, uint32_t value);
void __recompiler_store8(JITTIR::RegisterState *regs, JITTIR::Address addr, uint32_t value);
uint32_t __recompiler_load32(JITTIR::RegisterState *regs, JITTIR::Address addr);
uint16_t __recompiler_load16(JITTIR::RegisterState *regs, JITTIR::Address addr);
uint8_t __recompiler_load8(JITTIR::RegisterState *regs, JITTIR::Address addr);
void __recompiler_sigill(JITTIR::RegisterState *regs, JITTIR::Address addr);
void __recompiler_break(JITTIR::RegisterState *regs, JITTIR::Address addr, uint32_t code);
void __recompiler_syscall(JITTIR::RegisterState *regs, JITTIR::Address addr, uint32_t code);
uint32_t __recompiler_lwl(JITTIR::RegisterState *regs, JITTIR::Address addr, uint32_t old_value);
uint32_t __recompiler_lwr(JITTIR::RegisterState *regs, JITTIR::Address addr, uint32_t old_value);
void __recompiler_swl(JITTIR::RegisterState *regs, JITTIR::Address addr, uint32_t value);
void __recompiler_swr(JITTIR::RegisterState *regs, JITTIR::Address addr, uint32_t value);
void __recompiler_step(JITTIR::RegisterState *regs);
void __recompiler_step_after(JITTIR::RegisterState *regs);
}