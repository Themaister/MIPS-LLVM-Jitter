#pragma once

#include "mips.hpp"
#include <stdint.h>

extern "C"
{
JITTIR::StubCallPtr __recompiler_call_addr(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, JITTIR::Address expected_addr);
void __recompiler_predict_return(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, JITTIR::Address expected_addr);
JITTIR::StubCallPtr __recompiler_jump_indirect(JITTIR::VirtualMachineState *regs, JITTIR::Address addr);
void __recompiler_store32(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t value);
void __recompiler_store16(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t value);
void __recompiler_store8(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t value);
uint32_t __recompiler_load32(JITTIR::VirtualMachineState *regs, JITTIR::Address addr);
uint16_t __recompiler_load16(JITTIR::VirtualMachineState *regs, JITTIR::Address addr);
uint8_t __recompiler_load8(JITTIR::VirtualMachineState *regs, JITTIR::Address addr);
void __recompiler_sigill(JITTIR::VirtualMachineState *regs, JITTIR::Address addr);
void __recompiler_break(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t code);
void __recompiler_syscall(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t code);
uint32_t __recompiler_lwl(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t old_value);
uint32_t __recompiler_lwr(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t old_value);
void __recompiler_swl(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t value);
void __recompiler_swr(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t value);
void __recompiler_step(JITTIR::VirtualMachineState *regs);
void __recompiler_step_after(JITTIR::VirtualMachineState *regs);
}