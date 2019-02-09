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

uint32_t __recompiler_lwl_be(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t old_value);
uint32_t __recompiler_lwr_be(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t old_value);
void __recompiler_swl_be(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t value);
void __recompiler_swr_be(JITTIR::VirtualMachineState *regs, JITTIR::Address addr, uint32_t value);

void __recompiler_step(JITTIR::VirtualMachineState *regs);
void __recompiler_step_after(JITTIR::VirtualMachineState *regs);
}
