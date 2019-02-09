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

using namespace JITTIR;

extern "C"
{
StubCallPtr __recompiler_call_addr(VirtualMachineState *regs, Address addr, Address expected_addr)
{
	return static_cast<MIPS *>(regs)->call_addr(addr, expected_addr);
}

void __recompiler_predict_return(VirtualMachineState *regs, Address addr, Address expected_addr)
{
	static_cast<MIPS *>(regs)->predict_return(addr, expected_addr);
}

StubCallPtr __recompiler_jump_indirect(VirtualMachineState *regs, Address addr)
{
	return static_cast<MIPS *>(regs)->jump_addr(addr);
}

void __recompiler_store32(VirtualMachineState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->store32(addr, value);
}

void __recompiler_store16(VirtualMachineState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->store16(addr, value);
}

void __recompiler_store8(VirtualMachineState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->store8(addr, value);
}

uint32_t __recompiler_load32(VirtualMachineState *regs, Address addr)
{
	return static_cast<MIPS *>(regs)->load32(addr);
}

uint16_t __recompiler_load16(VirtualMachineState *regs, Address addr)
{
	return static_cast<MIPS *>(regs)->load16(addr);
}

uint8_t __recompiler_load8(VirtualMachineState *regs, Address addr)
{
	return static_cast<MIPS *>(regs)->load8(addr);
}

void __recompiler_sigill(VirtualMachineState *regs, Address addr)
{
	static_cast<MIPS *>(regs)->sigill(addr);
}

void __recompiler_break(VirtualMachineState *regs, Address addr, uint32_t code)
{
	static_cast<MIPS *>(regs)->op_break(addr, code);
}

void __recompiler_syscall(VirtualMachineState *regs, Address addr, uint32_t code)
{
	static_cast<MIPS *>(regs)->op_syscall(addr, code);
}

uint32_t __recompiler_lwl(VirtualMachineState *regs, Address addr, uint32_t old_value)
{
	return static_cast<MIPS *>(regs)->lwl(addr, old_value);
}

uint32_t __recompiler_lwr(VirtualMachineState *regs, Address addr, uint32_t old_value)
{
	return static_cast<MIPS *>(regs)->lwr(addr, old_value);
}

void __recompiler_swl(VirtualMachineState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->swl(addr, value);
}

void __recompiler_swr(VirtualMachineState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->swr(addr, value);
}

uint32_t __recompiler_lwl_be(VirtualMachineState *regs, Address addr, uint32_t old_value)
{
	return static_cast<MIPS *>(regs)->lwl_be(addr, old_value);
}

uint32_t __recompiler_lwr_be(VirtualMachineState *regs, Address addr, uint32_t old_value)
{
	return static_cast<MIPS *>(regs)->lwr_be(addr, old_value);
}

void __recompiler_swl_be(VirtualMachineState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->swl_be(addr, value);
}

void __recompiler_swr_be(VirtualMachineState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->swr_be(addr, value);
}

void __recompiler_step(VirtualMachineState *regs)
{
	static_cast<MIPS *>(regs)->step();
}

void __recompiler_step_after(VirtualMachineState *regs)
{
	static_cast<MIPS *>(regs)->step_after();
}
}
