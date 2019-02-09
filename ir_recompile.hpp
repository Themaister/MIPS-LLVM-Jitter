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

#include "jitter.hpp"
#include "ir_function.hpp"
#include "linuxvm.hpp"

namespace JITTIR
{
class Recompiler;

class RecompilerBackend
{
public:
	virtual ~RecompilerBackend() = default;
	virtual void recompile_basic_block(
		Address start_addr, Address end_addr,
		Recompiler *recompiler,
		const Block &block,
		llvm::BasicBlock *basic_block,
		llvm::Value *arg) = 0;
};

struct VirtualMachineState
{
	enum { MaxIntegerRegisters = 64, MaxFloatRegisters = 64 };
	int32_t scalar_registers[MaxIntegerRegisters] = {};
	int32_t float_registers[MaxFloatRegisters] = {}; // Stored as raw 32-bit, rely on bitcast as needed.
	void *virtual_pages[VirtualAddressSpace::PageCount] = {};
};

class Recompiler
{
public:
	void set_backend(RecompilerBackend *backend);
	void set_jitter(Jitter *jitter);

	struct Result
	{
		Jitter::ModuleHandle handle;
		void (*call)(VirtualMachineState *);
		llvm::Function *function;
	};

	explicit Recompiler(std::unordered_map<Address, void (*)(VirtualMachineState *)> *blocks_)
		: blocks(blocks_)
	{
	}

	Result recompile_function(Function &function, llvm::Module *target_module = nullptr, llvm::Type *argument_type = nullptr);
	llvm::BasicBlock *get_block_for_address(Address addr);
	llvm::Function *get_current_function();
	llvm::Module *get_current_module();

private:
	RecompilerBackend *backend = nullptr;
	Jitter *jitter = nullptr;
	std::unordered_map<Address, llvm::BasicBlock *> address_to_basic_block;

	llvm::Module *module = nullptr;
	llvm::Function *function = nullptr;

	std::unordered_map<Address, void (*)(VirtualMachineState *)> *blocks;
};
}
