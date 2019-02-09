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
#include "mips.hpp"

namespace JITTIR
{
class RegisterTracker
{
public:
	RegisterTracker(llvm::Value *arg_);

	void set_builder(llvm::IRBuilder<> *builder_);
	llvm::Value *get_argument();
	void write_int(unsigned index, llvm::Value *value);
	llvm::Value *read_int(unsigned index);

	void write_fp_s(unsigned index, llvm::Value *value);
	void write_fp_d(unsigned index, llvm::Value *value);
	void write_fp_w(unsigned index, llvm::Value *value);
	void write_fp_l(unsigned index, llvm::Value *value);
	llvm::Value *read_fp_s(unsigned index);
	llvm::Value *read_fp_d(unsigned index);
	llvm::Value *read_fp_w(unsigned index);
	llvm::Value *read_fp_l(unsigned index);

	void flush();
	void invalidate();
	std::string get_twine(unsigned index);
	std::string get_float_twine(unsigned index);

private:
	llvm::IRBuilder<> *builder = nullptr;
	llvm::Value *arg;
	llvm::Value *int_registers[VirtualMachineState::MaxIntegerRegisters] = {};
	llvm::Value *float_registers[VirtualMachineState::MaxFloatRegisters] = {};
	uint64_t dirty_int = 0;
	uint64_t dirty_float = 0;
};

}
