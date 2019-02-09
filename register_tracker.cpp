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

#include "register_tracker.hpp"

using namespace llvm;

namespace JITTIR
{
RegisterTracker::RegisterTracker(Value *arg_)
		: arg(arg_)
{
}

void RegisterTracker::set_builder(IRBuilder<> *builder_)
{
	builder = builder_;
}

Value *RegisterTracker::get_argument()
{
	return arg;
}

void RegisterTracker::write_int(unsigned index, Value *value)
{
	if (index != 0)
	{
		int_registers[index] = value;
		dirty_int |= 1ull << index;
	}
}

Value *RegisterTracker::read_int(unsigned index)
{
	if (index == 0)
		return ConstantInt::get(Type::getInt32Ty(builder->getContext()), 0);

	if (int_registers[index])
		return int_registers[index];

	auto &ctx = builder->getContext();
	Value *indices[] = {
		ConstantInt::get(Type::getInt32Ty(ctx), 0),
		ConstantInt::get(Type::getInt32Ty(ctx), 0),
		ConstantInt::get(Type::getInt32Ty(ctx), index),
	};

	auto *ptr = builder->CreateInBoundsGEP(arg, indices, std::string(get_scalar_register_name(index)) + "Ptr");
	int_registers[index] = builder->CreateLoad(ptr, std::string(get_scalar_register_name(index)) + "Loaded");
	return int_registers[index];
}

void RegisterTracker::write_fp_w(unsigned index, Value *value)
{
	assert(value);
	float_registers[index] = value;
	dirty_float |= 1ull << index;
}

Value *RegisterTracker::read_fp_w(unsigned index)
{
	if (float_registers[index])
		return float_registers[index];

	auto &ctx = builder->getContext();
	Value *indices[] = {
		ConstantInt::get(Type::getInt32Ty(ctx), 0),
		ConstantInt::get(Type::getInt32Ty(ctx), 1),
		ConstantInt::get(Type::getInt32Ty(ctx), index),
	};

	auto *ptr = builder->CreateInBoundsGEP(arg, indices, std::string("FReg") + std::to_string(index) + "Ptr");
	float_registers[index] = builder->CreateLoad(ptr, std::string("FReg") + std::to_string(index) + "Loaded");
	return float_registers[index];
}

void RegisterTracker::write_fp_s(unsigned index, Value *value)
{
	assert(value);
	auto &ctx = builder->getContext();
	auto *word = builder->CreateBitCast(value, Type::getInt32Ty(ctx), "SToWBitCast");
	write_fp_w(index, word);
}

void RegisterTracker::write_fp_l(unsigned index, Value *dword)
{
	assert(dword);
	auto &ctx = builder->getContext();
	index &= ~1;
	write_fp_w(index, builder->CreateTrunc(dword, Type::getInt32Ty(ctx), "TruncTo32Lo"));
	write_fp_w(index + 1, builder->CreateTrunc(builder->CreateLShr(dword, ConstantInt::get(Type::getInt64Ty(ctx), 32)), Type::getInt32Ty(builder->getContext()), "TruncTo32Hi"));
}

void RegisterTracker::write_fp_d(unsigned index, Value *value)
{
	assert(value);
	auto &ctx = builder->getContext();
	auto *dword = builder->CreateBitCast(value, Type::getInt64Ty(ctx), "SToWBitCast");
	write_fp_l(index, dword);
}

Value *RegisterTracker::read_fp_s(unsigned index)
{
	auto &ctx = builder->getContext();
	auto *word = read_fp_w(index);
	auto *fp32 = builder->CreateBitCast(word, Type::getFloatTy(ctx), "WToSBitCast");
	return fp32;
}

Value *RegisterTracker::read_fp_l(unsigned index)
{
	auto &ctx = builder->getContext();
	index &= ~1;
	auto *word_lo = read_fp_w(index);
	auto *word_hi = read_fp_w(index + 1);
	word_lo = builder->CreateZExt(word_lo, Type::getInt64Ty(ctx), "ZExtTo64Lo");
	word_hi = builder->CreateZExt(word_hi, Type::getInt64Ty(ctx), "ZExtTo64Hi");
	word_hi = builder->CreateShl(word_hi, ConstantInt::get(Type::getInt64Ty(ctx), 32), "ShlHi");
	auto *dword = builder->CreateOr(word_lo, word_hi, "FP64Combine");
	return dword;
}

Value *RegisterTracker::read_fp_d(unsigned index)
{
	auto &ctx = builder->getContext();
	auto *dword = read_fp_l(index);
	auto *fp64 = builder->CreateBitCast(dword, Type::getDoubleTy(ctx), "DWordToFP64BitCast");
	return fp64;
}

void RegisterTracker::flush()
{
	auto &ctx = builder->getContext();

	for (int i = 0; i < VirtualMachineState::MaxIntegerRegisters; i++)
	{
		if (dirty_int & (1ull << i))
		{
			Value *indices[] = {
				ConstantInt::get(Type::getInt32Ty(ctx), 0),
				ConstantInt::get(Type::getInt32Ty(ctx), 0),
				ConstantInt::get(Type::getInt32Ty(ctx), i),
			};

			auto *ptr = builder->CreateInBoundsGEP(arg, indices, std::string(get_scalar_register_name(i)) + "Ptr");
			builder->CreateStore(int_registers[i], ptr);
		}
	}

	for (int i = 0; i < VirtualMachineState::MaxFloatRegisters; i++)
	{
		if (dirty_float & (1ull << i))
		{
			Value *indices[] = {
				ConstantInt::get(Type::getInt32Ty(ctx), 0),
				ConstantInt::get(Type::getInt32Ty(ctx), 1),
				ConstantInt::get(Type::getInt32Ty(ctx), i),
			};

			auto *ptr = builder->CreateInBoundsGEP(arg, indices, std::string("FReg") + std::to_string(i) + "Ptr");
			builder->CreateStore(float_registers[i], ptr);
		}
	}

	dirty_int = 0;
	dirty_float = 0;
}

void RegisterTracker::invalidate()
{
	memset(int_registers, 0, sizeof(int_registers));
	memset(float_registers, 0, sizeof(float_registers));
}

std::string RegisterTracker::get_twine(unsigned index)
{
	return get_scalar_register_name(index);
}

std::string RegisterTracker::get_float_twine(unsigned index)
{
	return std::string("FReg") + std::to_string(index) + "_";
}
}
