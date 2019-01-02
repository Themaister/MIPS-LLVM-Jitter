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

	auto *ptr = builder->CreateConstInBoundsGEP1_64(arg, index, std::string("Reg") + std::to_string(index) + "Ptr");
	int_registers[index] = builder->CreateLoad(ptr, std::string("Reg") + std::to_string(index) + "Loaded");
	return int_registers[index];
}

void RegisterTracker::write_float(unsigned index, Value *value)
{
	if (index != 0)
	{
		float_registers[index] = value;
		dirty_float |= 1u << index;
	}
}

Value *RegisterTracker::read_float(unsigned index)
{
	if (float_registers[index])
		return float_registers[index];

	auto *ptr = builder->CreateConstInBoundsGEP1_64(arg, index + RegisterState::MaxIntegerRegisters,
	                                                std::string("FReg") + std::to_string(index) + "Ptr");
	float_registers[index] = builder->CreateLoad(ptr, std::string("FReg") + std::to_string(index) + "Loaded");
	return float_registers[index];
}

void RegisterTracker::flush()
{
	for (int i = 0; i < RegisterState::MaxIntegerRegisters; i++)
	{
		if (dirty_int & (1ull << i))
		{
			auto *ptr = builder->CreateConstInBoundsGEP1_64(arg, i, std::string("Reg") + std::to_string(i) + "Ptr");
			builder->CreateStore(int_registers[i], ptr);
		}
	}

	for (int i = 0; i < RegisterState::MaxFloatRegisters; i++)
	{
		if (dirty_float & (1ull << i))
		{
			auto *ptr = builder->CreateConstInBoundsGEP1_64(arg, i + RegisterState::MaxIntegerRegisters,
			                                                std::string("FReg") + std::to_string(i) + "Ptr");
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
	return std::string("Reg") + std::to_string(index) + "_";
}

std::string RegisterTracker::get_float_twine(unsigned index)
{
	return std::string("FReg") + std::to_string(index) + "_";
}
}