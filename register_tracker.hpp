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
	void write_float(unsigned index, llvm::Value *value);
	llvm::Value *read_float(unsigned index);
	void flush();
	void invalidate();
	std::string get_twine(unsigned index);
	std::string get_float_twine(unsigned index);

private:
	llvm::IRBuilder<> *builder = nullptr;
	llvm::Value *arg;
	llvm::Value *int_registers[RegisterState::MaxIntegerRegisters] = {};
	llvm::Value *float_registers[RegisterState::MaxFloatRegisters] = {};
	uint64_t dirty_int = 0;
	uint64_t dirty_float = 0;
};

}