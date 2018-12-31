#pragma once

#include "jitter.hpp"
#include "ir_function.hpp"

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

struct RegisterState
{
	enum { MaxIntegerRegisters = 64, MaxFloatRegisters = 64 };
	int32_t scalar_registers[MaxIntegerRegisters] = {};
	int32_t float_registers[MaxFloatRegisters] = {}; // Stored as raw 32-bit, rely on bitcast as needed.
};

class Recompiler
{
public:
	void set_backend(RecompilerBackend *backend);
	void set_jitter(Jitter *jitter);

	struct Result
	{
		Jitter::ModuleHandle handle;
		void (*call)(RegisterState *);
	};

	Result recompile_function(const Function &function);
	llvm::BasicBlock *get_block_for_address(Address addr);
	llvm::Function *get_current_function();
	llvm::Module *get_current_module();

private:
	RecompilerBackend *backend = nullptr;
	Jitter *jitter = nullptr;
	std::unordered_map<Address, llvm::BasicBlock *> address_to_basic_block;

	llvm::Module *module = nullptr;
	llvm::Function *function = nullptr;
};
}