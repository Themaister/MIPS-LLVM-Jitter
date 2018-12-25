#pragma once

#include "jitter.hpp"
#include "ir_function.hpp"

namespace JITTIR
{
struct RegisterInstances
{
	std::vector<llvm::Value *> instances;
};

class Recompiler;

class RecompilerBackend
{
public:
	virtual ~RecompilerBackend() = default;
	virtual void recompile_basic_block(
		Address start_addr, Address end_addr,
		Recompiler *recompiler,
		llvm::BasicBlock *basic_block,
		llvm::Value **registers) = 0;
};

class Recompiler
{
public:
	void set_backend(RecompilerBackend *backend);
	void set_jitter(Jitter *jitter);

	struct Result
	{
		Jitter::ModuleHandle handle;
		void (*call)(void *);
	};

	Result recompile_function(const Function &function);

	// Helpers which build various LLVM instructions.

private:
	RecompilerBackend *backend = nullptr;
	Jitter *jitter = nullptr;

	std::unordered_map<Address, llvm::BasicBlock *> address_to_basic_block;
};
}