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
		const Block &block,
		llvm::BasicBlock *basic_block,
		llvm::Value *arg) = 0;
};

struct RegisterState
{
	int32_t scalar_registers[MaxRegisters] = {};
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

	void create_call(Address addr, Address expected_return);
	void create_call(llvm::Value *addr, Address expected_return);
	void create_jump_indirect(llvm::Value *addr);
	void create_store32(llvm::Value *addr, llvm::Value *value);
	void create_store16(llvm::Value *addr, llvm::Value *value);
	void create_store8(llvm::Value *addr, llvm::Value *value);
	llvm::Value *create_load32(llvm::Value *addr);
	llvm::Value *create_load16(llvm::Value *addr);
	llvm::Value *create_load8(llvm::Value *addr);

	// Helpers which build various LLVM instructions.

private:
	RecompilerBackend *backend = nullptr;
	Jitter *jitter = nullptr;
	std::unordered_map<Address, llvm::BasicBlock *> address_to_basic_block;

	struct
	{
		llvm::Function *store32 = nullptr;
		llvm::Function *store16 = nullptr;
		llvm::Function *store8 = nullptr;
		llvm::Function *load32 = nullptr;
		llvm::Function *load16 = nullptr;
		llvm::Function *load8 = nullptr;
		llvm::Function *call = nullptr;
		llvm::Function *jump_indirect = nullptr;
	} calls;
	llvm::Value *argument = nullptr;
	llvm::BasicBlock *bb = nullptr;
	llvm::Module *module = nullptr;
};
}