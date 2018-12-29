#include "ir_recompile.hpp"
#include "llvm/IR/Verifier.h"

using namespace std;

namespace JITTIR
{
void Recompiler::set_backend(RecompilerBackend *backend)
{
	this->backend = backend;
}

void Recompiler::set_jitter(Jitter *jitter)
{
	this->jitter = jitter;
}

llvm::BasicBlock *Recompiler::get_block_for_address(Address addr)
{
	return address_to_basic_block.find(addr)->second;
}

llvm::Function *Recompiler::get_current_function()
{
	return function;
}

llvm::Module *Recompiler::get_current_module()
{
	return module;
}

Recompiler::Result Recompiler::recompile_function(const Function &function)
{
	auto &visit_order = function.get_visit_order();

	auto module = jitter->create_module(to_string(visit_order.front()->block.block_start));
	this->module = module.get();
	auto &ctx = module->getContext();

	// Create our function.
	llvm::Type *types[1] = { llvm::Type::getInt32PtrTy(ctx) };
	auto *function_type = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), types, false);
	auto *func = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
	                                    to_string(visit_order.front()->block.block_start),
	                                    module.get());
	auto *argument = &func->args().begin()[0];
	this->function = func;

	// Allocate basic blocks.
	vector<llvm::BasicBlock *> basic_blocks;
	basic_blocks.reserve(visit_order.size());
	address_to_basic_block.clear();

	for (auto &order : visit_order)
	{
		auto *block = llvm::BasicBlock::Create(ctx, to_string(order->block.block_start), func);
		basic_blocks.push_back(block);
		address_to_basic_block[order->block.block_start] = block;
	}

	size_t count = visit_order.size();
	for (size_t i = 0; i < count; i++)
	{
		auto &meta_block = *visit_order[i];
		auto *bb = basic_blocks[i];
		backend->recompile_basic_block(meta_block.block.block_start, meta_block.block.block_end,
		                               this, meta_block.block, bb, argument);
	}

	Result result = {};
	if (llvm::verifyFunction(*func, &llvm::errs()))
	{
		module->print(llvm::errs(), nullptr);
		return result;
	}

	result.handle = jitter->add_module(move(module));
	result.call = (void (*)(RegisterState *))jitter->get_symbol_address(to_string(visit_order.front()->block.block_start));
	return result;
}
}