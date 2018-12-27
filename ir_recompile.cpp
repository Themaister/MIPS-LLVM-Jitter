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

void Recompiler::create_call(Address addr)
{
	llvm::IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.call)
	{
		llvm::Type *types[] = { llvm::Type::getInt32PtrTy(ctx), llvm::Type::getInt32Ty(ctx) };
		auto *function_type = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), types, false);
		calls.call = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
		                                    "__recompiler_call_addr", module);
	}

	llvm::Value *values[] = { argument, llvm::ConstantInt::get(llvm::Type::getInt32Ty(builder.getContext()), addr) };
	builder.CreateCall(calls.call, values);
}

void Recompiler::create_jump_indirect(llvm::Value *value)
{
	llvm::IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.jump_indirect)
	{
		llvm::Type *types[] = { llvm::Type::getInt32PtrTy(ctx), llvm::Type::getInt32Ty(ctx) };
		auto *function_type = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), types, false);
		calls.jump_indirect = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
		                                             "__recompiler_jump_indirect", module);
	}

	llvm::Value *values[] = { argument, value };
	builder.CreateCall(calls.jump_indirect, values);
}

void Recompiler::create_store32(llvm::Value *addr, llvm::Value *value)
{
	llvm::IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.store32)
	{
		llvm::Type *store_types[] = { llvm::Type::getInt32PtrTy(ctx), llvm::Type::getInt32Ty(ctx), llvm::Type::getInt32Ty(ctx) };
		auto *store_type = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), store_types, false);
		calls.store32 = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                       "__recompiler_store32", module);
	}

	llvm::Value *values[] = { argument, addr, value };
	builder.CreateCall(calls.store32, values);
}

void Recompiler::create_store16(llvm::Value *addr, llvm::Value *value)
{
	llvm::IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.store16)
	{
		llvm::Type *store_types[] = { llvm::Type::getInt32PtrTy(ctx), llvm::Type::getInt32Ty(ctx), llvm::Type::getInt32Ty(ctx) };
		auto *store_type = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), store_types, false);
		calls.store16 = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                       "__recompiler_store16", module);
	}

	llvm::Value *values[] = { argument, addr, value };
	builder.CreateCall(calls.store16, values);
}

void Recompiler::create_store8(llvm::Value *addr, llvm::Value *value)
{
	llvm::IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.store8)
	{
		llvm::Type *store_types[] = { llvm::Type::getInt32PtrTy(ctx), llvm::Type::getInt32Ty(ctx), llvm::Type::getInt32Ty(ctx) };
		auto *store_type = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), store_types, false);
		calls.store8 = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_store8", module);
	}

	llvm::Value *values[] = { argument, addr, value };
	builder.CreateCall(calls.store8, values);
}

llvm::Value *Recompiler::create_load32(llvm::Value *addr)
{
	llvm::IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.load32)
	{
		llvm::Type *load_types[] = {llvm::Type::getInt32PtrTy(ctx), llvm::Type::getInt32Ty(ctx)};
		auto *load_type = llvm::FunctionType::get(llvm::Type::getInt32Ty(ctx), load_types, false);
		calls.load32 = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_load32", module);
	}

	llvm::Value *values[] = { argument, addr };
	return builder.CreateCall(calls.load32, values);
}

llvm::Value *Recompiler::create_load16(llvm::Value *addr)
{
	llvm::IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.load16)
	{
		llvm::Type *load_types[] = {llvm::Type::getInt32PtrTy(ctx), llvm::Type::getInt32Ty(ctx)};
		auto *load_type = llvm::FunctionType::get(llvm::Type::getInt16Ty(ctx), load_types, false);
		calls.load16 = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_load16", module);
	}

	llvm::Value *values[] = { argument, addr };
	return builder.CreateCall(calls.load16, values);
}

llvm::Value *Recompiler::create_load8(llvm::Value *addr)
{
	llvm::IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.load8)
	{
		llvm::Type *load_types[] = {llvm::Type::getInt32PtrTy(ctx), llvm::Type::getInt32Ty(ctx)};
		auto *load_type = llvm::FunctionType::get(llvm::Type::getInt8Ty(ctx), load_types, false);
		calls.load8 = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                     "__recompiler_load8", module);
	}

	llvm::Value *values[] = { argument, addr };
	return builder.CreateCall(calls.load8, values);
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
	argument = &func->args().begin()[0];

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

	calls = {};

	size_t count = visit_order.size();
	for (size_t i = 0; i < count; i++)
	{
		auto &meta_block = *visit_order[i];
		bb = basic_blocks[i];
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
	result.call = (void (*)(void *))jitter->get_symbol_address(to_string(visit_order.front()->block.block_start));
	return result;
}
}