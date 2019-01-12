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
	auto itr = address_to_basic_block.find(addr);
	if (itr != end(address_to_basic_block))
		return itr->second;
	else
		return nullptr;
}

llvm::Function *Recompiler::get_current_function()
{
	return function;
}

llvm::Module *Recompiler::get_current_module()
{
	return module;
}

Recompiler::Result Recompiler::recompile_function(Function &function, llvm::Module *target_module, llvm::Type *argument_type)
{
	unique_ptr<llvm::Module> module_;
	if (target_module)
		this->module = target_module;
	else
	{
		module_ = jitter->create_module(to_string(function.get_entry_address()));
		this->module = module_.get();
	}
	auto &ctx = module->getContext();
	auto entry_symbol = string("_") + to_string(function.get_entry_address());

	if (target_module)
	{
		// Do we have this function already in our module? Just return it.
		for (auto &f : *target_module)
		{
			if (entry_symbol == f.getName())
			{
				Recompiler::Result result = {};
				result.function = &f;
				return result;
			}
		}
	}

	// Create our function.
	if (!argument_type)
	{
		auto *int_register_array = llvm::ArrayType::get(llvm::Type::getInt32Ty(ctx),
		                                                VirtualMachineState::MaxIntegerRegisters);
		auto *float_register_array = llvm::ArrayType::get(llvm::Type::getInt32Ty(ctx),
		                                                  VirtualMachineState::MaxFloatRegisters);
		auto *page_array = llvm::ArrayType::get(llvm::PointerType::get(llvm::Type::getVoidTy(ctx), 0),
		                                        VirtualAddressSpace::PageCount);
		llvm::Type *struct_types[] = { int_register_array, float_register_array, page_array };
		argument_type = llvm::StructType::create(struct_types);
		argument_type = llvm::PointerType::get(argument_type, 0);
	}

	llvm::Type *types[] = { argument_type };
	auto *func_type = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), types, false);
	auto *func = llvm::Function::Create(func_type, llvm::Function::ExternalLinkage,
	                                    entry_symbol,
	                                    module);

	if (target_module)
	{
		// Do we have the block in the JIT cache? Then we can rely on linking.
		// If we don't do anything, it is declared as an extern void func(); which needs to be linked by Jitter later.
		auto external_symbol = jitter->find_symbol(entry_symbol);
		if (cantFail(external_symbol.getAddress()) != 0)
		{
			Recompiler::Result result = {};
			result.function = func;
			return result;
		}
	}

	// Lazily analyze.
	function.analyze_from_entry();
	auto &visit_order = function.get_visit_order();

	auto *argument = &func->args().begin()[0];
	this->function = func;

	// Allocate basic blocks.
	vector<llvm::BasicBlock *> basic_blocks;
	basic_blocks.reserve(visit_order.size());
	address_to_basic_block.clear();

	auto *entry_bb = llvm::BasicBlock::Create(ctx, "entry", func);

	for (auto &order : visit_order)
	{
		auto *block = llvm::BasicBlock::Create(ctx, to_string(order->block_start), func);
		basic_blocks.push_back(block);
		address_to_basic_block[order->block_start] = block;
	}

	llvm::BranchInst::Create(address_to_basic_block[function.get_entry_address()], entry_bb);

	size_t count = visit_order.size();
	for (size_t i = 0; i < count; i++)
	{
		auto &meta_block = *visit_order[i];
		auto *bb = basic_blocks[i];
		backend->recompile_basic_block(meta_block.block_start, meta_block.block_end,
		                               this, meta_block, bb, argument);
	}

	Result result = {};
	if (llvm::verifyFunction(*func, &llvm::errs()))
	{
		module->print(llvm::errs(), nullptr);
		return result;
	}

	// If we are creating a new module, compile and update symbols here.
	if (module_)
	{
		vector<string> symbols;
		for (auto &f : *this->module)
		{
			// Skip any builtin symbols.
			if (f.getName().substr(0, 2) == "__")
				continue;
			symbols.push_back(f.getName());
		}
		result.handle = jitter->add_module(move(module_));

		for (auto &name : symbols)
		{
			auto symbol = (void (*)(VirtualMachineState *)) jitter->get_symbol_address(name);
			name.erase(begin(name));
			blocks->emplace(Address(stoull(name)), symbol);
		}

		result.call = (void (*)(VirtualMachineState *)) jitter->get_symbol_address(entry_symbol);
	}

	result.function = func;
	return result;
}
}
