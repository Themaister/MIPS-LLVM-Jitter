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

Recompiler::Result Recompiler::recompile_function(const Function &function)
{
	auto &visit_order = function.get_visit_order();

	auto module = jitter->create_module(to_string(visit_order.front()->block.block_start));
	auto &ctx = module->getContext();

	// Create our function.
	llvm::Type *types[1] = { llvm::Type::getInt32PtrTy(ctx) };
	auto *function_type = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), types, false);
	auto *func = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
	                                    to_string(visit_order.front()->block.block_start),
	                                    module.get());
	auto *arg = &func->args().begin()[0];

	// Allocate basic blocks.
	vector<llvm::BasicBlock *> basic_blocks;
	basic_blocks.reserve(visit_order.size());
	address_to_basic_block.clear();
	llvm::BasicBlock *entry_block = llvm::BasicBlock::Create(ctx, "entry", func);

	// Allocate all instances of registers.
	RegisterInstances registers[MaxRegisters];
	for (unsigned i = 0; i < MaxRegisters; i++)
		registers[i].instances.resize(function.get_instances_for_register(i));


	// Load the registers we need to read from memory.
	auto &entry_meta_block = *visit_order.front();
	uint64_t loaded_registers = entry_meta_block.child_preserve_registers |
	                            entry_meta_block.block.preserve_registers;

	llvm::IRBuilder<> builder(entry_block);
	for (int i = 0; i < MaxRegisters; i++)
		if (loaded_registers & (1ull << i))
			registers[i].instances[0] = builder.CreateLoad(builder.CreateConstInBoundsGEP1_64(arg, i));

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

		llvm::IRBuilder<> builder(bb);
		llvm::PHINode *phis[MaxRegisters] = {}; // Cannot resolve PHI nodes until after we have built, just in case.
		// Build up the current register bank.
		llvm::Value *register_bank[MaxRegisters] = {};

		// Build PHI nodes if we need to.
		for (int r = 0; i < MaxRegisters; i++)
		{
			if (meta_block.need_phi_node & (1ull << r))
			{
				phis[r] = builder.CreatePHI(llvm::Type::getInt32Ty(ctx), meta_block.preds.size());
				registers[r].instances[meta_block.register_instance[r]] = phis[r];
			}

			register_bank[r] = registers[r].instances[meta_block.register_instance[r]];
		}

		backend->recompile_basic_block(meta_block.block.block_start, meta_block.block.block_end,
		                               this, bb, register_bank);

		// Flush back the register bank.
		for (int r = 0; i < MaxRegisters; i++)
			if (meta_block.register_instance[r] != 0)
				registers[r].instances[meta_block.register_instance[r]] = register_bank[r];

		// Update the PHI nodes with appropriate values.
		// Need to do this after building the basic block because we can have loop feedback.
		for (int r = 0; i < MaxRegisters; i++)
		{
			if (meta_block.need_phi_node & (1ull << r))
			{
				for (auto *pred : meta_block.preds)
				{
					llvm::Value *incoming_value = registers[r].instances[pred->register_instance[r]];
					llvm::BasicBlock *incoming_block = address_to_basic_block.find(meta_block.block.block_start)->second;
					phis[r]->addIncoming(incoming_value, incoming_block);
				}
			}
		}
	}

	Result result = {};
	if (!llvm::verifyFunction(*func, &llvm::errs()))
		return result;

	result.handle = jitter->add_module(move(module));
	result.call = (void (*)(void *))jitter->get_symbol_address(to_string(visit_order.front()->block.block_start));
	return result;
}
}