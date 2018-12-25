#include "ir_function.hpp"
#include <string.h>
#include <algorithm>

using namespace std;

namespace JITTIR
{
void Function::set_backend(BlockAnalysisBackend *backend)
{
	this->backend = backend;
}

void BlockMeta::add_pred(BlockMeta *block)
{
	if (find(begin(preds), end(preds), block) == end(preds))
		preds.push_back(block);
}

void Function::reset()
{
	block_map.clear();
	leaf_blocks.clear();
	visit_order.clear();
	memset(register_instance, 0, sizeof(register_instance));
}

void Function::analyze_from_entry(Address addr)
{
	reset();
	analyze_from_entry_inner(addr);
	for (auto *block : leaf_blocks)
		resolve_block(block);
	;
}

void Function::resolve_block(BlockMeta *meta)
{
	if (meta->resolve_complete)
		return;
	meta->resolve_complete = true;

	for (auto *pred : meta->preds)
	{
		// If we need to preserve registers somehow, all call paths into our block must also preserve.
		// Distinguish between preserved registers (actual read), and transient reads (read only by children later).
		pred->child_preserve_registers |= meta->block.preserve_registers | meta->child_preserve_registers;

		resolve_block(pred);

		// All call path writes to any register must be flushed.
		meta->dirty_registers |= pred->dirty_registers;
	}

	visit_order.push_back(meta);

	// For each register we need to preserve into a block, check if we need a PHI node for it.
	// This is the case if not all the timestamps for a register is the same.
	// If we have a PHI node, make sure that we also mark the register as written, with its own timestamp.
	if (!meta->preds.empty())
	{
		for (int i = 0; i < MaxRegisters; i++)
		{
			if ((meta->block.preserve_registers | meta->child_preserve_registers) & (1ull << i))
			{
				bool same_instance = true;
				uint32_t instance = meta->preds.front()->output_register_instance[i];
				for (auto *pred : meta->preds)
				{
					// If we get the same instance, and we write to the value in this block,
					// we know we have a feedback scenario, and we need a PHI node.
					bool feedback =
						(meta->block.preserve_registers & (1ull << i)) != 0 &&
						pred->output_register_instance[i] == instance &&
						(meta->block.write_registers & (1ull << i)) != 0;

					if (feedback || pred->output_register_instance[i] != instance)
					{
						same_instance = false;
						break;
					}
				}

				if (!same_instance)
				{
					meta->need_phi_node |= 1ull << i;
					meta->input_register_instance[i] = ++register_instance[i];
					// Mark the phi node as a write.
					meta->block.write_registers |= 1ull << i;
				}
				else
				{
					// It's all the same instance, inherit this information.
					meta->input_register_instance[i] = instance;
					meta->output_register_instance[i] = instance;
				}
			}

			if (meta->block.write_registers & (1ull << i))
				meta->output_register_instance[i] = ++register_instance[i];
		}
	}
}

uint32_t Function::get_instances_for_register(unsigned index) const
{
	return register_instance[index] + 1;
}

BlockMeta *Function::analyze_from_entry_inner(Address addr)
{
	auto itr = block_map.find(addr);
	if (itr != end(block_map))
		return itr->second.get();

	auto meta_ = make_unique<BlockMeta>();
	auto *meta = meta_.get();
	block_map[addr] = move(meta_);
	backend->get_block_from_address(addr, meta->block);
	meta->dirty_registers = meta->block.write_registers;

	switch (meta->block.terminator)
	{
	case Terminator::DirectBranch:
	{
		auto *target = analyze_from_entry_inner(meta->block.static_address_targets[0]);
		target->add_pred(meta);
		meta->targets[0] = target;
		break;
	}

	case Terminator::SelectionBranch:
	{
		auto *pt = meta->targets;
		for (auto target_addr : meta->block.static_address_targets)
		{
			auto *target = analyze_from_entry_inner(target_addr);
			target->add_pred(meta);
			*pt++ = target;
		}
		break;
	}

	case Terminator::Unwind:
	case Terminator::IndirectBranch:
	{
		// This will end any function. For indirect branches, we will return after all call if the leaf target returns.
		// For unwind we directly call longjmp and end our frame.
		leaf_blocks.push_back(meta);
		break;
	}

	default:
		break;
	}

	return meta;
}
}