#include "ir_frontend.hpp"
#include <string.h>
#include <algorithm>

using namespace std;

namespace IR
{
void IRFrontend::set_backend(IR::Backend *backend)
{
	this->backend = backend;
}

void BlockMeta::add_pred(BlockMeta *block)
{
	if (find(begin(preds), end(preds), block) == end(preds))
		preds.push_back(block);
}

void IRFrontend::reset()
{
	block_map.clear();
	leaf_blocks.clear();
	memset(register_instance, 0, sizeof(register_instance));
}

void IRFrontend::analyze_from_entry(Address addr)
{
	reset();
	analyze_from_entry_inner(addr);
	for (auto *block : leaf_blocks)
		resolve_block(block);
}

void IRFrontend::resolve_block(BlockMeta *meta)
{
	if (meta->complete)
		return;

	for (auto *pred : meta->preds)
	{
		resolve_block(pred);
		meta->dirty_registers |= pred->dirty_registers;
	}

	// For each register we need to preserve into a block, check if we need a PHI node for it.
	// This is the case if not all the timestamps for a register is the same.
	// If we have a PHI node, make sure that we also mark the register as written, with its own timestamp.
	if (!meta->preds.empty())
	{
		for (int i = 0; i < MaxRegisters; i++)
		{
			if (meta->block.preserve_registers & (1ull << i))
			{
				bool same_instance = true;
				uint32_t instance = meta->preds.front()->register_instance[i];
				for (auto *pred : meta->preds)
				{
					if (pred == meta || pred->register_instance[i] != instance)
					{
						same_instance = false;
						break;
					}
				}

				if (!same_instance)
				{
					meta->need_phi_node |= 1ull << i;
					// Mark the phi node as a write.
					if (!(meta->block.write_registers & (1ull << i)))
					{
						meta->block.write_registers |= 1ull << i;
						meta->register_instance[i] = ++register_instance[i];
					}
				}
				else
				{
					// It's all the same instance, inherit this information.
					meta->register_instance[i] = instance;
				}
			}
		}
	}

	meta->complete = true;
}

BlockMeta *IRFrontend::analyze_from_entry_inner(Address addr)
{
	auto itr = block_map.find(addr);
	if (itr != end(block_map))
		return itr->second.get();

	auto meta = make_unique<BlockMeta>();
	backend->get_block_from_address(addr, meta->block);

	switch (meta->block.terminator)
	{
	case Terminator::DirectBranch:
	{
		auto *target = analyze_from_entry_inner(meta->block.static_address_targets[0]);
		target->add_pred(meta.get());
		meta->targets[0] = target;
		break;
	}

	case Terminator::SelectionBranch:
	{
		auto *pt = meta->targets;
		for (auto addr : meta->block.static_address_targets)
		{
			auto *target = analyze_from_entry_inner(addr);
			target->add_pred(meta.get());
			*pt++ = target;
		}
		break;
	}

	case Terminator::Unwind:
	case Terminator::IndirectBranch:
		// This will end any function. For indirect branches, we will return after all call if the leaf target returns.
		// For unwind we directly call longjmp and end our frame.
		leaf_blocks.push_back(meta.get());
		break;

	default:
		break;
	}

	return meta.get();
}
}