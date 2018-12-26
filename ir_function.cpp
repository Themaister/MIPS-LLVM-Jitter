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
}

void Function::analyze_from_entry(Address addr)
{
	reset();
	analyze_from_entry_inner(addr);
	for (auto *block : leaf_blocks)
		resolve_block(block);
}

void Function::resolve_block(BlockMeta *meta)
{
	if (meta->resolve_complete)
		return;
	meta->resolve_complete = true;

	for (auto *pred : meta->preds)
		resolve_block(pred);

	visit_order.push_back(meta);
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