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

void Function::reset()
{
	block_map.clear();
	visit_order.clear();
}

void Function::set_entry_address(Address addr)
{
	entry_addr = addr;
}

void Function::analyze_from_entry()
{
	reset();
	analyze_from_entry_inner(entry_addr);
}

BlockMeta *Function::analyze_from_entry_inner(Address addr)
{
	auto itr = block_map.find(addr);
	if (itr != end(block_map))
		return itr->second.get();

	//fprintf(stderr, "  Adding basic block 0x%x\n", addr);

	auto meta_ = make_unique<BlockMeta>();
	auto *meta = meta_.get();
	block_map[addr] = move(meta_);
	backend->get_block_from_address(addr, meta->block);

	visit_order.push_back(meta);

	switch (meta->block.terminator)
	{
	case Terminator::DirectBranch:
	{
		auto *target = analyze_from_entry_inner(meta->block.static_address_targets[0]);
		meta->targets[0] = target;
		break;
	}

	case Terminator::SelectionBranch:
	{
		auto *pt = meta->targets;
		for (auto target_addr : meta->block.static_address_targets)
		{
			auto *target = analyze_from_entry_inner(target_addr);
			*pt++ = target;
		}
		break;
	}

	default:
		break;
	}

	return meta;
}
}