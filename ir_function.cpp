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

	for (auto *order : visit_order)
	{
		if (order->terminator == Terminator::TailCall) // Check if a jump was actually a direct branch after all.
			if (block_map.count(order->static_address_targets[0]))
				order->terminator = Terminator::DirectBranch;
	}
}

void Function::analyze_from_entry_inner(Address addr)
{
	auto itr = block_map.find(addr);
	if (itr != end(block_map))
		return;

	//fprintf(stderr, "  Adding basic block 0x%x\n", addr);

	auto meta_ = make_unique<Block>();
	auto *meta = meta_.get();
	block_map[addr] = move(meta_);
	backend->get_block_from_address(addr, *meta);

	visit_order.push_back(meta);

	switch (meta->terminator)
	{
	case Terminator::DirectBranch:
	{
		// If we have a direct branch we can either have a tail call or a branch to a block (stays in the function).
		// Use a really trivial heuristic here. If we have a basic block for this address, use it, otherwise, make a tail call.
		if (!block_map.count(meta->static_address_targets[0]))
			meta->terminator = Terminator::TailCall;
		break;
	}

	case Terminator::SelectionBranch:
	{
		for (auto target_addr : meta->static_address_targets)
			analyze_from_entry_inner(target_addr);
		break;
	}

	default:
		break;
	}
}
}