#pragma once
#include <unordered_map>
#include <vector>
#include <memory>
#include <stdint.h>

namespace JITTIR
{
using Address = uint32_t;
enum
{
	MaxRegisters = 64
};

enum class Terminator
{
	DirectBranch, // Direct jump to static address.
	SelectionBranch, // Branches to one of two possible addresses.
	IndirectBranch, // Branches to register. Return also goes here since it might return to unpredictable location.
	Unwind // Should immediately flush registers and unwind its stack to top frame (SJLJ-style).
};

struct Block
{
	Address block_start = 0; // First instruction.
	Address block_end = 0; // Address past last executed instruction.

	// For DirectBranch and SelectionBranch.
	Terminator terminator = Terminator::DirectBranch;
	Address static_address_targets[2] = {};
};

struct BlockMeta
{
	Block block;

	void add_pred(BlockMeta *block);
	std::vector<BlockMeta *> preds;
	BlockMeta *targets[2] = {};
	bool resolve_complete = false;
};

class BlockAnalysisBackend
{
public:
	virtual ~BlockAnalysisBackend() = default;
	virtual void get_block_from_address(Address addr, Block &block) = 0;
};

class Function
{
public:
	void set_backend(BlockAnalysisBackend *backend);
	void analyze_from_entry(Address addr); // Map out all static execution paths from an address.

	const std::vector<BlockMeta *> &get_visit_order() const
	{
		return visit_order;
	}

private:
	BlockAnalysisBackend *backend = nullptr;
	std::unordered_map<Address, std::unique_ptr<BlockMeta>> block_map;
	std::vector<BlockMeta *> leaf_blocks;
	std::vector<BlockMeta *> visit_order;

	BlockMeta *analyze_from_entry_inner(Address addr); // Map out all static execution paths from an address.
	void resolve_block(BlockMeta *meta);
	void reset();
};
}