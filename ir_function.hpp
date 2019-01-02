#pragma once
#include <unordered_map>
#include <vector>
#include <memory>
#include <stdint.h>

namespace JITTIR
{
using Address = uint32_t;

enum class Terminator
{
	DirectBranch, // Direct jump to static address.
	SelectionBranch, // Branches to one of two possible addresses.
	Exit // Ends function.
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
	BlockMeta *targets[2] = {};
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
	void analyze_from_entry(); // Map out all static execution paths from an address.
	void set_entry_address(Address addr);

	Address get_entry_address() const
	{
		return entry_addr;
	}

	const std::vector<BlockMeta *> &get_visit_order() const
	{
		return visit_order;
	}

private:
	BlockAnalysisBackend *backend = nullptr;
	std::unordered_map<Address, std::unique_ptr<BlockMeta>> block_map;
	std::vector<BlockMeta *> visit_order;
	Address entry_addr = 0;

	BlockMeta *analyze_from_entry_inner(Address addr); // Map out all static execution paths from an address.
	void reset();
};
}