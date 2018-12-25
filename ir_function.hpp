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

	uint64_t preserve_registers = 0;
	uint64_t write_registers = 0;

	// For DirectBranch and SelectionBranch.
	Terminator terminator = Terminator::DirectBranch;
	Address static_address_targets[2] = {};
};

struct BlockMeta
{
	Block block;

	// Registers which must be flushed to memory before leaving the JIT-ed function (indirect or unwind).
	uint64_t dirty_registers = 0;
	uint64_t need_phi_node = 0;
	uint64_t child_preserve_registers = 0;

	// After leaving a block, each register might get a new instance of itself (SSA), so keep track of that here.
	uint32_t register_instance[MaxRegisters] = {};

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

	uint32_t get_instances_for_register(unsigned index) const;

private:
	BlockAnalysisBackend *backend = nullptr;
	std::unordered_map<Address, std::unique_ptr<BlockMeta>> block_map;
	std::vector<BlockMeta *> leaf_blocks;
	std::vector<BlockMeta *> visit_order;
	uint32_t register_instance[MaxRegisters] = {};

	BlockMeta *analyze_from_entry_inner(Address addr); // Map out all static execution paths from an address.
	void resolve_block(BlockMeta *meta);
	void reset();
};
}