/* Copyright (c) 2018-2019 Hans-Kristian Arntzen
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

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
	TailCall, // DirectBranch can be promoted to a TailCall to avoid unbounded inlining.
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

	const std::vector<Block *> &get_visit_order() const
	{
		return visit_order;
	}

private:
	BlockAnalysisBackend *backend = nullptr;
	std::unordered_map<Address, std::unique_ptr<Block>> block_map;
	std::vector<Block *> visit_order;
	Address entry_addr = 0;

	void analyze_from_entry_inner(Address addr); // Map out all static execution paths from an address.
	void reset();
};
}
