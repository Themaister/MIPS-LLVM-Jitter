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

#include <elf.h>
#include <unordered_map>
#include <vector>

namespace JITTIR
{
class VirtualAddressSpace
{
public:
	enum { PageSize = 0x1000, PageSizeLog2 = 12, PageCount = 1u << (32 - PageSizeLog2) };
	void set_page(uint32_t page, void *data);

	uint32_t brk(uint32_t addr);
	uint32_t map_memory(uint32_t size, int prot, int flags, int fd, int off);
	bool unmap_memory(uint32_t addr, uint32_t length);
	uint32_t realloc_memory(uint32_t old_addr, uint32_t old_size, uint32_t new_size);
	uint32_t allocate_stack(uint32_t size);

	void copy_to_user(uint32_t dst, const void *data, uint32_t size);
	void copy_from_user(void *data, uint32_t src, uint32_t size);

	uint32_t get_brk() const
	{
		return brk_page * PageSize;
	}

	inline void *get_page(uint32_t page) const
	{
		return pages[page];
	}

	void set_pages(void **pages)
	{
		this->pages = pages;
	}

	void set_big_endian(bool enable)
	{
		big_endian = enable;
	}

private:
	void **pages;
	uint32_t last_page = 1;
	uint32_t first_page = UINT32_MAX / PageSize;
	uint32_t brk_page = 0;
	bool big_endian = false;
};

struct SymbolTable
{
	std::unordered_map<std::string, uint32_t> symbol_to_address;
	std::unordered_map<uint32_t, std::string> address_to_symbol;
};

struct ElfMiscData
{
	int32_t tls_base = 0;
	uint32_t phdr_addr = 0;
	bool big_endian = false;
};

bool load_elf(const char *path, Elf32_Ehdr &ehdr_output,
              VirtualAddressSpace &addr_space,
              SymbolTable &symbol_table,
              ElfMiscData &misc);
}
