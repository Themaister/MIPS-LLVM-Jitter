#pragma once

#include <elf.h>
#include <unordered_map>
#include <vector>

namespace JITTIR
{
class VirtualAddressSpace
{
public:
	enum { PageSize = 0x1000 };
	VirtualAddressSpace();
	void set_page(uint32_t page, void *data);
	void *get_page(uint32_t page) const;

	uint32_t sbrk(uint32_t size);
	uint32_t allocate_stack(uint32_t size);

private:
	std::vector<void *> pages;
	uint32_t last_page = 1;
	uint32_t first_page = UINT32_MAX / PageSize;
};

using SymbolTable = std::unordered_map<std::string, uint32_t>;

bool load_elf(const char *path, Elf32_Ehdr &ehdr_output,
              VirtualAddressSpace &addr_space,
              SymbolTable &symbol_table,
              int32_t &tls_base);
}
