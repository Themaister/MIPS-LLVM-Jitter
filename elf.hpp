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
	uint32_t map_memory(uint32_t size, int prot, int flags, int fd, int off);
	uint32_t allocate_stack(uint32_t size);

	void copy(uint32_t dst, const void *data, uint32_t size);

private:
	std::vector<void *> pages;
	uint32_t last_page = 1;
	uint32_t first_page = UINT32_MAX / PageSize;
};

struct SymbolTable
{
	std::unordered_map<std::string, uint32_t> symbol_to_address;
	std::unordered_map<uint32_t, std::string> address_to_symbol;
};

bool load_elf(const char *path, Elf32_Ehdr &ehdr_output,
              VirtualAddressSpace &addr_space,
              SymbolTable &symbol_table,
              int32_t &tls_base, uint32_t &phr_addr);
}
