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

#include "linuxvm.hpp"

#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <functional>
#include <elf.h>

namespace JITTIR
{
class OnExit
{
public:
	explicit OnExit(std::function<void ()> func)
		: func(std::move(func))
	{
	}

	~OnExit()
	{
		if (func)
			func();
	}

private:
	std::function<void ()> func;
};

static uint32_t flip_bytes(uint32_t v)
{
	return (v >> 24) |
	       (v << 24) |
	       ((v >> 8) & 0x0000ff00u) |
	       ((v << 8) & 0x00ff0000u);
}

void VirtualAddressSpace::set_page(uint32_t page, void *data)
{
	pages[page] = data;
	if (page < first_page)
		first_page = page;
	if (page > last_page)
		last_page = page;
}

uint32_t VirtualAddressSpace::allocate_stack(uint32_t size)
{
	uint32_t pages = (size + PageSize - 1) / PageSize;
	uint32_t start = UINT32_MAX / PageSize - pages;
	auto *mapped = static_cast<uint8_t *>(mmap(nullptr, size,
	                                           PROT_READ | PROT_WRITE,
	                                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));

	if (mapped == MAP_FAILED)
		return 0;

	auto old_last_page = last_page;
	for (uint32_t i = 0; i < pages; i++)
		set_page(start + i, mapped + i * PageSize);
	last_page = old_last_page;

	return start * PageSize;
}

void VirtualAddressSpace::copy_to_user(uint32_t dst, const void *data_, uint32_t size)
{
	auto *data = static_cast<const uint8_t *>(data_);

	if (big_endian)
	{
		for (uint32_t i = 0; i < size; i++, dst++, data++)
		{
			auto *page = static_cast<uint8_t *>(get_page(dst / PageSize));
			page[(dst & (PageSize - 1)) ^ 3] = *data;
		}
	}
	else
	{
		for (uint32_t i = 0; i < size; i++, dst++, data++)
		{
			auto *page = static_cast<uint8_t *>(get_page(dst / PageSize));
			page[dst & (PageSize - 1)] = *data;
		}
	}
}

void VirtualAddressSpace::copy_from_user(void *data_, uint32_t src, uint32_t size)
{
	auto *data = static_cast<uint8_t *>(data_);

	if (big_endian)
	{
		for (uint32_t i = 0; i < size; i++, src++, data++)
		{
			auto *page = static_cast<const uint8_t *>(get_page(src / PageSize));
			*data = page[(src & (PageSize - 1)) ^ 3];
		}
	}
	else
	{
		for (uint32_t i = 0; i < size; i++, src++, data++)
		{
			auto *page = static_cast<const uint8_t *>(get_page(src / PageSize));
			*data = page[src & (PageSize - 1)];
		}
	}
}

bool VirtualAddressSpace::unmap_memory(uint32_t addr, uint32_t length)
{
	uint32_t page = addr / PageSize;
	uint32_t num_pages = (length + PageSize - 1) / PageSize;
	for (uint32_t i = 0; i < num_pages; i++)
		if (!get_page(page + i))
			return false;

	for (uint32_t i = 0; i < num_pages; i++)
	{
		// Is this legal? Could just null out the pages instead and avoid the unmap.
		if (munmap(pages[page + i], PageSize) < 0)
			return false;
		pages[page + i] = nullptr;
	}

	if (page + num_pages == last_page + 1)
		last_page = page - 1;

	return true;
}

uint32_t VirtualAddressSpace::realloc_memory(uint32_t old_addr, uint32_t old_size, uint32_t new_size)
{
	uint32_t page = old_addr / PageSize;
	uint32_t old_pages = (old_size + PageSize - 1) / PageSize;
	uint32_t new_pages = (new_size + PageSize - 1) / PageSize;
	uint32_t avail_pages = UINT32_MAX / PageSize - last_page;

	if (avail_pages < new_pages)
		return 0;

	auto *mapped = static_cast<uint8_t *>(mmap(nullptr, (new_pages - old_pages) * PageSize,
	                                           PROT_READ | PROT_WRITE,
	                                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
	if (!mapped)
		return 0;

	// Copy old pages.
	uint32_t start = last_page + 1;
	for (uint32_t i = 0; i < old_pages; i++)
		set_page(start + i, get_page(page + i));

	// Allocate new pages.
	for (uint32_t i = old_pages; i < new_pages; i++, mapped += PageSize)
		set_page(start + i, mapped);

	return start * PageSize;
}

uint32_t VirtualAddressSpace::map_memory(uint32_t size, int prot, int flags, int fd, int off)
{
	size = (size + PageSize - 1) & ~(PageSize - 1); // Align to page.

	uint32_t pages = (size + PageSize - 1) / PageSize;
	uint32_t avail_pages = UINT32_MAX / PageSize - last_page;
	if (avail_pages < pages)
		return 0;

	auto *mapped = static_cast<uint8_t *>(mmap(nullptr, size,
	                                           prot & ~PROT_EXEC,
	                                           flags, fd, off));

	if (mapped == MAP_FAILED)
		return 0;

	uint32_t start = last_page + 1;
	for (uint32_t i = 0; i < pages; i++)
		set_page(start + i, mapped + i * PageSize);

	return start * PageSize;
}

uint32_t VirtualAddressSpace::brk(uint32_t end)
{
	uint32_t current_end = (last_page + 1) * PageSize;

	if (end == 0)
	{
		// Last observed brk.
		brk_page = last_page + 1;
	}

	// Cannot decrement the data segment.
	if (end == 0 || end <= current_end)
		return current_end;

	// Check if we can actually allocate any longer with brk.
	uint32_t end_page = end / PageSize;
	for (uint32_t p = brk_page; p < end_page; p++)
		if (get_page(p))
			return current_end;

	uint32_t mapped = map_memory(end - current_end, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!mapped)
		return current_end;

	current_end = (last_page + 1) * PageSize;
	return current_end;
}

static void flip_endian(uint16_t &v)
{
	v = (v << 8) | (v >> 8);
}

static void flip_endian(uint32_t &v)
{
	v = flip_bytes(v);
}

bool load_elf(const char *path, Elf32_Ehdr &ehdr_output, VirtualAddressSpace &addr_space,
              SymbolTable &symbol_table, ElfMiscData &misc)
{
	misc.tls_base = 0;

	// Load a very simple MIPS32 little-endian ELF file.
	int fd = open(path, O_RDONLY);
	OnExit close_fd([fd]() {
		if (fd >= 0)
			close(fd);
	});

	if (fd < 0)
		return false;

	struct stat s;
	if (fstat(fd, &s) < 0)
		return false;

	auto *mapped = static_cast<const uint8_t *>(mmap(nullptr, size_t(s.st_size), PROT_READ, MAP_PRIVATE, fd, 0));
	if (mapped == MAP_FAILED)
		return false;

	if (size_t(s.st_size) < sizeof(Elf32_Ehdr))
		return false;

	auto ehdr = *reinterpret_cast<const Elf32_Ehdr *>(mapped);
	static const uint8_t elf_ident[] = {
		127, 69, 76, 70,
	};

	if (memcmp(ehdr.e_ident, elf_ident, sizeof(elf_ident)) != 0)
		return false;

	if (ehdr.e_ident[EI_CLASS] != ELFCLASS32)
		return false;
	if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB && ehdr.e_ident[EI_DATA] != ELFDATA2MSB)
		return false;

	misc.big_endian = ehdr.e_ident[EI_DATA] == ELFDATA2MSB;

	if (misc.big_endian)
	{
		addr_space.set_big_endian(true);
		flip_endian(ehdr.e_type);
		flip_endian(ehdr.e_machine);
		flip_endian(ehdr.e_version);
		flip_endian(ehdr.e_phoff);
		flip_endian(ehdr.e_phentsize);
		flip_endian(ehdr.e_phnum);
		flip_endian(ehdr.e_ehsize);
		flip_endian(ehdr.e_shstrndx);
		flip_endian(ehdr.e_shnum);
		flip_endian(ehdr.e_shoff);
		flip_endian(ehdr.e_shentsize);
		flip_endian(ehdr.e_entry);
	}

	ehdr_output = ehdr;

	if (ehdr.e_ident[EI_VERSION] != EV_CURRENT)
		return false;
	if (ehdr.e_type != ET_EXEC)
		return false;
	if (ehdr.e_machine != EM_MIPS)
		return false;
	if (ehdr.e_version != EV_CURRENT)
		return false;

	uint32_t ph_table = ehdr.e_phoff;
	uint32_t ph_size = ehdr.e_phentsize;
	uint32_t ph_num = ehdr.e_phnum;

	if (ph_table + ph_num * ph_size > s.st_size)
		return false;

	for (uint32_t i = 0; i < ph_num; i++)
	{
		auto phdr = *reinterpret_cast<const Elf32_Phdr *>(mapped + ph_table + i * ph_size);

		if (misc.big_endian)
		{
			flip_endian(phdr.p_filesz);
			flip_endian(phdr.p_offset);
			flip_endian(phdr.p_memsz);
			flip_endian(phdr.p_align);
			flip_endian(phdr.p_paddr);
			flip_endian(phdr.p_vaddr);
			flip_endian(phdr.p_flags);
			flip_endian(phdr.p_type);
		}

		auto type = phdr.p_type;
		auto offset = phdr.p_offset;
		auto vaddr = phdr.p_vaddr;
		auto file_size = phdr.p_filesz;
		auto memory_size = phdr.p_memsz;
		auto flags = phdr.p_flags;
		auto align = phdr.p_align;
		if (align == 0)
			align = 1;

		if (type == PT_LOAD && memory_size != 0)
		{
			if (align < uint32_t(getpagesize()) || align < VirtualAddressSpace::PageSize)
				return 1;

			int prot = 0;
			//if (flags & PF_X)
			//	prot |= PROT_EXEC;
			if (flags & PF_R)
				prot |= PROT_READ;
			if (flags & PF_W)
				prot |= PROT_WRITE;

			uint8_t *page = nullptr;
			if (file_size == memory_size && !misc.big_endian) // We can map the file directly.
			{
				uint32_t end_file_segment = offset + file_size;
				uint32_t begin_file_segment = offset & ~(align - 1);
				uint32_t end_memory_segment = vaddr + memory_size;
				uint32_t begin_memory_segment = vaddr & ~(align - 1);

				page = static_cast<uint8_t *>(mmap(nullptr, end_file_segment - begin_file_segment,
				                                   prot, MAP_PRIVATE, fd, begin_file_segment));
				if (page == MAP_FAILED)
					return 1;

				for (uint32_t addr = begin_memory_segment; addr < end_memory_segment; addr += VirtualAddressSpace::PageSize)
					addr_space.set_page(addr / VirtualAddressSpace::PageSize, page + (addr - begin_memory_segment));
			}
			else // Partial. Just copy.
			{
				uint32_t end_memory_segment = vaddr + memory_size;
				uint32_t begin_memory_segment = vaddr & ~(align - 1);
				page = static_cast<uint8_t *>(mmap(nullptr, end_memory_segment - begin_memory_segment,
				                                   prot | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
				if (page == MAP_FAILED)
					return 1;

				for (uint32_t addr = begin_memory_segment; addr < end_memory_segment; addr += VirtualAddressSpace::PageSize)
					addr_space.set_page(addr / VirtualAddressSpace::PageSize, page + (addr - begin_memory_segment));

				addr_space.copy_to_user(vaddr, mapped + offset, file_size);

				// Disable writes.
				if ((prot & PROT_WRITE) == 0)
					mprotect(page, end_memory_segment - begin_memory_segment, prot);
			}
		}
		else if (type == PT_TLS && memory_size != 0)
		{
			// Load TLS.
			uint32_t tls = addr_space.map_memory(phdr.p_memsz, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			misc.tls_base = tls;
			addr_space.copy_to_user(tls, mapped + phdr.p_offset, phdr.p_filesz);
		}
	}

	// Copy PHDR data to virtual address space so we can pass it in AUXV (for musl).
	uint32_t phdr_size = ph_num * ph_size;
	misc.phdr_addr = addr_space.map_memory(phdr_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	addr_space.copy_to_user(misc.phdr_addr, mapped + ehdr.e_phoff, phdr_size);

	uint32_t sh_table = ehdr.e_shoff;
	uint32_t sh_size = ehdr.e_shentsize;
	uint32_t sh_num = ehdr.e_shnum;

	// Read the symbols.
	for (uint32_t i = 0; i < sh_num; i++)
	{
		auto shdr = *reinterpret_cast<const Elf32_Shdr *>(mapped + sh_table + i * sh_size);

		if (misc.big_endian)
		{
			flip_endian(shdr.sh_addr);
			flip_endian(shdr.sh_addralign);
			flip_endian(shdr.sh_entsize);
			flip_endian(shdr.sh_flags);
			flip_endian(shdr.sh_info);
			flip_endian(shdr.sh_link);
			flip_endian(shdr.sh_name);
			flip_endian(shdr.sh_offset);
			flip_endian(shdr.sh_size);
			flip_endian(shdr.sh_type);
		}

		if (shdr.sh_type != SHT_SYMTAB)
			continue;

		unsigned entries = shdr.sh_size / shdr.sh_entsize;
		uint32_t base_addr = shdr.sh_offset;

		for (unsigned e = 0; e < entries; e++)
		{
			uint32_t string_section = shdr.sh_link;
			const char *strings = nullptr;
			if (string_section != SHN_UNDEF)
			{
				auto sh_offset = reinterpret_cast<const Elf32_Shdr *>(mapped + sh_table + string_section * sh_size)->sh_offset;
				if (misc.big_endian)
					flip_endian(sh_offset);

				strings = reinterpret_cast<const char *>(mapped + sh_offset);
			}

			auto sym = *reinterpret_cast<const Elf32_Sym *>(mapped + base_addr + e * shdr.sh_entsize);

			if (misc.big_endian)
			{
				flip_endian(sym.st_name);
				flip_endian(sym.st_shndx);
				flip_endian(sym.st_value);
				flip_endian(sym.st_size);
			}

			int binding = ELF32_ST_BIND(sym.st_info);
			if (binding != STB_GLOBAL)
				continue;

			if (sym.st_name == SHN_UNDEF)
				continue;

			const char *name = strings + sym.st_name;
			symbol_table.symbol_to_address.emplace(name, sym.st_value);
			symbol_table.address_to_symbol.emplace(sym.st_value, name);
		}
	}

	munmap(const_cast<uint8_t *>(mapped), size_t(s.st_size));
	return true;
}

}
