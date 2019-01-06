#include "elf.hpp"

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

VirtualAddressSpace::VirtualAddressSpace()
{
	pages.resize(1u << (32 - 12));
}

void *VirtualAddressSpace::get_page(uint32_t page) const
{
	return pages[page];
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
	for (uint32_t i = 0; i < size; i++, dst++, data++)
	{
		auto *page = static_cast<uint8_t *>(get_page(dst / PageSize));
		page[dst & (PageSize - 1)] = *data;
	}
}

void VirtualAddressSpace::copy_from_user(void *data_, uint32_t src, uint32_t size)
{
	auto *data = static_cast<uint8_t *>(data_);
	for (uint32_t i = 0; i < size; i++, src++, data++)
	{
		auto *page = static_cast<const uint8_t *>(get_page(src / PageSize));
		*data = page[src & (PageSize - 1)];
	}
}

bool VirtualAddressSpace::unmap_memory(uint32_t addr, uint32_t length)
{
	uint32_t page = addr / PageSize;
	uint32_t num_pages = (length + PageSize - 1) & ~(PageSize - 1);
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

	return true;
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

	// Cannot decrement the data segment.
	if (end == 0 || end <= current_end)
		return current_end;

	uint32_t mapped = map_memory(end - current_end, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!mapped)
		return current_end;

	current_end = (last_page + 1) * PageSize;
	return current_end;
}

bool load_elf(const char *path, Elf32_Ehdr &ehdr_output, VirtualAddressSpace &addr_space,
              SymbolTable &symbol_table, int32_t &tls_base,
              uint32_t &phdr_addr)
{
	tls_base = 0;

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

	auto *ehdr = reinterpret_cast<const Elf32_Ehdr *>(mapped);
	ehdr_output = *ehdr;
	static const uint8_t elf_ident[] = {
		127, 69, 76, 70,
	};

	if (memcmp(ehdr->e_ident, elf_ident, sizeof(elf_ident)) != 0)
		return false;

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32)
		return false;
	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
		return false;
	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT)
		return false;
	if (ehdr->e_type != ET_EXEC)
		return false;
	if (ehdr->e_machine != EM_MIPS)
		return false;
	if (ehdr->e_version != EV_CURRENT)
		return false;

	uint32_t ph_table = ehdr->e_phoff;
	uint32_t ph_size = ehdr->e_phentsize;
	uint32_t ph_num = ehdr->e_phnum;

	if (ph_table + ph_num * ph_size > s.st_size)
		return false;

	for (uint32_t i = 0; i < ph_num; i++)
	{
		auto *phdr = reinterpret_cast<const Elf32_Phdr *>(mapped + ph_table + i * ph_size);
		auto type = phdr->p_type;
		auto offset = phdr->p_offset;
		auto vaddr = phdr->p_vaddr;
		auto file_size = phdr->p_filesz;
		auto memory_size = phdr->p_memsz;
		auto flags = phdr->p_flags;
		auto align = phdr->p_align;
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
			if (file_size == memory_size) // We can map the file directly.
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
				uint32_t copy_offset = vaddr - begin_memory_segment;
				page = static_cast<uint8_t *>(mmap(nullptr, end_memory_segment - begin_memory_segment,
				                                   prot | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
				if (page == MAP_FAILED)
					return 1;

				// Fill in the section partially.
				memcpy(page + copy_offset, mapped + offset, file_size);

				// Disable writes.
				if ((prot & PROT_WRITE) == 0)
					mprotect(page, end_memory_segment - begin_memory_segment, prot);

				for (uint32_t addr = begin_memory_segment; addr < end_memory_segment; addr += VirtualAddressSpace::PageSize)
					addr_space.set_page(addr / VirtualAddressSpace::PageSize, page + (addr - begin_memory_segment));
			}
		}
		else if (type == PT_TLS && memory_size != 0)
		{
			// Load TLS.
			uint32_t tls = addr_space.map_memory(phdr->p_memsz, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			tls_base = tls;
			addr_space.copy_to_user(tls, mapped + phdr->p_offset, phdr->p_filesz);
		}
	}

	// Copy PHDR data to virtual address space so we can pass it in AUXV (for musl).
	uint32_t phdr_size = ph_num * ph_size;
	phdr_addr = addr_space.map_memory(phdr_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	addr_space.copy_to_user(phdr_addr, mapped + ehdr->e_phoff, phdr_size);

	uint32_t sh_table = ehdr->e_shoff;
	uint32_t sh_size = ehdr->e_shentsize;
	uint32_t sh_num = ehdr->e_shnum;

	// Read the symbols.
	for (uint32_t i = 0; i < sh_num; i++)
	{
		auto *shdr = reinterpret_cast<const Elf32_Shdr *>(mapped + sh_table + i * sh_size);
		if (shdr->sh_type != SHT_SYMTAB)
			continue;

		unsigned entries = shdr->sh_size / shdr->sh_entsize;
		uint32_t base_addr = shdr->sh_offset;

		for (unsigned e = 0; e < entries; e++)
		{
			uint32_t string_section = shdr->sh_link;
			const char *strings = nullptr;
			if (string_section != SHN_UNDEF)
			{
				strings =
					reinterpret_cast<const char *>(
						mapped + reinterpret_cast<const Elf32_Shdr *>(mapped + sh_table + string_section * sh_size)->sh_offset);
			}

			const auto *sym = reinterpret_cast<const Elf32_Sym *>(mapped + base_addr + e * shdr->sh_entsize);
			int binding = ELF32_ST_BIND(sym->st_info);
			if (binding != STB_GLOBAL)
				continue;

			if (sym->st_name == SHN_UNDEF)
				continue;

			const char *name = strings + sym->st_name;
			symbol_table.symbol_to_address.emplace(name, sym->st_value);
			symbol_table.address_to_symbol.emplace(sym->st_value, name);
		}
	}

	munmap(const_cast<uint8_t *>(mapped), size_t(s.st_size));
	return true;
}

}