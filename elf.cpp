#include "elf.hpp"

#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <functional>

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
}

bool load_elf(const char *path, Elf32_Ehdr &ehdr_output, VirtualAddressSpace &addr_space,
              std::unordered_map<std::string, uint32_t> &symbol_table)
{
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
	}

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
			symbol_table.emplace(name, sym->st_value);
		}
	}

	munmap(const_cast<uint8_t *>(mapped), size_t(s.st_size));
	return true;
}

}