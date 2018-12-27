#include <elf.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <unistd.h>
#include <string.h>
#include <memory>
#include <vector>
#include "ir_function.hpp"
#include "ir_recompile.hpp"
#include "jitter.hpp"

using namespace JITTIR;
using namespace llvm;

class VirtualAddressSpace
{
public:
	enum { PageSize = 0x1000 };
	VirtualAddressSpace();
	void set_page(uint32_t page, void *data);
	void *get_page(uint32_t page) const;

private:
	std::vector<void *> pages;
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

static bool load_elf(const char *path, Elf32_Ehdr &ehdr_output, VirtualAddressSpace &addr_space)
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
			if (flags & PF_X)
				prot |= PROT_EXEC;
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

				for (uint32_t addr = begin_memory_segment; addr < end_memory_segment; addr += VirtualAddressSpace::PageSize)
					addr_space.set_page(addr / VirtualAddressSpace::PageSize, page + (addr - begin_memory_segment));
			}
		}
	}

	munmap(const_cast<uint8_t *>(mapped), size_t(s.st_size));
	return true;
}

using StubCallPtr = void (*)(RegisterState *);
extern "C"
{
static StubCallPtr backend_call_addr(RegisterState *regs, Address addr, Address expected_addr);
static StubCallPtr backend_jump_addr(RegisterState *regs, Address addr);
static void backend_store32(RegisterState *regs, Address addr, uint32_t value);
static void backend_store16(RegisterState *regs, Address addr, uint32_t value);
static void backend_store8(RegisterState *regs, Address addr, uint32_t value);
static uint32_t backend_load32(RegisterState *regs, Address addr);
static uint16_t backend_load16(RegisterState *regs, Address addr);
static uint8_t backend_load8(RegisterState *regs, Address addr);
}

class MIPS : public JITTIR::RegisterState, public JITTIR::RecompilerBackend, public JITTIR::BlockAnalysisBackend
{
public:
	MIPS();
	VirtualAddressSpace &get_address_space();

	void store32(Address addr, uint32_t value) noexcept;
	void store16(Address addr, uint32_t value) noexcept;
	void store8(Address addr, uint32_t value) noexcept;
	uint32_t load32(Address addr) const noexcept;
	uint16_t load16(Address addr) const noexcept;
	uint8_t load8(Address addr) const noexcept;
	Address enter(Address addr) noexcept;
	StubCallPtr call_addr(Address addr, Address expected_addr) noexcept;
	StubCallPtr jump_addr(Address addr) noexcept;

	enum { ExitTooDeepStack = 1, ExitTooDeepJumpStack = 2 };

private:
	VirtualAddressSpace addr_space;

	void get_block_from_address(Address addr,
	                            Block &block) override;

	void recompile_basic_block(
		Address start_addr, Address end_addr,
		Recompiler *recompiler, const Block &block, BasicBlock *bb, Value *args) override;

	Jitter jitter;
	std::unordered_map<Address, JITTIR::Recompiler::Result> blocks;
	jmp_buf jump_buffer;
	Address return_stack[1024];
	unsigned return_stack_count = 0;
	unsigned stack_depth = 0;
	Address exit_pc = 0;

	StubCallPtr call(Address addr) noexcept;
};

extern "C"
{
static StubCallPtr backend_call_addr(RegisterState *regs, Address addr, Address expected_addr)
{
	return static_cast<MIPS *>(regs)->call_addr(addr, expected_addr);
}

static StubCallPtr backend_jump_addr(RegisterState *regs, Address addr)
{
	return static_cast<MIPS *>(regs)->jump_addr(addr);
}

static void backend_store32(RegisterState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->store32(addr, value);
}

static void backend_store16(RegisterState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->store16(addr, value);
}

static void backend_store8(RegisterState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->store8(addr, value);
}

static uint32_t backend_load32(RegisterState *regs, Address addr)
{
	return static_cast<MIPS *>(regs)->load32(addr);
}

static uint16_t backend_load16(RegisterState *regs, Address addr)
{
	return static_cast<MIPS *>(regs)->load16(addr);
}

static uint8_t backend_load8(RegisterState *regs, Address addr)
{
	return static_cast<MIPS *>(regs)->load8(addr);
}
}

MIPS::MIPS()
{
	jitter.add_external_symbol("__recompiler_call_addr", backend_call_addr);
	jitter.add_external_symbol("__recompiler_jump_indirect", backend_jump_addr);
	jitter.add_external_symbol("__recompiler_store32", backend_store32);
	jitter.add_external_symbol("__recompiler_store16", backend_store16);
	jitter.add_external_symbol("__recompiler_store8", backend_store8);
	jitter.add_external_symbol("__recompiler_load32", backend_load32);
	jitter.add_external_symbol("__recompiler_load16", backend_load16);
	jitter.add_external_symbol("__recompiler_load8", backend_load8);
}

VirtualAddressSpace &MIPS::get_address_space()
{
	return addr_space;
}

void MIPS::store32(Address addr, uint32_t value) noexcept
{
	auto *ptr = static_cast<uint32_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 2] = value;
}

void MIPS::store16(Address addr, uint32_t value) noexcept
{
	auto *ptr = static_cast<uint16_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 1] = uint16_t(value);
}

void MIPS::store8(Address addr, uint32_t value) noexcept
{
	auto *ptr = static_cast<uint16_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 0] = uint8_t(value);
}

uint32_t MIPS::load32(Address addr) const noexcept
{
	auto *ptr = static_cast<uint32_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	return ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 2];
}

uint16_t MIPS::load16(Address addr) const noexcept
{
	auto *ptr = static_cast<uint16_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	return ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 1];
}

uint8_t MIPS::load8(Address addr) const noexcept
{
	auto *ptr = static_cast<uint8_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	return ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 0];
}

Address MIPS::enter(Address addr) noexcept
{
	exit_pc = addr;

	if (setjmp(jump_buffer))
		return exit_pc;

	auto *ptr = call(addr);
	ptr(this);

	// Should not be reached.
	return exit_pc;
}

StubCallPtr MIPS::call_addr(Address addr, Address expected_addr) noexcept
{
	if (return_stack_count >= 1024)
	{
		exit_pc = addr;
		longjmp(jump_buffer, ExitTooDeepStack);
	}

	return_stack[return_stack_count++] = expected_addr;
	stack_depth++;
	return call(addr);
}

StubCallPtr MIPS::jump_addr(Address addr) noexcept
{
	if (return_stack_count > 0 && return_stack[return_stack_count - 1] == addr)
	{
		stack_depth--;
		return_stack[return_stack_count--];
		return nullptr;
	}
	else
	{
		stack_depth++;
		if (stack_depth > 2048)
		{
			exit_pc = addr;
			longjmp(jump_buffer, ExitTooDeepJumpStack);
		}
		return call(addr);
	}
}

StubCallPtr MIPS::call(Address addr) noexcept
{
	auto itr = blocks.find(addr);
	if (itr != end(blocks))
	{
		return itr->second.call;
	}
	else
	{
		JITTIR::Function func;
		JITTIR::Recompiler recompiler;
		func.set_backend(this);
		recompiler.set_backend(this);
		recompiler.set_jitter(&jitter);
		func.analyze_from_entry(addr);
		auto result = recompiler.recompile_function(func);
		if (!result.call)
			std::abort();
		blocks.emplace(addr, result);
		return result.call;
	}
}

void MIPS::get_block_from_address(Address addr, Block &block)
{

}

void MIPS::recompile_basic_block(
	Address start_addr, Address end_addr,
	Recompiler *recompiler, const Block &block, BasicBlock *bb, Value *args)
{

}

int main(int argc, char **argv)
{
	VirtualAddressSpace addr_space;
	Elf32_Ehdr ehdr;
	if (!load_elf(argv[1], ehdr, addr_space))
		return 1;

	MIPS mips;
}