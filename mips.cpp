#include "linuxvm.hpp"
#include "mips.hpp"
#include "jitter.hpp"
#include "mips_c_stubs.hpp"
#include "mips_opcode.hpp"

#include <memory>
#include <vector>

#include <setjmp.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/utsname.h>

using namespace llvm;

namespace JITTIR
{
static const char *register_names[] = {
		"zero",
		"at",
		"v0",
		"v1",
		"a0",
		"a1",
		"a2",
		"a3",
		"t0",
		"t1",
		"t2",
		"t3",
		"t4",
		"t5",
		"t6",
		"t7",
		"s0",
		"s1",
		"s2",
		"s3",
		"s4",
		"s5",
		"s6",
		"s7",
		"t8",
		"t9",
		"k0",
		"k1",
		"gp",
		"sp",
		"fp",
		"ra",
		"lo",
		"hi",
		"pc",
};

MIPS::MIPS()
{
	jitter.add_external_symbol("__recompiler_call_addr", __recompiler_call_addr);
	jitter.add_external_symbol("__recompiler_predict_return", __recompiler_predict_return);
	jitter.add_external_symbol("__recompiler_jump_indirect", __recompiler_jump_addr);
	jitter.add_external_symbol("__recompiler_store32", __recompiler_store32);
	jitter.add_external_symbol("__recompiler_store16", __recompiler_store16);
	jitter.add_external_symbol("__recompiler_store8", __recompiler_store8);
	jitter.add_external_symbol("__recompiler_load32", __recompiler_load32);
	jitter.add_external_symbol("__recompiler_load16", __recompiler_load16);
	jitter.add_external_symbol("__recompiler_load8", __recompiler_load8);
	jitter.add_external_symbol("__recompiler_sigill", __recompiler_sigill);
	jitter.add_external_symbol("__recompiler_break", __recompiler_break);
	jitter.add_external_symbol("__recompiler_syscall", __recompiler_syscall);
	jitter.add_external_symbol("__recompiler_step", __recompiler_step);
	jitter.add_external_symbol("__recompiler_step_after", __recompiler_step_after);
	jitter.add_external_symbol("__recompiler_lwl", __recompiler_lwl);
	jitter.add_external_symbol("__recompiler_lwr", __recompiler_lwr);
	jitter.add_external_symbol("__recompiler_swl", __recompiler_swl);
	jitter.add_external_symbol("__recompiler_swr", __recompiler_swr);

	syscall_table[SYSCALL_EXIT] = &MIPS::syscall_exit;
	syscall_table[SYSCALL_EXIT_GROUP] = &MIPS::syscall_exit;
	syscall_table[SYSCALL_WRITE] = &MIPS::syscall_write;
	syscall_table[SYSCALL_OPEN] = &MIPS::syscall_open;
	syscall_table[SYSCALL_CLOSE] = &MIPS::syscall_close;
	syscall_table[SYSCALL_BRK] = &MIPS::syscall_brk;
	syscall_table[SYSCALL_READV] = &MIPS::syscall_readv;
	syscall_table[SYSCALL_WRITEV] = &MIPS::syscall_writev;
	syscall_table[SYSCALL_SET_THREAD_AREA] = &MIPS::syscall_set_thread_area;
	syscall_table[SYSCALL_READ] = &MIPS::syscall_read;
	syscall_table[SYSCALL_MMAP2] = &MIPS::syscall_mmap2;
	syscall_table[SYSCALL_MMAP] = &MIPS::syscall_mmap;
	syscall_table[SYSCALL_MREMAP] = &MIPS::syscall_mremap;
	syscall_table[SYSCALL_MUNMAP] = &MIPS::syscall_munmap;
	syscall_table[SYSCALL_LLSEEK] = &MIPS::syscall_llseek;
	syscall_table[SYSCALL_TKILL] = &MIPS::syscall_tkill;
	syscall_table[SYSCALL_UNAME] = &MIPS::syscall_uname;
	syscall_table[SYSCALL_READLINK] = &MIPS::syscall_readlink;
}

VirtualAddressSpace &MIPS::get_address_space()
{
	return addr_space;
}

SymbolTable &MIPS::get_symbol_table()
{
	return symbol_table;
}

MIPSInstruction MIPS::load_instr(Address addr)
{
	auto *ptr = static_cast<uint32_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	if (!ptr)
	{
		MIPSInstruction instr{};
		instr.op = Op::Invalid; // Should be a segfault meta-op.
		return instr;
	}
	return decode_mips_instruction(addr, ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 2]);
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
	auto *ptr = static_cast<uint8_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 0] = uint8_t(value);
}

uint32_t MIPS::lwl(Address addr, uint32_t old_value) const noexcept
{
	// Little-endian MIPS. Needs a different implementation for Big-endian.

	uint32_t loaded = load32(addr);
	uint32_t addr_offset = addr & 3;
	loaded <<= (addr_offset ^ 3) * 8;
	uint32_t retain_mask = (1u << 24) - 1u;
	retain_mask >>= addr_offset * 8;
	return (old_value & retain_mask) | (loaded & ~retain_mask);
}

uint32_t MIPS::lwr(Address addr, uint32_t old_value) const noexcept
{
	// Little-endian MIPS. Needs a different implementation for Big-endian.

	uint32_t addr_offset = addr & 3;

	uint32_t loaded = load32(addr);
	loaded >>= addr_offset * 8;

	uint32_t keep_mask = 0xffffffffu;
	keep_mask >>= addr_offset * 8;
	return (old_value & ~keep_mask) | (loaded & keep_mask);
}

void MIPS::swl(Address addr, uint32_t value) noexcept
{
	// Little-endian MIPS. Needs a different implementation for Big-endian.

	uint32_t base_addr = addr & ~3;
	uint32_t addr_offset = addr & 3;

	switch (addr_offset)
	{
	case 0:
		store8(base_addr, value >> 24);
		break;

	case 1:
		store16(base_addr, value >> 16);
		break;

	case 2:
		store8(base_addr + 0, uint8_t(value >> 8));
		store8(base_addr + 1, uint8_t(value >> 16));
		store8(base_addr + 2, uint8_t(value >> 24));
		break;

	case 3:
		store32(base_addr, value);
		break;
	}
}

void MIPS::swr(Address addr, uint32_t value) noexcept
{
	// Little-endian MIPS. Needs a different implementation for Big-endian.

	uint32_t base_addr = addr & ~3;
	uint32_t addr_offset = addr & 3;

	switch (addr_offset)
	{
	case 0:
		store32(base_addr, value);
		break;

	case 1:
		store8(base_addr + 1, uint8_t(value >> 0));
		store8(base_addr + 2, uint8_t(value >> 8));
		store8(base_addr + 3, uint8_t(value >> 16));
		break;

	case 2:
		store16(base_addr + 2, uint16_t(value));
		break;

	case 3:
		store8(base_addr + 3, uint8_t(value));
		break;
	}
}

void MIPS::step() noexcept
{
	//auto instr = load_instr(scalar_registers[REG_PC]);
	fprintf(stderr, "Executing PC 0x%x:\n", scalar_registers[REG_PC]);
	//for (int i = 0; i < REG_COUNT; i++)
	//	fprintf(stderr, "   [%s] = 0x%x (%d)\n", register_names[i], scalar_registers[i], scalar_registers[i]);

	memcpy(old_state.scalar_registers, scalar_registers, sizeof(scalar_registers));
	memcpy(old_state.float_registers, float_registers, sizeof(float_registers));
}

void MIPS::step_after() noexcept
{
	for (int i = 0; i < RegisterState::MaxIntegerRegisters; i++)
	{
		if (old_state.scalar_registers[i] != scalar_registers[i])
		{
			fprintf(stderr, "    [%s] = 0x%x (%d) <- 0x%x (%d)\n",
			        register_names[i], scalar_registers[i], scalar_registers[i],
			        old_state.scalar_registers[i], old_state.scalar_registers[i]);
		}
	}
}

uint32_t MIPS::load32(Address addr) const noexcept
{
	auto *ptr = static_cast<uint32_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	uint32_t loaded = ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 2];
	return loaded;
}

uint16_t MIPS::load16(Address addr) const noexcept
{
	auto *ptr = static_cast<uint16_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	uint16_t loaded = ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 1];
	return loaded;
}

uint8_t MIPS::load8(Address addr) const noexcept
{
	auto *ptr = static_cast<uint8_t *>(addr_space.get_page(addr / VirtualAddressSpace::PageSize));
	uint8_t loaded = ptr[(addr & (VirtualAddressSpace::PageSize - 1)) >> 0];
	return loaded;
}

void MIPS::sigill(Address addr) const noexcept
{
	raise(SIGILL);
}

void MIPS::op_break(Address addr, uint32_t) noexcept
{
	exit_pc = addr;
	longjmp(jump_buffer, static_cast<int>(ExitCondition::ExitBreak));
}

void MIPS::op_syscall(Address addr, uint32_t) noexcept
{
	// Syscall
	// On Linux, syscall number is encoded in $v0.
	auto syscall = unsigned(scalar_registers[REG_V0]);
	//fprintf(stderr, "SYSCALL %u called!\n", syscall);
	syscall -= 4000;
	if (syscall < SYSCALL_COUNT && syscall_table[syscall])
		(this->*syscall_table[syscall])();
	else
	{
		fprintf(stderr, "Unimplemented SYSCALL %u called!\n", syscall + 4000);
		syscall_unimplemented();
		//std::abort();
	}
}

void MIPS::syscall_exit()
{
	exit(scalar_registers[REG_A0]);
}

void MIPS::syscall_brk()
{
	scalar_registers[REG_A3] = 0;

	uint32_t new_end = uint32_t(scalar_registers[REG_A0]);
	new_end = addr_space.brk(new_end);

	if (new_end)
		scalar_registers[REG_V0] = new_end;
	else
	{
		scalar_registers[REG_V0] = -1;
		scalar_registers[REG_A3] = ENOMEM;
	}
}

void MIPS::syscall_open()
{
	Address path = scalar_registers[REG_A0];
	int flags = scalar_registers[REG_A1];
	mode_t mode = scalar_registers[REG_A2];

	std::string path_copied;
	while (char c = load8(path++))
		path_copied.push_back(c);

	int fd = open(path_copied.c_str(), flags, mode);
	scalar_registers[REG_V0] = fd;
	if (fd < 0)
		scalar_registers[REG_A3] = errno;
	else
		scalar_registers[REG_A3] = 0;
}

void MIPS::syscall_close()
{
	int fd = scalar_registers[REG_A0];
	int ret = close(fd);
	scalar_registers[REG_V0] = ret;

	if (ret < 0)
		scalar_registers[REG_A3] = errno;
	else
		scalar_registers[REG_A3] = 0;
}

void MIPS::syscall_write()
{
	int fd = scalar_registers[REG_A0];
	Address addr = scalar_registers[REG_A1];
	uint32_t count = scalar_registers[REG_A2];
	std::vector<uint8_t> output;
	output.reserve(count);

	addr_space.copy_from_user(output.data(), addr, count);
	scalar_registers[REG_V0] = write(fd, output.data(), count);

	if (scalar_registers[REG_V0] < 0)
		scalar_registers[REG_A3] = errno;
	else
		scalar_registers[REG_A3] = 0;
}

void MIPS::syscall_unimplemented()
{
	scalar_registers[REG_V0] = 0;
	scalar_registers[REG_A3] = ENOSYS;
}

void MIPS::syscall_set_thread_area()
{
	Address addr = scalar_registers[REG_A0];
	scalar_registers[REG_TLS] = addr;
	scalar_registers[REG_V0] = 0;
	scalar_registers[REG_A3] = 0;
}

void MIPS::syscall_readv()
{
	int fd = scalar_registers[REG_A0];
	Address addr = scalar_registers[REG_A1];
	int count = scalar_registers[REG_A2];

	if (count <= 0)
	{
		scalar_registers[REG_A3] = EINVAL;
		return;
	}

	std::vector<iovec> iov(count);
	std::vector<std::vector<uint8_t>> buffers(count);

	for (int i = 0; i < count; i++)
	{
		uint32_t iov_len = load32(addr + 8 * i + 4);
		buffers[i].resize(iov_len);
		iov[i].iov_base = buffers[i].data();
		iov[i].iov_len = iov_len;
	}

	ssize_t ret = readv(fd, iov.data(), count);

	scalar_registers[REG_V0] = ret;

	if (ret < 0)
		scalar_registers[REG_A3] = errno;
	else
	{
		for (int i = 0; i < count; i++)
		{
			uint32_t bytes_to_read = std::min<uint32_t>(ret, iov[i].iov_len);
			if (bytes_to_read)
			{
				addr_space.copy_to_user(load32(addr + 8 * i), iov[i].iov_base, bytes_to_read);
				ret -= bytes_to_read;
			}
		}
		scalar_registers[REG_A3] = 0;
	}
}

void MIPS::syscall_writev()
{
	int fd = scalar_registers[REG_A0];
	Address addr = scalar_registers[REG_A1];
	int count = scalar_registers[REG_A2];

	if (count <= 0)
	{
		scalar_registers[REG_A3] = EINVAL;
		return;
	}

	std::vector<iovec> iov(count);
	std::vector<std::vector<uint8_t>> buffers(count);
	for (int i = 0; i < count; i++)
	{
		uint32_t iov_base = load32(addr + 8 * i + 0);
		uint32_t iov_len = load32(addr + 8 * i + 4);
		buffers[i].resize(iov_len);
		for (uint32_t j = 0; j < iov_len; j++)
			buffers[i][j] = load8(iov_base + j);

		iov[i].iov_base = buffers[i].data();
		iov[i].iov_len = iov_len;
	}

	scalar_registers[REG_V0] = writev(fd, iov.data(), count);

	if (scalar_registers[REG_V0] < 0)
		scalar_registers[REG_A3] = errno;
	else
		scalar_registers[REG_A3] = 0;
}

void MIPS::syscall_munmap()
{
	uint32_t addr = scalar_registers[REG_A0];
	uint32_t length = scalar_registers[REG_A1];

	if (addr_space.unmap_memory(addr, length))
	{
		scalar_registers[REG_V0] = 0;
		scalar_registers[REG_A3] = 0;
	}
	else
	{
		scalar_registers[REG_V0] = -1;
		scalar_registers[REG_A3] = EINVAL;
	}
}

void MIPS::syscall_mremap()
{
	// We can only do this if old_addr + old_size points to brk point.
	// Assume this is only used for MAP_ANON/PRIVATE regions, like for realloc().
	// Can't support this for file mmap, but seriously ...

	Address old_addr = scalar_registers[REG_A0];
	uint32_t old_size = scalar_registers[REG_A1];
	uint32_t new_size = scalar_registers[REG_A2];
	int flags = scalar_registers[REG_A3];

	if (flags & MREMAP_FIXED) // Not supported.
	{
		scalar_registers[REG_V0] = -1;
		scalar_registers[REG_A3] = EINVAL;
		return;
	}

	if (new_size < old_size)
	{
		scalar_registers[REG_V0] = old_addr;
		scalar_registers[REG_A3] = 0;
		return;
	}

	if (old_addr + old_size == addr_space.brk(0) &&
	    addr_space.map_memory(new_size - old_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
	{
		scalar_registers[REG_V0] = old_addr;
		scalar_registers[REG_A3] = 0;
	}
	else if (flags & MREMAP_MAYMOVE)
	{
		// Move old pages to a new address space, and allocate some more ...
		Address new_addr = addr_space.realloc_memory(old_addr, old_size, new_size);
		if (new_addr)
		{
			scalar_registers[REG_V0] = new_addr;
			scalar_registers[REG_A3] = 0;
		}
		else
		{
			scalar_registers[REG_V0] = -1;
			scalar_registers[REG_A3] = ENOMEM;
		}
	}
	else
	{
		scalar_registers[REG_V0] = -1;
		scalar_registers[REG_A3] = ENOMEM;
	}
}

void MIPS::syscall_mmap_impl(int page_mult)
{
	uint32_t addr = scalar_registers[REG_A0];
	uint32_t length = scalar_registers[REG_A1];
	int prot = scalar_registers[REG_A2];
	int flags = scalar_registers[REG_A3];

	if (addr != 0)
	{
		scalar_registers[REG_A3] = ENOSYS;
		return;
	}

	int fd = load32(scalar_registers[REG_SP] + 16);
	int off = load32(scalar_registers[REG_SP] + 20) * page_mult;

	if (fd == -1)
		flags |= MAP_ANONYMOUS;
	flags &= (MAP_ANONYMOUS | MAP_PRIVATE | MAP_SHARED);

	scalar_registers[REG_V0] = addr_space.map_memory(length, prot, flags, fd, off);

	if (!scalar_registers[REG_V0])
		scalar_registers[REG_A3] = ENOMEM;
	else
		scalar_registers[REG_A3] = 0;
}

void MIPS::syscall_mmap()
{
	syscall_mmap_impl(1);
}

void MIPS::syscall_mmap2()
{
	syscall_mmap_impl(VirtualAddressSpace::PageSize);
}

void MIPS::syscall_readlink()
{
	Address path = scalar_registers[REG_A0];
	Address buf = scalar_registers[REG_A1];
	uint32_t bufsize = scalar_registers[REG_A2];

	std::string path_buffer;
	while (char c = load8(path++))
		path_buffer.push_back(c);

	std::vector<char> buf_kernel(bufsize);
	ssize_t ret = readlink(path_buffer.c_str(), buf_kernel.data(), bufsize);
	if (ret < 0)
	{
		scalar_registers[REG_V0] = 0;
		scalar_registers[REG_A3] = errno;
	}
	else
	{
		scalar_registers[REG_V0] = ret;
		scalar_registers[REG_A3] = 0;
		addr_space.copy_to_user(buf, buf_kernel.data(), bufsize);
	}
}

void MIPS::syscall_uname()
{
	utsname n;
	if (uname(&n) < 0)
	{
		scalar_registers[REG_V0] = -1;
		scalar_registers[REG_A3] = errno;
	}
	else
	{
		// Assume sizeof on MIPS is the same. It's all chars anyways.
		addr_space.copy_to_user(scalar_registers[REG_A0], &n, sizeof(n));
		scalar_registers[REG_V0] = 0;
		scalar_registers[REG_A3] = 0;
	}
}

void MIPS::syscall_tkill()
{
	// Not accurate, but it's used for abort() by musl.
	raise(scalar_registers[REG_A1]);
	scalar_registers[REG_V0] = 0;
	scalar_registers[REG_A3] = 0;
}

void MIPS::syscall_llseek()
{
	int fd = scalar_registers[REG_A0];
	uint32_t off_high = scalar_registers[REG_A1];
	uint32_t off_lo = scalar_registers[REG_A2];
	Address loff_ptr = scalar_registers[REG_A3];
	int whence = load32(scalar_registers[REG_SP] + 16);

	off64_t off = off64_t((uint64_t(off_high) << 32) | off_lo);

	off64_t ret = lseek64(fd, off, whence);
	if (ret < 0)
	{
		scalar_registers[REG_V0] = ret;
		scalar_registers[REG_A3] = errno;
	}
	else
	{
		scalar_registers[REG_V0] = 0;
		scalar_registers[REG_A3] = 0;

		// Little endian.
		store32(loff_ptr + 0, ret & 0xffffffffu);
		store32(loff_ptr + 4, (ret >> 32) & 0xffffffffu);
	}
}

void MIPS::syscall_read()
{
	int fd = scalar_registers[REG_A0];
	Address addr = scalar_registers[REG_A1];
	uint32_t count = scalar_registers[REG_A2];
	std::vector<uint8_t> output(count);
	ssize_t ret = ::read(fd, output.data(), count);

	if (ret > 0)
		addr_space.copy_to_user(addr, output.data(), ret);
	scalar_registers[REG_V0] = ret;

	if (scalar_registers[REG_V0] < 0)
		scalar_registers[REG_A3] = errno;
	else
		scalar_registers[REG_A3] = 0;
}

MIPS::ExitState MIPS::enter(Address addr) noexcept
{
	exit_pc = addr;
	return_stack_count = 0;
	stack_depth = 0;
	call_stack_name.clear();

	auto itr = symbol_table.address_to_symbol.find(addr);
	if (itr != end(symbol_table.address_to_symbol))
		call_stack_name.push_back(itr->second);
	else
		call_stack_name.push_back("??? missing symbol");

	if (auto ret = setjmp(jump_buffer))
	{
		ExitState state = {};
		state.condition = static_cast<ExitCondition>(ret);
		state.pc = exit_pc;
		return state;
	}

	auto *ptr = call(addr);
	ptr(this);

	// Should not be reached.
	ExitState state = {};
	state.pc = exit_pc;
	state.condition = ExitCondition::Invalid;
	return state;
}

void MIPS::predict_return(Address addr, Address expected_addr) noexcept
{
	{
		auto itr = symbol_table.address_to_symbol.find(addr);
		if (itr != end(symbol_table.address_to_symbol))
			call_stack_name.push_back(itr->second);
		else
			call_stack_name.push_back("??? missing symbol");
	}

	//fprintf(stderr, "Calling 0x%x, Expecting return to 0x%x.\n", addr, expected_addr);
	if (return_stack_count >= 1024)
	{
		exit_pc = addr;
		longjmp(jump_buffer, static_cast<int>(ExitCondition::ExitTooDeepStack));
	}

	return_stack[return_stack_count++] = expected_addr;
	stack_depth++;
}

StubCallPtr MIPS::call_addr(Address addr, Address expected_addr) noexcept
{
	predict_return(addr, expected_addr);
	return call(addr);
}

StubCallPtr MIPS::jump_addr(Address addr) noexcept
{
	//fprintf(stderr, "Jumping indirect to 0x%x.\n", addr);
	if (return_stack_count > 0 && return_stack[return_stack_count - 1] == addr)
	{
		//fprintf(stderr, "  Successfully predicted return.\n");
		return_stack_count--;
		stack_depth = return_stack_count;
		call_stack_name.pop_back();
		return nullptr;
	}
	else if (addr == 0)
	{
		// Useful for cases where we want to test arbitrary functions and just want it to return to host.
		exit_pc = addr;
		longjmp(jump_buffer, static_cast<int>(ExitCondition::JumpToZero));
	}
	else
	{
		//fprintf(stderr, "  Mispredicted return, calling deeper into stack.\n");
		stack_depth++;
		if (stack_depth > 2048)
		{
			exit_pc = addr;
			longjmp(jump_buffer, static_cast<int>(ExitCondition::ExitTooDeepJumpStack));
		}
		return call(addr);
	}
}

StubCallPtr MIPS::call(Address addr) noexcept
{
	auto itr = blocks.find(addr);
	if (itr != end(blocks))
	{
		return itr->second;
	}
	else
	{
		JITTIR::Function func;
		JITTIR::Recompiler recompiler(&blocks);
		calls = {};
		func.set_backend(this);
		recompiler.set_backend(this);
		recompiler.set_jitter(&jitter);
		func.set_entry_address(addr);
		auto result = recompiler.recompile_function(func);
		if (!result.call)
			std::abort();
		return result.call;
	}
}

}
