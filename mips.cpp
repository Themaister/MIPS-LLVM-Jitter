#include "elf.hpp"
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
#include <sys/uio.h>

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

static MIPSInstruction decode_mips_instruction(Address pc, uint32_t word)
{
	MIPSInstruction instr = {};
	instr.op = Op::Invalid;
	uint8_t rs = (word >> 21) & 31;
	uint8_t rt = (word >> 16) & 31;
	uint8_t rd = (word >> 11) & 31;
	uint8_t shamt = (word >> 6) & 31;
	uint16_t imm16 = word & 0xffff;
	uint32_t imm26 = word & ((1u << 26) - 1u);
	uint8_t low_op = word & ((1u << 6) - 1u);

	instr.rs = rs;
	instr.rt = rt;
	instr.rd = rd;

	switch (word >> 26)
	{
	case 0:
	{
		switch (low_op)
		{
		case 0:
			instr.op = Op::SLL;
			instr.imm = shamt;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 2:
			instr.op = Op::SRL;
			instr.imm = shamt;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 3:
			instr.op = Op::SRA;
			instr.imm = shamt;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 4:
			instr.op = Op::SLLV;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 6:
			instr.op = Op::SRLV;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 7:
			instr.op = Op::SRAV;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 8:
			instr.op = Op::JR;
			break;

		case 9:
			instr.op = Op::JALR;
			break;

		case 0xc:
			instr.op = Op::SYSCALL;
			instr.imm = imm26 >> 6;
			break;

		case 0xd:
			instr.op = Op::BREAK;
			instr.imm = imm26 >> 6;
			break;

		case 0x10:
			instr.op = Op::MFHI;
			break;

		case 0x11:
			instr.op = Op::MTHI;
			break;

		case 0x12:
			instr.op = Op::MFLO;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x13:
			instr.op = Op::MTLO;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x18:
			instr.op = Op::MULT;
			break;

		case 0x19:
			instr.op = Op::MULTU;
			break;

		case 0x1a:
			instr.op = Op::DIV;
			break;

		case 0x1b:
			instr.op = Op::DIVU;
			break;

		case 0x20:
			instr.op = Op::ADD;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x21:
			instr.op = Op::ADDU;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x22:
			instr.op = Op::SUB;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x23:
			instr.op = Op::SUBU;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x24:
			instr.op = Op::AND;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x25:
			instr.op = Op::OR;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x26:
			instr.op = Op::XOR;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x27:
			instr.op = Op::NOR;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x2a:
			instr.op = Op::SLT;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		case 0x2b:
			instr.op = Op::SLTU;
			if (instr.rd == 0)
				instr.op = Op::NOP;
			break;

		default:
			instr.op = Op::Invalid;
			break;
		}
		break;
	}

	case 1:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		switch (rt)
		{
		case 0:
			if (rs == 0)
				instr.op = Op::NOP;
			else
				instr.op = Op::BLTZ;
			break;

		case 1:
			if (rs == 0)
				instr.op = Op::J;
			else
				instr.op = Op::BGEZ;
			break;

		case 16:
			if (rs == 0)
				instr.op = Op::NOP;
			else
				instr.op = Op::BLTZAL;
			break;

		case 17:
			if (rs == 0)
				instr.op = Op::JAL;
			else
				instr.op = Op::BGEZAL;
			break;

		default:
			break;
		}
		break;

	case 2:
		instr.imm = ((pc + 4) & 0xf0000000) + 4 * imm26;
		instr.op = Op::J;
		break;

	case 3:
		instr.imm = ((pc + 4) & 0xf0000000) + 4 * imm26;
		instr.op = Op::JAL;
		break;

	case 4:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		if (instr.rs == instr.rt)
			instr.op = Op::J;
		else
			instr.op = Op::BEQ;
		break;

	case 5:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		if (instr.rs == instr.rt)
			instr.op = Op::NOP;
		else
			instr.op = Op::BNE;
		break;

	case 6:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		if (instr.rs == 0)
			instr.op = Op::J;
		else
			instr.op = Op::BLEZ;
		break;

	case 7:
		instr.imm = (pc + 4) + 4 * int16_t(imm16);
		if (instr.rs == 0)
			instr.op = Op::NOP;
		else
			instr.op = Op::BGTZ;
		break;

	case 8:
		instr.op = Op::ADDI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 9:
		instr.op = Op::ADDIU;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xa:
		instr.op = Op::SLTI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xb:
		instr.op = Op::SLTIU;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xc:
		instr.op = Op::ANDI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xd:
		instr.op = Op::ORI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xe:
		instr.op = Op::XORI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0xf:
		instr.op = Op::LUI;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x20:
		instr.op = Op::LB;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x21:
		instr.op = Op::LH;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x22:
		instr.op = Op::LWL;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x23:
		instr.op = Op::LW;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x24:
		instr.op = Op::LBU;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x25:
		instr.op = Op::LHU;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x26:
		instr.op = Op::LWR;
		instr.imm = imm16;
		if (instr.rt == 0)
			instr.op = Op::NOP;
		break;

	case 0x28:
		instr.op = Op::SB;
		instr.imm = imm16;
		break;

	case 0x29:
		instr.op = Op::SH;
		instr.imm = imm16;
		break;

	case 0x2a:
		instr.op = Op::SWL;
		instr.imm = imm16;
		break;

	case 0x2b:
		instr.op = Op::SW;
		instr.imm = imm16;
		break;

	case 0x2e:
		instr.op = Op::SWR;
		instr.imm = imm16;
		break;

	case 0x39:
		instr.op = Op::SWC1;
		instr.imm = imm16;
		break;

	case 0x31:
		instr.op = Op::LWC1;
		instr.imm = imm16;
		break;

	default:
		break;
	}

	return instr;
}

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
	syscall_table[SYSCALL_WRITEV] = &MIPS::syscall_writev;
	syscall_table[SYSCALL_IOCTL] = &MIPS::syscall_unimplemented;
	syscall_table[SYSCALL_SET_THREAD_AREA] = &MIPS::syscall_unimplemented;
	syscall_table[SYSCALL_SET_TID_ADDRESS] = &MIPS::syscall_unimplemented;
	syscall_table[SYSCALL_READ] = &MIPS::syscall_read;
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
	kill(getpid(), SIGILL);
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
		std::abort();
	}
}

void MIPS::syscall_exit()
{
	exit(scalar_registers[REG_A0]);
}

void MIPS::syscall_write()
{
	int fd = scalar_registers[REG_A0];
	Address addr = scalar_registers[REG_A1];
	uint32_t count = scalar_registers[REG_A2];
	std::vector<uint8_t> output;
	output.reserve(count);

	for (uint32_t i = 0; i < count; i++)
		output.push_back(load8(addr + i));

	scalar_registers[REG_V0] = write(fd, output.data(), count);
}

void MIPS::syscall_unimplemented()
{
	scalar_registers[REG_V0] = 0;
}

void MIPS::syscall_writev()
{
	int fd = scalar_registers[REG_A0];
	Address addr = scalar_registers[REG_A1];
	uint32_t count = scalar_registers[REG_A2];

	std::vector<iovec> iov(count);
	std::vector<std::vector<uint8_t>> buffers(count);
	for (uint32_t i = 0; i < count; i++)
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
}

void MIPS::syscall_read()
{
	int fd = scalar_registers[REG_A0];
	Address addr = scalar_registers[REG_A1];
	uint32_t count = scalar_registers[REG_A2];
	std::vector<uint8_t> output(count);
	ssize_t ret = ::read(fd, output.data(), count);
	for (ssize_t i = 0; i < ret; i++)
		store8(addr + i, output[i]);
	scalar_registers[REG_V0] = ret;
}

MIPS::ExitState MIPS::enter(Address addr) noexcept
{
	exit_pc = addr;
	return_stack_count = 0;
	stack_depth = 0;

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

void MIPS::get_block_from_address(Address addr, Block &block)
{
	block.block_start = addr;

	for (;;)
	{
		auto instruction = load_instr(addr);
		bool end_of_basic_block = mips_opcode_ends_basic_block(instruction.op);

		if (end_of_basic_block)
		{
			if (mips_opcode_is_branch(instruction.op) && !mips_opcode_is_branch(load_instr(addr + 4).op))
				block.block_end = addr + 8;
			else
				block.block_end = addr + 4;

			switch (instruction.op)
			{
			case Op::J:
				block.terminator = Terminator::DirectBranch;
				block.static_address_targets[0] = instruction.imm;
				break;

			case Op::JR:
			case Op::BREAK:
			case Op::Invalid:
				block.terminator = Terminator::Exit;
				break;

			case Op::BLTZ:
			case Op::BGEZ:
			case Op::BLEZ:
			case Op::BGTZ:
			case Op::BEQ:
			case Op::BNE:
				block.terminator = Terminator::SelectionBranch;
				block.static_address_targets[0] = instruction.imm;
				block.static_address_targets[1] = addr + 8;
				break;

			default:
				break;
			}

			break;
		}

		addr += 4;
	}
}

}
