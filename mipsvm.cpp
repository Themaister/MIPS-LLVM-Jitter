#include <elf.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <memory>
#include <vector>
#include "ir_function.hpp"
#include "ir_recompile.hpp"
#include "jitter.hpp"
#include <sys/uio.h>

using namespace JITTIR;
using namespace llvm;

//#define LS_DEBUG
//#define STEP_DEBUG

#ifdef STEP_DEBUG
#define STEP() do { \
	tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr)); \
	tracker.flush(); \
	call_step(recompiler, tracker.get_argument(), bb); \
	tracker.invalidate(); \
} while(0)

#define STEP_AFTER() do { \
	tracker.flush(); \
	call_step_after(recompiler, tracker.get_argument(), bb); \
	tracker.invalidate(); \
} while(0)
#else
#define STEP() ((void)0)
#define STEP_AFTER() ((void)0)
#endif

enum Syscalls
{
	SYSCALL_SYSCALL = 0,
	SYSCALL_EXIT = 1,
	SYSCALL_FORK = 2,
	SYSCALL_READ = 3,
	SYSCALL_WRITE = 4,
	SYSCALL_OPEN = 5,
	SYSCALL_CLOSE = 6,
	SYSCALL_WAITPID = 7,
	SYSCALL_CREAT = 8,
	SYSCALL_LINK = 9,
	SYSCALL_IOCTL = 54,
	SYSCALL_WRITEV = 146,
	SYSCALL_EXIT_GROUP = 246,
	SYSCALL_SET_TID_ADDRESS = 252,
	SYSCALL_SET_THREAD_AREA = 283,
	SYSCALL_COUNT
};

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

enum Registers
{
	REG_ZERO = 0,
	REG_AT,
	REG_V0,
	REG_V1,
	REG_A0,
	REG_A1,
	REG_A2,
	REG_A3,
	REG_T0,
	REG_T1,
	REG_T2,
	REG_T3,
	REG_T4,
	REG_T5,
	REG_T6,
	REG_T7,
	REG_S0,
	REG_S1,
	REG_S2,
	REG_S3,
	REG_S4,
	REG_S5,
	REG_S6,
	REG_S7,
	REG_T8,
	REG_T9,
	REG_K0,
	REG_K1,
	REG_GP,
	REG_SP,
	REG_FP,
	REG_RA,

	REG_LO,
	REG_HI,
	REG_PC,
	REG_COUNT
};

struct RegisterTracker
{
	RegisterTracker(Value *arg_)
		: arg(arg_)
	{
	}

	void set_builder(IRBuilder<> *builder_)
	{
		builder = builder_;
	}

	Value *get_argument()
	{
		return arg;
	}

	void write_int(unsigned index, Value *value)
	{
		if (index != 0)
		{
			int_registers[index] = value;
			dirty_int |= 1ull << index;
		}
	}

	Value *read_int(unsigned index)
	{
		if (index == 0)
			return ConstantInt::get(Type::getInt32Ty(builder->getContext()), 0);

		if (int_registers[index])
			return int_registers[index];

		auto *ptr = builder->CreateConstInBoundsGEP1_64(arg, index, std::string("Reg") + std::to_string(index) + "Ptr");
		int_registers[index] = builder->CreateLoad(ptr, std::string("Reg") + std::to_string(index) + "Loaded");
		return int_registers[index];
	}

	void write_float(unsigned index, Value *value)
	{
		if (index != 0)
		{
			float_registers[index] = value;
			dirty_float |= 1u << index;
		}
	}

	Value *read_float(unsigned index)
	{
		if (float_registers[index])
			return float_registers[index];

		auto *ptr = builder->CreateConstInBoundsGEP1_64(arg, index + RegisterState::MaxIntegerRegisters, std::string("FReg") + std::to_string(index) + "Ptr");
		float_registers[index] = builder->CreateLoad(ptr, std::string("FReg") + std::to_string(index) + "Loaded");
		return float_registers[index];
	}

	void flush()
	{
		for (int i = 0; i < RegisterState::MaxIntegerRegisters; i++)
		{
			if (dirty_int & (1ull << i))
			{
				auto *ptr = builder->CreateConstInBoundsGEP1_64(arg, i, std::string("Reg") + std::to_string(i) + "Ptr");
				builder->CreateStore(int_registers[i], ptr);
			}
		}

		for (int i = 0; i < RegisterState::MaxFloatRegisters; i++)
		{
			if (dirty_float & (1ull << i))
			{
				auto *ptr = builder->CreateConstInBoundsGEP1_64(arg, i + RegisterState::MaxIntegerRegisters, std::string("FReg") + std::to_string(i) + "Ptr");
				builder->CreateStore(float_registers[i], ptr);
			}
		}

		dirty_int = 0;
		dirty_float = 0;
	}

	void invalidate()
	{
		memset(int_registers, 0, sizeof(int_registers));
		memset(float_registers, 0, sizeof(float_registers));
	}

	std::string get_twine(unsigned index)
	{
		return std::string("Reg") + std::to_string(index) + "_";
	}

	std::string get_float_twine(unsigned index)
	{
		return std::string("FReg") + std::to_string(index) + "_";
	}

	IRBuilder<> *builder = nullptr;
	Value *arg;
	Value *int_registers[RegisterState::MaxIntegerRegisters] = {};
	Value *float_registers[RegisterState::MaxFloatRegisters] = {};
	uint64_t dirty_int = 0;
	uint64_t dirty_float = 0;
};

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

static bool load_elf(const char *path, Elf32_Ehdr &ehdr_output, VirtualAddressSpace &addr_space,
                     std::unordered_map<std::string, Address> &symbol_table)
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

enum class Op
{
	Invalid,
	NOP,
	SLL,
	SRL,
	SRA,
	SLLV,
	SRLV,
	SRAV,
	JR,
	JALR,
	SYSCALL,
	BREAK,
	MFHI,
	MFLO,
	MTHI,
	MTLO,
	MULT,
	MULTU,
	DIV,
	DIVU,
	ADD,
	ADDU,
	SUB,
	SUBU,
	AND,
	OR,
	XOR,
	NOR,
	SLT,
	SLTU,
	BLTZ,
	BGEZ,
	BLTZAL,
	BGEZAL,
	J,
	JAL,
	BEQ,
	BNE,
	BLEZ,
	BGTZ,
	ADDI,
	ADDIU,
	SLTI,
	SLTIU,
	ANDI,
	ORI,
	XORI,
	LUI,
	LB,
	LH,
	LWL,
	LW,
	LBU,
	LHU,
	LWR,
	SB,
	SH,
	SWL,
	SW,
	SWR,

	LWC1,
	SWC1,
#if 0
	LWC0,
	LWC2,
	LWC3,
	SWC0,
	SWC2,
	SWC3,
	COP0,
	COP1,
	COP2,
	COP3,
#endif
};

struct MIPSInstruction
{
	Op op;
	uint8_t rs, rt, rd;
	uint32_t imm;
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
	}

	return instr;
}

class MIPS : public JITTIR::RegisterState, public JITTIR::RecompilerBackend, public JITTIR::BlockAnalysisBackend
{
public:
	MIPS();
	VirtualAddressSpace &get_address_space();

	enum class ExitCondition : int
	{
		Invalid = 0,
		ExitTooDeepStack = 1,
		ExitTooDeepJumpStack = 2,
		ExitBreak = 3,
		JumpToZero = 4
	};

	struct ExitState
	{
		Address pc;
		ExitCondition condition;
	};

	ExitState enter(Address addr) noexcept;

	uint32_t lwl(Address addr, uint32_t old_value) const noexcept;
	uint32_t lwr(Address addr, uint32_t old_value) const noexcept;
	void swl(Address addr, uint32_t value) noexcept;
	void swr(Address addr, uint32_t value) noexcept;
	void step() noexcept;
	void step_after() noexcept;

	void store32(Address addr, uint32_t value) noexcept;
	void store16(Address addr, uint32_t value) noexcept;
	void store8(Address addr, uint32_t value) noexcept;
	uint32_t load32(Address addr) const noexcept;
	uint16_t load16(Address addr) const noexcept;
	uint8_t load8(Address addr) const noexcept;
	void sigill(Address addr) const noexcept;
	void op_break(Address addr, uint32_t code) noexcept;
	void op_syscall(Address addr, uint32_t code) noexcept;
	StubCallPtr call_addr(Address addr, Address expected_addr) noexcept;
	void predict_return(Address addr, Address expected_addr) noexcept;
	StubCallPtr jump_addr(Address addr) noexcept;

private:
	VirtualAddressSpace addr_space;

	void get_block_from_address(Address addr, Block &block) override;

	void recompile_basic_block(
		Address start_addr, Address end_addr,
		Recompiler *recompiler, const Block &block, BasicBlock *bb, Value *args) override;

	Jitter jitter;
	jmp_buf jump_buffer;
	Address return_stack[1024];
	unsigned return_stack_count = 0;
	unsigned stack_depth = 0;
	Address exit_pc = 0;

	std::unordered_map<Address, void (*)(RegisterState *)> blocks;
	StubCallPtr call(Address addr) noexcept;
	MIPSInstruction load_instr(Address addr);
	void recompile_instruction(Recompiler *recompiler, BasicBlock *&bb,
	                           IRBuilder<> &builder, RegisterTracker &tracker, Address addr);

	Value *create_call(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr, Address expected_return);
	Value *create_call(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Address expected_return);
	Value *create_jump_indirect(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr);
	void create_store32(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value);
	void create_store16(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value);
	void create_store8(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value);
	Value *create_load32(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr);
	Value *create_load16(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr);
	Value *create_load8(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr);
	void create_sigill(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr);
	void create_break(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr, uint32_t code);
	void create_syscall(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr, uint32_t code);

	Value *create_lwl(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *old_value, Value *addr);
	Value *create_lwr(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *old_value, Value *addr);
	void create_swl(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value);
	void create_swr(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value);
	void call_step(Recompiler *recompiler, Value *argument, BasicBlock *bb);
	void call_step_after(Recompiler *recompiler, Value *argument, BasicBlock *bb);

	struct
	{
		llvm::Function *lwl = nullptr;
		llvm::Function *lwr = nullptr;
		llvm::Function *swl = nullptr;
		llvm::Function *swr = nullptr;
		llvm::Function *store32 = nullptr;
		llvm::Function *store16 = nullptr;
		llvm::Function *store8 = nullptr;
		llvm::Function *load32 = nullptr;
		llvm::Function *load16 = nullptr;
		llvm::Function *load8 = nullptr;
		llvm::Function *call = nullptr;
		llvm::Function *predict_return = nullptr;
		llvm::Function *jump_indirect = nullptr;
		llvm::Function *sigill = nullptr;
		llvm::Function *op_break = nullptr;
		llvm::Function *op_syscall = nullptr;
		llvm::Function *step = nullptr;
		llvm::Function *step_after = nullptr;
	} calls;

	using SyscallPtr = void (MIPS::*)();
	SyscallPtr syscall_table[SYSCALL_COUNT] = {};
	void syscall_exit();
	void syscall_write();
	void syscall_writev();
	void syscall_unimplemented();
	void syscall_read();

	RegisterState old_state = {};
};

extern "C"
{
static StubCallPtr backend_call_addr(RegisterState *regs, Address addr, Address expected_addr)
{
	return static_cast<MIPS *>(regs)->call_addr(addr, expected_addr);
}

static void backend_predict_return(RegisterState *regs, Address addr, Address expected_addr)
{
	static_cast<MIPS *>(regs)->predict_return(addr, expected_addr);
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

static void backend_sigill(RegisterState *regs, Address addr)
{
	static_cast<MIPS *>(regs)->sigill(addr);
}

static void backend_break(RegisterState *regs, Address addr, uint32_t code)
{
	static_cast<MIPS *>(regs)->op_break(addr, code);
}

static void backend_syscall(RegisterState *regs, Address addr, uint32_t code)
{
	static_cast<MIPS *>(regs)->op_syscall(addr, code);
}

static uint32_t backend_lwl(RegisterState *regs, Address addr, uint32_t old_value)
{
	return static_cast<MIPS *>(regs)->lwl(addr, old_value);
}

static uint32_t backend_lwr(RegisterState *regs, Address addr, uint32_t old_value)
{
	return static_cast<MIPS *>(regs)->lwr(addr, old_value);
}

static void backend_swl(RegisterState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->swl(addr, value);
}

static void backend_swr(RegisterState *regs, Address addr, uint32_t value)
{
	static_cast<MIPS *>(regs)->swr(addr, value);
}

static void backend_step(RegisterState *regs)
{
	static_cast<MIPS *>(regs)->step();
}

static void backend_step_after(RegisterState *regs)
{
	static_cast<MIPS *>(regs)->step_after();
}

}

MIPS::MIPS()
{
	jitter.add_external_symbol("__recompiler_call_addr", backend_call_addr);
	jitter.add_external_symbol("__recompiler_predict_return", backend_predict_return);
	jitter.add_external_symbol("__recompiler_jump_indirect", backend_jump_addr);
	jitter.add_external_symbol("__recompiler_store32", backend_store32);
	jitter.add_external_symbol("__recompiler_store16", backend_store16);
	jitter.add_external_symbol("__recompiler_store8", backend_store8);
	jitter.add_external_symbol("__recompiler_load32", backend_load32);
	jitter.add_external_symbol("__recompiler_load16", backend_load16);
	jitter.add_external_symbol("__recompiler_load8", backend_load8);
	jitter.add_external_symbol("__recompiler_sigill", backend_sigill);
	jitter.add_external_symbol("__recompiler_break", backend_break);
	jitter.add_external_symbol("__recompiler_syscall", backend_syscall);
	jitter.add_external_symbol("__recompiler_step", backend_step);
	jitter.add_external_symbol("__recompiler_step_after", backend_step_after);
	jitter.add_external_symbol("__recompiler_lwl", backend_lwl);
	jitter.add_external_symbol("__recompiler_lwr", backend_lwr);
	jitter.add_external_symbol("__recompiler_swl", backend_swl);
	jitter.add_external_symbol("__recompiler_swr", backend_swr);

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
	auto instr = load_instr(scalar_registers[REG_PC]);
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

// Technically undefined to run a branch instruction inside a basic block.
// At the very least, it must not branch, so ... it's effectively a no-op.
static bool mips_opcode_is_branch(Op op)
{
	switch (op)
	{
	case Op::J:
	case Op::JAL:
	case Op::JR:
	case Op::JALR:
	case Op::BEQ:
	case Op::BNE:
	case Op::BLEZ:
	case Op::BGTZ:
	case Op::BLTZ:
	case Op::BGEZ:
	case Op::BLTZAL:
	case Op::BGEZAL:
		return true;

	default:
		return false;
	}
}

static bool mips_opcode_ends_basic_block(Op op)
{
	switch (op)
	{
	case Op::J:
	case Op::JR:
	case Op::BEQ:
	case Op::BNE:
	case Op::BLEZ:
	case Op::BGTZ:
	case Op::BLTZ:
	case Op::BGEZ:
	case Op::BREAK:
	case Op::Invalid:
		return true;

	default:
		return false;
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

void MIPS::recompile_instruction(Recompiler *recompiler, BasicBlock *&bb,
                                 IRBuilder<> &builder, RegisterTracker &tracker, Address addr)
{
	auto &ctx = builder.getContext();
	auto instr = load_instr(addr);
	bool can_do_step_after = true;

	STEP();

	switch (instr.op)
	{
	case Op::NOP:
		break;

	// Arithmetic operations.
	case Op::ADD:
	case Op::ADDU:
		tracker.write_int(instr.rd, builder.CreateAdd(tracker.read_int(instr.rs), tracker.read_int(instr.rt),
		                                              tracker.get_twine(instr.rd)));
		break;

	case Op::SUB:
	case Op::SUBU:
		tracker.write_int(instr.rd, builder.CreateSub(tracker.read_int(instr.rs), tracker.read_int(instr.rt),
		                                              tracker.get_twine(instr.rd)));
		break;

	case Op::ADDI:
	case Op::ADDIU:
		tracker.write_int(instr.rt, builder.CreateAdd(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                              tracker.get_twine(instr.rt)));
		break;

	case Op::SLT:
	{
		Value *cmp = builder.CreateICmpSLT(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "SLTCmp");
		tracker.write_int(instr.rd,
		                  builder.CreateSelect(cmp, ConstantInt::get(Type::getInt32Ty(ctx), 1), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                       tracker.get_twine(instr.rd)));
		break;
	}

	case Op::SLTU:
	{
		Value *cmp = builder.CreateICmpULT(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "ULTCmp");
		tracker.write_int(instr.rd,
		                  builder.CreateSelect(cmp, ConstantInt::get(Type::getInt32Ty(ctx), 1), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                       tracker.get_twine(instr.rd)));
		break;
	}

	case Op::SLTI:
	{
		Value *cmp = builder.CreateICmpSLT(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SLTICmp");
		tracker.write_int(instr.rt,
		                  builder.CreateSelect(cmp, ConstantInt::get(Type::getInt32Ty(ctx), 1), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                       tracker.get_twine(instr.rt)));
		break;
	}

	case Op::SLTIU:
	{
		Value *cmp = builder.CreateICmpULT(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SLTIUCmp");
		tracker.write_int(instr.rt,
		                  builder.CreateSelect(cmp, ConstantInt::get(Type::getInt32Ty(ctx), 1), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                       tracker.get_twine(instr.rt)));
		break;
	}

	case Op::AND:
		tracker.write_int(instr.rd, builder.CreateAnd(tracker.read_int(instr.rs), tracker.read_int(instr.rt), tracker.get_twine(instr.rd)));
		break;

	case Op::OR:
		tracker.write_int(instr.rd, builder.CreateOr(tracker.read_int(instr.rs), tracker.read_int(instr.rt), tracker.get_twine(instr.rd)));
		break;

	case Op::XOR:
		tracker.write_int(instr.rd, builder.CreateXor(tracker.read_int(instr.rs), tracker.read_int(instr.rt), tracker.get_twine(instr.rd)));
		break;

	case Op::NOR:
		tracker.write_int(instr.rd, builder.CreateNot(builder.CreateOr(tracker.read_int(instr.rs), tracker.read_int(instr.rt)), tracker.get_twine(instr.rd)));
		break;

	case Op::ANDI:
		tracker.write_int(instr.rt, builder.CreateAnd(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.imm)), tracker.get_twine(instr.rt)));
		break;

	case Op::ORI:
		tracker.write_int(instr.rt, builder.CreateOr(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.imm)), tracker.get_twine(instr.rt)));
		break;

	case Op::XORI:
		tracker.write_int(instr.rt, builder.CreateXor(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.imm)), tracker.get_twine(instr.rt)));
		break;

	case Op::SLL:
		tracker.write_int(instr.rd, builder.CreateShl(tracker.read_int(instr.rt), ConstantInt::get(Type::getInt32Ty(ctx), instr.imm & 31), tracker.get_twine(instr.rd)));
		break;

	case Op::SRL:
		tracker.write_int(instr.rd, builder.CreateLShr(tracker.read_int(instr.rt), ConstantInt::get(Type::getInt32Ty(ctx), instr.imm & 31), tracker.get_twine(instr.rd)));
		break;

	case Op::SRA:
		tracker.write_int(instr.rd, builder.CreateAShr(tracker.read_int(instr.rt), ConstantInt::get(Type::getInt32Ty(ctx), instr.imm & 31), tracker.get_twine(instr.rd)));
		break;

	case Op::SLLV:
		tracker.write_int(instr.rd, builder.CreateShl(tracker.read_int(instr.rt),
		                                              builder.CreateAnd(tracker.read_int(instr.rs),
		                                                                ConstantInt::get(Type::getInt32Ty(ctx), 31), "ShiftMask"),
		                                              tracker.get_twine(instr.rd)));
		break;

	case Op::SRLV:
		tracker.write_int(instr.rd, builder.CreateLShr(tracker.read_int(instr.rt),
		                                               builder.CreateAnd(tracker.read_int(instr.rs),
		                                                                 ConstantInt::get(Type::getInt32Ty(ctx), 31), "ShiftMask"),
		                                               tracker.get_twine(instr.rd)));
		break;

	case Op::SRAV:
		tracker.write_int(instr.rd, builder.CreateAShr(tracker.read_int(instr.rt),
		                                               builder.CreateAnd(tracker.read_int(instr.rs),
		                                                                 ConstantInt::get(Type::getInt32Ty(ctx), 31), "ShiftMask"),
		                                               tracker.get_twine(instr.rd)));
		break;

	case Op::LUI:
		tracker.write_int(instr.rt, ConstantInt::get(Type::getInt32Ty(ctx), (instr.imm & 0xffff) << 16));
		break;

	case Op::MULT:
	{
		auto *mul = builder.CreateMul(builder.CreateSExt(tracker.read_int(instr.rs), Type::getInt64Ty(ctx), "MulSExt"),
		                              builder.CreateSExt(tracker.read_int(instr.rt), Type::getInt64Ty(ctx), "MulSExt"), "Mul");

		tracker.write_int(REG_LO, builder.CreateTrunc(mul, Type::getInt32Ty(ctx), "LO"));
		tracker.write_int(REG_HI, builder.CreateTrunc(builder.CreateLShr(mul, ConstantInt::get(Type::getInt64Ty(ctx), 32)),
		                                              Type::getInt32Ty(ctx), "HI"));
		break;
	}

	case Op::MULTU:
	{
		auto *mul = builder.CreateMul(builder.CreateZExt(tracker.read_int(instr.rs), Type::getInt64Ty(ctx), "MulZExt"),
		                              builder.CreateZExt(tracker.read_int(instr.rt), Type::getInt64Ty(ctx), "MulZExt"), "Mul");

		tracker.write_int(REG_LO, builder.CreateTrunc(mul, Type::getInt32Ty(ctx), "LO"));
		tracker.write_int(REG_HI, builder.CreateTrunc(builder.CreateLShr(mul, ConstantInt::get(Type::getInt64Ty(ctx), 32)),
		                                              Type::getInt32Ty(ctx), "HI"));
		break;
	}

	case Op::DIV:
	{
		auto *div = builder.CreateSDiv(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "LO");
		auto *rem = builder.CreateSRem(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "HI"); // Probably not correct.
		tracker.write_int(REG_LO, div);
		tracker.write_int(REG_HI, rem);
		break;
	}

	case Op::DIVU:
	{
		auto *div = builder.CreateUDiv(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "LO");
		auto *rem = builder.CreateURem(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "HI"); // Probably not correct.
		tracker.write_int(REG_LO, div);
		tracker.write_int(REG_HI, rem);
		break;
	}

	case Op::MFHI:
		tracker.write_int(instr.rd, tracker.read_int(REG_HI));
		break;

	case Op::MFLO:
		tracker.write_int(instr.rd, tracker.read_int(REG_LO));
		break;

	case Op::MTHI:
		tracker.write_int(REG_HI, tracker.read_int(instr.rs));
		break;

	case Op::MTLO:
		tracker.write_int(REG_LO, tracker.read_int(instr.rs));
		break;

	case Op::J:
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		tracker.flush();
		break;

	case Op::JAL:
	{
		Address target = instr.imm;
		tracker.write_int(REG_RA, ConstantInt::get(Type::getInt32Ty(ctx), addr + 8));

		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.flush();
		auto *call = create_call(recompiler, tracker.get_argument(), bb, target, addr + 8);
		if (call)
		{
			Value *values[] = { tracker.get_argument() };
			builder.SetInsertPoint(bb);
			builder.CreateCall(call, values);
		}
		tracker.invalidate();
		break;
	}

	case Op::JR:
	{
		Value *target = tracker.read_int(instr.rs);
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.set_builder(&builder);
		tracker.flush();

		auto *call = create_jump_indirect(recompiler, tracker.get_argument(), bb, target);
		auto *bb_call = BasicBlock::Create(ctx, "IndirectJumpPath", recompiler->get_current_function());
		auto *bb_return = BasicBlock::Create(ctx, "IndirectJumpReturn", recompiler->get_current_function());
		builder.SetInsertPoint(bb);
		builder.CreateCondBr(
			builder.CreateICmpNE(call,
			                     ConstantPointerNull::get(static_cast<PointerType *>(call->getType())), "jump_addr_cmp"),
			bb_call, bb_return);

		builder.SetInsertPoint(bb_call);
		Value *values[] = { tracker.get_argument() };
		builder.CreateCall(call, values);
		BranchInst::Create(bb_return, bb_call);

		builder.SetInsertPoint(bb_return);
		builder.CreateRetVoid();
		break;
	}

	case Op::JALR:
	{
		tracker.write_int(REG_RA, ConstantInt::get(Type::getInt32Ty(ctx), addr + 8));
		auto *target = tracker.read_int(instr.rs);

		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.flush();
		auto *call = create_call(recompiler, tracker.get_argument(), bb, target, addr + 8);
		Value *values[] = { tracker.get_argument() };
		builder.SetInsertPoint(bb);
		builder.CreateCall(call, values);
		tracker.invalidate();
		break;
	}

	case Op::BEQ:
	{
		auto *cmp = builder.CreateICmpEQ(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "BEQ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BNE:
	{
		auto *cmp = builder.CreateICmpNE(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "BNE");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BLTZ:
	{
		auto *cmp = builder.CreateICmpSLT(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0), "BLTZ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BGEZ:
	{
		auto *cmp = builder.CreateICmpSGE(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0), "BGEZ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BGTZ:
	{
		auto *cmp = builder.CreateICmpSGT(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0), "BGTZ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BLEZ:
	{
		auto *cmp = builder.CreateICmpSLE(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0), "BLEZ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BLTZAL:
	{
		auto *cmp = builder.CreateICmpSLT(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0), "BLTZ");
		Address target = instr.imm;
		tracker.write_int(REG_RA, ConstantInt::get(Type::getInt32Ty(ctx), addr + 8));

		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.flush();

		auto *bb_call = BasicBlock::Create(ctx, "IndirectCallPath", recompiler->get_current_function());
		auto *bb_merge = BasicBlock::Create(ctx, "IndirectCallMerge", recompiler->get_current_function());
		BranchInst::Create(bb_call, bb_merge, cmp, bb);
		bb = bb_merge;

		auto *call = create_call(recompiler, tracker.get_argument(), bb_call, target, addr + 8);
		if (call)
		{
			Value *values[] = { tracker.get_argument() };
			builder.SetInsertPoint(bb_call);
			builder.CreateCall(call, values);
		}
		tracker.invalidate();
		break;
	}

	case Op::BGEZAL:
	{
		auto *cmp = builder.CreateICmpSGE(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0), "BGEZ");
		Address target = instr.imm;
		tracker.write_int(REG_RA, ConstantInt::get(Type::getInt32Ty(ctx), addr + 8));

		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.flush();

		auto *bb_call = BasicBlock::Create(ctx, "IndirectCallPath", recompiler->get_current_function());
		auto *bb_merge = BasicBlock::Create(ctx, "IndirectCallMerge", recompiler->get_current_function());
		BranchInst::Create(bb_call, bb_merge, cmp, bb);
		bb = bb_merge;

		auto *call = create_call(recompiler, tracker.get_argument(), bb_call, target, addr + 8);
		if (call)
		{
			Value *values[] = { tracker.get_argument() };
			builder.SetInsertPoint(bb_call);
			builder.CreateCall(call, values);
		}
		tracker.invalidate();
		break;
	}

	case Op::SYSCALL:
	{
		tracker.flush();
		create_syscall(recompiler, tracker.get_argument(), bb, addr, instr.imm);
		tracker.invalidate();
		break;
	}

	case Op::BREAK:
	{
		tracker.flush();
		create_break(recompiler, tracker.get_argument(), bb, addr, instr.imm);
		builder.SetInsertPoint(bb);
		builder.CreateRetVoid();
		can_do_step_after = false;
		break;
	}

	case Op::LB:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load8(recompiler, tracker.get_argument(), bb,
		                            builder.CreateAdd(tracker.read_int(instr.rs),
		                                              ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "LBAddr"));
		builder.SetInsertPoint(bb);
		loaded = builder.CreateSExt(loaded, Type::getInt32Ty(ctx), tracker.get_twine(instr.rt));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LH:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load16(recompiler, tracker.get_argument(), bb,
		                             builder.CreateAdd(tracker.read_int(instr.rs),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "LHAddr"));
		builder.SetInsertPoint(bb);
		loaded = builder.CreateSExt(loaded, Type::getInt32Ty(ctx), tracker.get_twine(instr.rt));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LBU:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load8(recompiler, tracker.get_argument(), bb,
		                            builder.CreateAdd(tracker.read_int(instr.rs),
		                                              ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "LBAddr"));
		builder.SetInsertPoint(bb);
		loaded = builder.CreateZExt(loaded, Type::getInt32Ty(ctx), tracker.get_twine(instr.rt));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LHU:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load16(recompiler, tracker.get_argument(), bb,
		                             builder.CreateAdd(tracker.read_int(instr.rs),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "LHAddr"));
		builder.SetInsertPoint(bb);
		loaded = builder.CreateZExt(loaded, Type::getInt32Ty(ctx), tracker.get_twine(instr.rt));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LW:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load32(recompiler, tracker.get_argument(), bb,
		                             builder.CreateAdd(tracker.read_int(instr.rs),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "LWAddr"));
		builder.SetInsertPoint(bb);
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::SB:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_store8(recompiler, tracker.get_argument(), bb,
		              builder.CreateAdd(tracker.read_int(instr.rs),
		                                ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SBAddr"),
		              tracker.read_int(instr.rt));
		break;
	}

	case Op::SH:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_store16(recompiler, tracker.get_argument(), bb,
		               builder.CreateAdd(tracker.read_int(instr.rs),
		                                 ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SHAddr"),
		               tracker.read_int(instr.rt));
		break;
	}

	case Op::SW:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_store32(recompiler, tracker.get_argument(), bb,
		               builder.CreateAdd(tracker.read_int(instr.rs),
		                                 ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SWAddr"),
		               tracker.read_int(instr.rt));
		break;
	}

	case Op::LWL:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_lwl(recompiler, tracker.get_argument(), bb, tracker.read_int(instr.rt),
		                          builder.CreateAdd(tracker.read_int(instr.rs),
		                                            ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "LWLAddr"));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LWR:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_lwr(recompiler, tracker.get_argument(), bb, tracker.read_int(instr.rt),
		                          builder.CreateAdd(tracker.read_int(instr.rs),
		                                            ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "LWRAddr"));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::SWL:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_swl(recompiler, tracker.get_argument(), bb,
		           builder.CreateAdd(tracker.read_int(instr.rs),
		                             ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SWLAddr"),
		           tracker.read_int(instr.rt));
		break;
	}

	case Op::SWR:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_swr(recompiler, tracker.get_argument(), bb,
		           builder.CreateAdd(tracker.read_int(instr.rs),
		                             ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SWRAddr"),
		           tracker.read_int(instr.rt));
		break;
	}

	case Op::LWC1:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load32(recompiler, tracker.get_argument(), bb,
		                             builder.CreateAdd(tracker.read_int(instr.rs),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "LWC1Addr"));
		tracker.write_float(instr.rt, loaded);
		break;
	}

	case Op::SWC1:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_store32(recompiler, tracker.get_argument(), bb,
		               builder.CreateAdd(tracker.read_int(instr.rs),
		                                 ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SWAddr"),
		               tracker.read_float(instr.rt));
		break;
	}

	default:
		can_do_step_after = false;
		tracker.flush();
		create_sigill(recompiler, tracker.get_argument(), bb, addr);
		builder.SetInsertPoint(bb);
		builder.CreateRetVoid();
		break;
	}

	if (can_do_step_after && !mips_opcode_is_branch(instr.op))
		STEP_AFTER();
}

void MIPS::recompile_basic_block(
	Address start_addr, Address end_addr,
	Recompiler *recompiler, const Block &block, BasicBlock *bb, Value *args)
{
	RegisterTracker tracker(args);

	for (Address addr = start_addr; addr < end_addr; addr += 4)
	{
		IRBuilder<> builder(bb);
		tracker.set_builder(&builder);
		recompile_instruction(recompiler, bb, builder, tracker, addr);
		if (mips_opcode_is_branch(load_instr(addr).op))
			addr += 4;
	}

	if (block.terminator == Terminator::DirectBranch)
	{
		BranchInst::Create(recompiler->get_block_for_address(block.static_address_targets[0]), bb);
	}
}

Value *MIPS::create_call(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr, Address expected_return)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

#define CALL_AGGRESSIVE_JIT
#ifdef CALL_AGGRESSIVE_JIT
	if (!calls.predict_return)
	{
		Type *types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *function_type = FunctionType::get(Type::getVoidTy(ctx), types, false);
		calls.predict_return = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
		                                              "__recompiler_predict_return", recompiler->get_current_module());

	}

	Value *values[] = {
		argument,
		ConstantInt::get(Type::getInt32Ty(ctx), addr),
		ConstantInt::get(Type::getInt32Ty(ctx), expected_return)
	};
	builder.CreateCall(calls.predict_return, values);

	// Eagerly compile all our call-sites as well, can facilitate inlining! :D
	JITTIR::Recompiler tmp(&blocks);
	tmp.set_jitter(&jitter);
	tmp.set_backend(this);
	JITTIR::Function tmp_func;
	tmp_func.set_entry_address(addr);
	auto result = tmp.recompile_function(tmp_func, recompiler->get_current_module());

	Value *call_values[] = { argument };
	builder.CreateCall(result.function, call_values);
	return nullptr;
#else
	// Thunk out calls all the time, even when address is static.
	return create_call(recompiler, argument, bb, ConstantInt::get(Type::getInt32Ty(ctx), addr), expected_return);
#endif
}

Value *MIPS::create_call(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Address expected_return)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.call)
	{
		Type *stub_types[] = { Type::getInt32PtrTy(ctx) };
		FunctionType *stub_type = FunctionType::get(Type::getVoidTy(ctx), stub_types, false);
		PointerType *stub_ptr_type = PointerType::get(stub_type, 0);

		Type *types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *function_type = FunctionType::get(stub_ptr_type, types, false);
		calls.call = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
		                                    "__recompiler_call_addr", recompiler->get_current_module());
	}

	Value *values[] = {
		argument,
		addr,
		ConstantInt::get(Type::getInt32Ty(ctx), expected_return)
	};
	return builder.CreateCall(calls.call, values, "call_addr");
}

Value *MIPS::create_jump_indirect(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.jump_indirect)
	{
		Type *stub_types[] = { Type::getInt32PtrTy(ctx) };
		FunctionType *stub_type = FunctionType::get(Type::getVoidTy(ctx), stub_types, false);
		PointerType *stub_ptr_type = PointerType::get(stub_type, 0);

		Type *types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx) };
		auto *function_type = FunctionType::get(stub_ptr_type, types, false);
		calls.jump_indirect = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
		                                             "__recompiler_jump_indirect", recompiler->get_current_module());
	}

	Value *values[] = { argument, value };
	return builder.CreateCall(calls.jump_indirect, values, "jump_addr");
}

void MIPS::create_store32(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.store32)
	{
		Type *store_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.store32 = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                       "__recompiler_store32", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr, value };
	builder.CreateCall(calls.store32, values);
}

void MIPS::create_swl(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.swl)
	{
		Type *store_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.swl = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                   "__recompiler_swl", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr, value };
	builder.CreateCall(calls.swl, values);
}

void MIPS::create_swr(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.swr)
	{
		Type *store_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.swr = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                   "__recompiler_swr", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr, value };
	builder.CreateCall(calls.swr, values);
}

void MIPS::create_store16(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.store16)
	{
		Type *store_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.store16 = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                       "__recompiler_store16", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr, value };
	builder.CreateCall(calls.store16, values);
}

void MIPS::create_store8(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.store8)
	{
		Type *store_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.store8 = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_store8", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr, value };
	builder.CreateCall(calls.store8, values);
}

Value *MIPS::create_lwl(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *old_value, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.lwl)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *load_type = FunctionType::get(Type::getInt32Ty(ctx), load_types, false);
		calls.lwl = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                   "__recompiler_lwl", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr, old_value };
	return builder.CreateCall(calls.lwl, values);
}

Value *MIPS::create_lwr(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *old_value, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.lwr)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *load_type = FunctionType::get(Type::getInt32Ty(ctx), load_types, false);
		calls.lwr = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                   "__recompiler_lwr", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr, old_value };
	return builder.CreateCall(calls.lwr, values);
}

Value *MIPS::create_load32(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.load32)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx) };
		auto *load_type = FunctionType::get(Type::getInt32Ty(ctx), load_types, false);
		calls.load32 = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_load32", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr };
	return builder.CreateCall(calls.load32, values);
}

Value *MIPS::create_load16(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.load16)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx) };
		auto *load_type = FunctionType::get(Type::getInt16Ty(ctx), load_types, false);
		calls.load16 = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_load16", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr };
	return builder.CreateCall(calls.load16, values);
}

Value *MIPS::create_load8(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.load8)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx) };
		auto *load_type = FunctionType::get(Type::getInt8Ty(ctx), load_types, false);
		calls.load8 = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                     "__recompiler_load8", recompiler->get_current_module());
	}

	Value *values[] = { argument, addr };
	return builder.CreateCall(calls.load8, values);
}

void MIPS::create_sigill(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.sigill)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx) };
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.sigill = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_sigill", recompiler->get_current_module());
	}

	Value *values[] = { argument, ConstantInt::get(Type::getInt32Ty(ctx), addr) };
	builder.CreateCall(calls.sigill, values);
}

void MIPS::create_break(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr, uint32_t code)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.op_break)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.op_break = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                        "__recompiler_break", recompiler->get_current_module());
	}

	Value *values[] = { argument, ConstantInt::get(Type::getInt32Ty(ctx), addr), ConstantInt::get(Type::getInt32Ty(ctx), code) };
	builder.CreateCall(calls.op_break, values);
}

void MIPS::create_syscall(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr, uint32_t code)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.op_syscall)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.op_syscall = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                          "__recompiler_syscall", recompiler->get_current_module());
	}

	Value *values[] = { argument, ConstantInt::get(Type::getInt32Ty(ctx), addr), ConstantInt::get(Type::getInt32Ty(ctx), code) };
	builder.CreateCall(calls.op_syscall, values);
}

void MIPS::call_step(Recompiler *recompiler, Value *argument, BasicBlock *bb)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.step)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx) };
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.step = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                    "__recompiler_step", recompiler->get_current_module());
	}

	Value *values[] = { argument };
	builder.CreateCall(calls.step, values);
}

void MIPS::call_step_after(Recompiler *recompiler, Value *argument, BasicBlock *bb)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.step_after)
	{
		Type *load_types[] = { Type::getInt32PtrTy(ctx) };
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.step_after = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                          "__recompiler_step_after", recompiler->get_current_module());
	}

	Value *values[] = { argument };
	builder.CreateCall(calls.step_after, values);
}

template <typename Call>
static void call_int(MIPS &mips, const std::unordered_map<std::string, Address> &symbol_table, const char *sym, int32_t a, int32_t b, const Call &call)
{
	mips.scalar_registers[REG_A0] = a;
	mips.scalar_registers[REG_A1] = b;
	auto test = symbol_table.find(sym)->second;
	mips.enter(test);
	call(mips.scalar_registers[REG_V0], mips.scalar_registers[REG_V1]);
}

int main(int argc, char **argv)
{
	MIPS mips;
	Elf32_Ehdr ehdr;
	std::unordered_map<std::string, Address> symbol_table;
	if (!load_elf(argv[1], ehdr, mips.get_address_space(), symbol_table))
		return 1;

	mips.scalar_registers[REG_SP] = symbol_table.find("__recompiler_stack")->second + 64 * 1024 - 16;

	mips.enter(ehdr.e_entry);
	std::terminate(); // Should never happen.
}