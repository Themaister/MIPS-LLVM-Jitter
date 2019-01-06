#include <elf.h>
#include <unistd.h>
#include "mips.hpp"

using namespace JITTIR;

static void setup_abi_stack(MIPS &mips, const Elf32_Ehdr &ehdr, uint32_t phdr, int argc, char **argv)
{
	uint32_t stack = mips.get_address_space().allocate_stack(1024 * 1024);

	if (stack)
	{
		Address stack_top = stack + 1024 * 1024 - 16;

		// Copy the argc/argv to stack.
		bool found = false;
		while (argc > 0 && !found)
		{
			if (*argv && strcmp(*argv, "--") == 0)
				found = true;

			argc--;
			argv++;
		}

		// Place argv.
		std::vector<Address> stack_data;
		stack_data.push_back(Address(argc));

		for (int i = 0; i < argc; i++)
		{
			size_t arg_len = strlen(argv[i]) + 1;
			stack_top -= arg_len;
			stack_data.push_back(stack_top);

			// Copy the argument.
			for (size_t j = 0; j < arg_len; j++)
				mips.store8(Address(stack_top + j), uint8_t(argv[i][j]));
		}

		// Terminate argv
		stack_data.push_back(0);

		// Null Environment
		stack_data.push_back(0);

		// ELF AUXV (used by musl).
		stack_data.push_back(AT_PHDR);
		stack_data.push_back(phdr);
		stack_data.push_back(AT_PHENT);
		stack_data.push_back(ehdr.e_phentsize);
		stack_data.push_back(AT_PHNUM);
		stack_data.push_back(ehdr.e_phnum);
		stack_data.push_back(AT_PAGESZ);
		stack_data.push_back(VirtualAddressSpace::PageSize);
		stack_data.push_back(AT_ENTRY);
		stack_data.push_back(ehdr.e_entry);
		stack_data.push_back(AT_UID);
		stack_data.push_back(getuid());
		stack_data.push_back(AT_EUID);
		stack_data.push_back(geteuid());
		stack_data.push_back(AT_GID);
		stack_data.push_back(getgid());
		stack_data.push_back(AT_EGID);
		stack_data.push_back(getegid());
		stack_data.push_back(AT_RANDOM);
		stack_data.push_back(stack_top); // Just point to something. glibc needs this.
		stack_data.push_back(AT_NULL);

		// Allocate stack.
		stack_top -= sizeof(Address) * stack_data.size();
		stack_top &= ~15;

		for (uint32_t i = 0; i < stack_data.size(); i++)
			mips.store32(stack_top + 4 * i, stack_data[i]);

		mips.scalar_registers[REG_SP] = stack_top;
	}
}

int main(int argc, char **argv)
{
	MIPS mips;
	Elf32_Ehdr ehdr;
	uint32_t phdr;
	if (!load_elf(argv[1], ehdr, mips.get_address_space(), mips.get_symbol_table(),
	              mips.scalar_registers[REG_TLS], phdr))
		return 1;

	setup_abi_stack(mips, ehdr, phdr, argc, argv);

	Address addr = ehdr.e_entry;
	for (;;)
	{
		auto result = mips.enter(addr);
		switch (result.condition)
		{
		case MIPS::ExitCondition::ExitTooDeepJumpStack:
		case MIPS::ExitCondition::ExitTooDeepStack:
			addr = result.pc;
			break;

		case MIPS::ExitCondition::JumpToZero:
			return 0;

		default:
			return 1;
		}
	}
}