#include "mips.hpp"

using namespace JITTIR;

static void setup_abi_stack(MIPS &mips, int argc, char **argv)
{
	auto &symbol_table = mips.get_symbol_table();
	auto itr = symbol_table.find("__recompiler_stack_size");
	if (itr != symbol_table.end())
	{
		uint32_t stack_size = mips.load32(itr->second);
		itr = symbol_table.find("__recompiler_stack");
		if (itr != symbol_table.end())
		{
			Address stack_top = itr->second + stack_size - 16;

			// Copy the argc/argv to stack.
			bool found = false;
			while (argc > 0 && !found)
			{
				if (*argv && strcmp(*argv, "--") == 0)
					found = true;

				argc--;
				argv++;
			}

			std::vector<Address> argv_pointers(argc + 1);
			for (int i = 0; i < argc; i++)
			{
				size_t arg_len = strlen(argv[i]) + 1;
				stack_top -= arg_len;
				argv_pointers[i] = stack_top;

				// Copy the argument.
				for (size_t j = 0; j < arg_len; j++)
					mips.store8(Address(stack_top + j), uint8_t(argv[i][j]));
			}
			argv_pointers[argc] = 0;
			stack_top &= ~15;
			stack_top -= 4 * (argc + 2);
			mips.store32(stack_top, uint32_t(argc));
			for (int i = 0; i < argc + 1; i++)
				mips.store32(stack_top + 4 + 4 * i, argv_pointers[i]);

			mips.scalar_registers[REG_SP] = stack_top;
		}
	}
}
int main(int argc, char **argv)
{
	MIPS mips;
	Elf32_Ehdr ehdr;
	if (!load_elf(argv[1], ehdr, mips.get_address_space(), mips.get_symbol_table()))
		return 1;

	setup_abi_stack(mips, argc, argv);

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