#include <elf.h>
#include <unistd.h>
#include "mips.hpp"
#include "cli_parser.hpp"
#include <dlfcn.h>

using namespace JITTIR;

static void setup_abi_stack(MIPS &mips, const Elf32_Ehdr &ehdr, const ElfMiscData &misc, int argc, char **argv)
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
			stack_top &= ~3;
			stack_data.push_back(stack_top);
			mips.get_address_space().copy_to_user(stack_top, argv[i], arg_len);
		}

		// Terminate argv
		stack_data.push_back(0);

		// Null Environment
		stack_data.push_back(0);

		// ELF AUXV (used by musl).
		stack_data.push_back(AT_PHDR);
		stack_data.push_back(misc.phdr_addr);
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

static void print_help()
{
	fprintf(stderr,
	        "Usage: <ELF>\n"
	        "\t[--help]\n"
	        "\t[--static-lib <lib>]\n"
	        "\t[--static-symbols <lib>]\n"
	        "\t[--dump-llvm <dir>]\n"
	        "\t[--debug-step]\n"
	        "\t[--debug-load-store-registers]\n"
	        "\t[--disable-inline-calls]\n"
	        "\t[--thunk-load-store]\n"
	        "\t[--log-modules]\n"
	        "\t[--optimize]\n"
	        "\t[--validate]\n"
	        "\n");
}
int main(int argc, char **argv)
{
	CLICallbacks cbs;

	MIPS::Options opts;

	std::string static_lib;
	std::string static_symbols;
	std::string mips_binary;
	std::string llvm_dir;
	std::string entry;

	cbs.add("--help", [&](CLIParser &parser) {
		print_help();
		parser.end();
	});

	cbs.add("--debug-load-store-registers", [&](CLIParser &) {
		opts.debug_load_store_registers = true;
		opts.inline_load_store = false;
	});

	cbs.add("--thunk-load-store", [&](CLIParser &) {
		opts.inline_load_store = false;
	});

	cbs.add("--disable-inline-calls", [&](CLIParser &) {
		opts.inline_static_address_calls = false;
	});

	cbs.add("--debug-step", [&](CLIParser &) {
		opts.debug_step = true;
	});

	cbs.add("--static-lib", [&](CLIParser &parser) {
		static_lib = parser.next_string();
	});

	cbs.add("--static-symbols", [&](CLIParser &parser) {
		static_symbols = parser.next_string();
	});

	cbs.add("--dump-llvm", [&](CLIParser &parser) {
		llvm_dir = parser.next_string();
	});

	cbs.add("--log-modules", [&](CLIParser &) {
		opts.log_modules = true;
	});

	cbs.add("--entry", [&](CLIParser &parser) {
		entry = parser.next_string();
	});

	cbs.add("--validate", [&](CLIParser &) {
		opts.validate_modules = true;
	});

	cbs.add("--optimize", [&](CLIParser &) {
		opts.optimize_modules = true;
	});

	cbs.default_handler = [&](const char *def) {
		mips_binary = def;
	};

	CLIParser parser(std::move(cbs), argc - 1, argv + 1);
	if (!parser.parse())
	{
		print_help();
		return 1;
	}
	else if (parser.is_ended_state())
		return 0;

	auto mips = MIPS::create();
	mips->set_options(opts);

	if (mips_binary.empty())
	{
		fprintf(stderr, "Need MIPS binary.\n");
		return 1;
	}

	if (!llvm_dir.empty())
		mips->set_external_ir_dump_directory(llvm_dir);

	void *dylib = nullptr;
	if (!static_lib.empty())
	{
		dylib = dlopen(static_lib.c_str(), RTLD_NOW);
		if (!dylib)
		{
			fprintf(stderr, "Failed to open dylib: %s (%s)\n", static_lib.c_str(), dlerror());
			return 1;
		}
	}

	if (!static_symbols.empty())
	{
		if (!dylib)
		{
			fprintf(stderr, "Need a dylib to use --static-symbols.\n");
			return 1;
		}

		FILE *f = fopen(static_symbols.c_str(), "rb");
		if (!f)
		{
			fprintf(stderr, "Failed to open %s for reading.\n", static_symbols.c_str());
			return 1;
		}

		Address addr;
		while (fread(&addr, sizeof(addr), 1, f) == 1)
		{
			std::string sym = "_" + std::to_string(addr);
			auto *callable = (void (*)(VirtualMachineState *)) dlsym(dylib, sym.c_str());
			if (callable)
				mips->set_external_symbol(addr, callable);
			else
				fprintf(stderr, "Could not find symbol: %s\n", sym.c_str());
		}

		fclose(f);
	}

	Elf32_Ehdr ehdr;
	ElfMiscData misc;
	if (!load_elf(mips_binary.c_str(), ehdr, mips->get_address_space(), mips->get_symbol_table(), misc))
		return 1;

	mips->set_big_endian(misc.big_endian);
	mips->scalar_registers[REG_TLS] = misc.tls_base;
	setup_abi_stack(*mips, ehdr, misc, argc, argv);

	Address addr;
	if (entry.empty())
		addr = ehdr.e_entry;
	else
	{
		auto &table = mips->get_symbol_table();
		auto itr = table.symbol_to_address.find(entry);
		if (itr == table.symbol_to_address.end())
		{
			fprintf(stderr, "Failed to find symbol %s in ELF.\n", entry.c_str());
			return 1;
		}
		else
			addr = itr->second;
	}

	for (;;)
	{
		auto result = mips->enter(addr);
		switch (result.condition)
		{
		case MIPS::ExitCondition::ExitTooDeepJumpStack:
		case MIPS::ExitCondition::ExitTooDeepStack:
			addr = result.pc;
			break;

		case MIPS::ExitCondition::JumpToZero:
			goto end;

		default:
			return 1;
		}
	}

end:
	fprintf(stderr, "Returned to PC 0, treating it as a clean exit.\n");
	fprintf(stderr, "Scalar registers:\n");
	for (int i = 1; i < 32; i++)
		fprintf(stderr, "  %s = %d\n", get_scalar_register_name(i), mips->scalar_registers[i]);
	return 0;
}