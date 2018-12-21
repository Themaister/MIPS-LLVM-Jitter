#include "jitter.hpp"
#include "llvm/IR/DataLayout.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include <future>

using namespace llvm;
using namespace orc;

void Jitter::init_global()
{
	InitializeNativeTarget();
	InitializeNativeTargetAsmPrinter();
	InitializeNativeTargetAsmParser();
}

JITSymbol Jitter::find_symbol(const std::string &name)
{
#if 0
	std::promise<JITSymbol> symbol;
	SymbolNameSet symbols{(*mangler)(name)};
	auto OnReady = [](Error) {
		errs() << "Ready!\n";
	};
	auto OnResolve = [&](Expected<SymbolMap> m) {
		errs() << "Resolve!\n";
		SymbolStringPtr str;
		symbol.set_value(m.get().find(str)->second);
	};
	JITDylibSearchList search_list = {{ &execution_session->getMainJITDylib() , false }};
	execution_session->lookup(search_list, symbols,
	                          std::move(OnResolve), std::move(OnReady), NoDependenciesToRegister);

	return symbol.get_future().get();
#else
	return cantFail(execution_session->lookup({ &execution_session->getMainJITDylib() }, (*mangler)(name)));
#endif
}

JITTargetAddress Jitter::get_symbol_address(const std::string &name)
{
	return cantFail(find_symbol(name).getAddress());
}

std::unique_ptr<Module> Jitter::create_module(const std::string &name)
{
	return std::make_unique<Module>(name, *context.getContext());
}

void Jitter::add_external_symbol_generic(const std::string &name, uint64_t symbol)
{
	externals[name] = symbol;
}

Jitter::Jitter()
	: context(std::make_unique<LLVMContext>())
{
	execution_session = std::make_unique<ExecutionSession>();
	execution_session->setErrorReporter([](Error error) {
		errs() << "Error: " << error << "\n";
	});


#if 0
	RTDyldObjectLinkingLayer::Resources resources;
	resources.MemMgr = memory_manager;
	resources.Resolver = createLegacyLookupResolver(
		*execution_session,
		[this](const std::string &name) -> JITSymbol {
			auto itr = externals.find(name);
			if (itr != std::end(externals))
				return JITSymbol(itr->second, JITSymbolFlags::Exported);
			else if (auto sym = compile_layer->findSymbol(name, false))
				return sym;
			else if (auto sym_addr = RTDyldMemoryManager::getSymbolAddressInProcess(name))
				return JITSymbol(sym_addr, JITSymbolFlags::Exported);
			else
				return nullptr;
		},
		[](Error) {}
	);
#endif

	object_layer = std::make_unique<RTDyldObjectLinkingLayer>(*execution_session,
	                                                          []() { return std::make_unique<SectionMemoryManager>(); });

	auto host = JITTargetMachineBuilder::detectHost();
	//auto target_machine = cantFail(host->createTargetMachine());
	data_layout = std::make_unique<DataLayout>(std::move(*host->getDefaultDataLayoutForTarget()));
	mangler = std::make_unique<MangleAndInterner>(*execution_session, *data_layout);

	compile_layer = std::make_unique<IRCompileLayer>(*execution_session,
	                                                 *object_layer,
	                                                 ConcurrentIRCompiler(cantFail(std::move(host))));

	execution_session->getMainJITDylib().setGenerator(cantFail(DynamicLibrarySearchGenerator::GetForCurrentProcess(*data_layout)));
}

void Jitter::add_module(std::unique_ptr<Module> module)
{
	module->print(errs(), nullptr);

	auto error = compile_layer->add(execution_session->getMainJITDylib(),
	                                ThreadSafeModule(std::move(module), context));
	if (error)
		errs() << "Failed to add module: " << error << "\n";

	execution_session->dump(errs());
}

#if 0
void Jitter::remove_module(Jitter::ModuleHandle module)
{
	auto error = compile_layer->removeModule(module);
	if (!error.success())
		llvm::errs() << "Failed to remove module: " << module << "\n";
}
#endif
