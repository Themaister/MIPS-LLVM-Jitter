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
	return compile_layer->findSymbol(name, false);
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

	LegacyRTDyldObjectLinkingLayer::Resources resources;
	resources.MemMgr = std::make_shared<SectionMemoryManager>();
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

	object_layer = std::make_unique<LegacyRTDyldObjectLinkingLayer>(*execution_session, [=](VModuleKey) { return resources; });

	auto host = JITTargetMachineBuilder::detectHost();
	target_machine = cantFail(host->createTargetMachine());
	data_layout = std::make_unique<DataLayout>(std::move(*host->getDefaultDataLayoutForTarget()));
	mangler = std::make_unique<MangleAndInterner>(*execution_session, *data_layout);
	compile_layer = std::make_unique<LegacyIRCompileLayer<
	    LegacyRTDyldObjectLinkingLayer, SimpleCompiler>>(*object_layer, SimpleCompiler(*target_machine));
}

Jitter::ModuleHandle Jitter::add_module(std::unique_ptr<Module> module)
{
	module->print(errs(), nullptr);
	auto K = execution_session->allocateVModule();
	auto error = compile_layer->addModule(K, std::move(module));
	if (error)
		return 0;
	else
		return K;
}

void Jitter::remove_module(Jitter::ModuleHandle module)
{
	auto error = compile_layer->removeModule(module);
	if (!error.success())
		llvm::errs() << "Failed to remove module: " << module << "\n";
}
