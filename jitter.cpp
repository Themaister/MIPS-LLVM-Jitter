#include "jitter.hpp"
#include "llvm/IR/DataLayout.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;
using namespace orc;

void Jitter::init_global()
{
	InitializeNativeTarget();
	InitializeNativeTargetAsmPrinter();
	InitializeNativeTargetAsmParser();
}

LLVMContext &Jitter::get_context()
{
	return *context;
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
	return std::make_unique<Module>(name, *context);
}

IRBuilder<> Jitter::create_builder()
{
	return IRBuilder<>(*context);
}

Jitter::Jitter()
{
	context = std::make_unique<LLVMContext>();
	execution_session = std::make_unique<ExecutionSession>();
	memory_manager = std::make_shared<SectionMemoryManager>();

	RTDyldObjectLinkingLayer::Resources resources;
	resources.MemMgr = memory_manager;
	resources.Resolver = createLegacyLookupResolver(
		*execution_session,
		[this](const std::string &name) -> JITSymbol {
			if (auto sym = compile_layer->findSymbol(name, false))
				return sym;
			else if (auto sym_addr = RTDyldMemoryManager::getSymbolAddressInProcess(name))
				return JITSymbol(sym_addr, JITSymbolFlags::Exported);
			else
				return nullptr;
		},
		[](Error) {}
	);

	object_layer = std::make_unique<RTDyldObjectLinkingLayer>(
		*execution_session,
		[this, resources](VModuleKey) { return resources; });

	auto host = JITTargetMachineBuilder::detectHost();
	target_machine = std::move(cantFail(host->createTargetMachine()));
	data_layout = std::make_unique<DataLayout>(target_machine->createDataLayout());

	compile_layer = std::make_unique<IRCompileLayer<
		RTDyldObjectLinkingLayer,
		SimpleCompiler>>(*object_layer,
	                     SimpleCompiler(*target_machine));

	sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
}

Jitter::ModuleHandle Jitter::add_module(std::unique_ptr<Module> module)
{
	module->print(errs(), nullptr);

	auto K = execution_session->allocateVModule();
	auto error = compile_layer->addModule(K, std::move(module));
	if (!error)
		return K;
	else
	{
		errs() << "Failed to add module: " << error << "\n";
		return 0;
	}
}

void Jitter::remove_module(Jitter::ModuleHandle module)
{
	auto error = compile_layer->removeModule(module);
	if (!error.success())
		llvm::errs() << "Failed to remove module: " << module << "\n";
}
