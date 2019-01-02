#include "jitter.hpp"
#include "llvm/IR/DataLayout.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"
#include <future>

using namespace llvm;
using namespace orc;

namespace JITTIR
{
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
#ifdef JITTER_LLVM_VERSION_LEGACY
	return std::make_unique<Module>(name, context);
#else
	return std::make_unique<Module>(name, *context.getContext());
#endif
}

void Jitter::add_external_symbol_generic(const std::string &name, uint64_t symbol)
{
	externals[name] = symbol;
}

struct JitterInit
{
	JitterInit()
	{
		Jitter::init_global();
	}
};

Jitter::Jitter()
{
	static JitterInit jitter_init;

#ifndef JITTER_LLVM_VERSION_LEGACY
	context = std::make_unique<LLVMContext>();
#endif
	execution_session = std::make_unique<ExecutionSession>();
	execution_session->setErrorReporter([](Error error) {
		if (error)
			errs() << "Error: " << error << "\n";
	});

#ifdef JITTER_LLVM_VERSION_LEGACY
	RTDyldObjectLinkingLayer::Resources resources;
#else
	LegacyRTDyldObjectLinkingLayer::Resources resources;
#endif
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

#ifdef JITTER_LLVM_VERSION_LEGACY
	object_layer = std::make_unique<RTDyldObjectLinkingLayer>(*execution_session,
	                                                          [=](VModuleKey) { return resources; });
#else
	object_layer = std::make_unique<LegacyRTDyldObjectLinkingLayer>(*execution_session, [=](VModuleKey) { return resources; });
#endif

	auto host = JITTargetMachineBuilder::detectHost();
	target_machine = cantFail(host->createTargetMachine());
	target_machine->setOptLevel(CodeGenOpt::Level::Default);

#ifdef JITTER_LLVM_VERSION_LEGACY
	data_layout = std::make_unique<DataLayout>(target_machine->createDataLayout());
#else
	data_layout = std::make_unique<DataLayout>(std::move(*host->getDefaultDataLayoutForTarget()));
#endif
	mangler = std::make_unique<MangleAndInterner>(*execution_session, *data_layout);

#ifdef JITTER_LLVM_VERSION_LEGACY
	compile_layer = std::make_unique<IRCompileLayer<
		RTDyldObjectLinkingLayer, SimpleCompiler>>(*object_layer, SimpleCompiler(*target_machine));
#else
	compile_layer = std::make_unique<LegacyIRCompileLayer<
		LegacyRTDyldObjectLinkingLayer, SimpleCompiler>>(*object_layer, SimpleCompiler(*target_machine));
#endif
}

Jitter::ModuleHandle Jitter::add_module(std::unique_ptr<Module> module)
{
	legacy::FunctionPassManager pass_manager(module.get());
	pass_manager.add(createConstantPropagationPass());
	pass_manager.add(createInstructionCombiningPass());
	pass_manager.add(createCFGSimplificationPass());
	pass_manager.add(createAggressiveDCEPass());
	pass_manager.add(createLoopSimplifyCFGPass());
	pass_manager.add(createLICMPass());
	pass_manager.add(createLoopSinkPass());
	pass_manager.add(createReassociatePass());
	pass_manager.add(createNewGVNPass());
	pass_manager.doInitialization();
	for (auto &func : *module)
		pass_manager.run(func);

	std::error_code err;
	llvm::raw_fd_ostream ostr(std::string("/tmp/llvm/") + module->getSourceFileName() + ".ll", err);
	module->print(ostr, nullptr);

	//module->print(errs(), nullptr);
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
}
