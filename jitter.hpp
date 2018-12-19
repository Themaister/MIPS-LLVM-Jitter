#pragma once

#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include <memory>
#include <unordered_map>

class Jitter
{
public:
	Jitter();
	static void init_global();

	using ModuleHandle = llvm::orc::VModuleKey;

	ModuleHandle add_module(std::unique_ptr<llvm::Module> module);
	void remove_module(ModuleHandle module);

	llvm::LLVMContext &get_context();

	llvm::JITSymbol find_symbol(const std::string &name);
	llvm::JITTargetAddress get_symbol_address(const std::string &name);

	std::unique_ptr<llvm::Module> create_module(const std::string &name);
	llvm::IRBuilder<> create_builder();

	template <typename T>
	void add_external_symbol(const std::string &name, T sym)
	{
		add_external_symbol_generic(name, (uint64_t)sym);
	}

	void add_external_symbol_generic(const std::string &name, uint64_t symbol);

private:
	std::unique_ptr<llvm::LLVMContext> context;
	std::unique_ptr<llvm::orc::ExecutionSession> execution_session;
	std::unique_ptr<llvm::orc::RTDyldObjectLinkingLayer> object_layer;
	std::shared_ptr<llvm::SectionMemoryManager> memory_manager;

	std::unique_ptr<llvm::orc::IRCompileLayer<
		llvm::orc::RTDyldObjectLinkingLayer,
		llvm::orc::SimpleCompiler>> compile_layer;

	std::unique_ptr<llvm::TargetMachine> target_machine;
	std::unique_ptr<llvm::DataLayout> data_layout;
	std::unique_ptr<llvm::orc::MangleAndInterner> mangle_and_interner;
	std::unordered_map<std::string, uint64_t> externals;
};

