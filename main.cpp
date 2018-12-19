#include "jitter.hpp"
#include "llvm/IR/Verifier.h"

using namespace llvm;

int main()
{
	Jitter::init_global();
	Jitter jitter;
	auto &ctx = jitter.get_context();
	auto test = jitter.create_module("test");
	auto builder = jitter.create_builder();

	std::vector<Type *> types{ Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
	auto *function_type = FunctionType::get(Type::getInt32Ty(ctx), types, false);
	auto *func = Function::Create(function_type, Function::ExternalLinkage,
	                              "test", test.get());

	auto *bb = BasicBlock::Create(ctx, "entry", func);
	builder.SetInsertPoint(bb);

	Value *lhs = &func->args().begin()[0];
	Value *rhs = &func->args().begin()[1];

	auto *tmp = builder.CreateAdd(lhs, rhs);
	builder.CreateRet(tmp);

	verifyFunction(*func, &errs());

	jitter.add_module(std::move(test));
	auto ptr = (int (*)(int, int))jitter.get_symbol_address("test");
	int r = ptr(90, 40);
	;
}
