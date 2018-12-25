#include "jitter.hpp"
#include "llvm/IR/Verifier.h"

using namespace llvm;

int main()
{
	Jitter::init_global();
	Jitter jitter;
	auto test = jitter.create_module("test");
	auto &ctx = test->getContext();
	IRBuilder<> builder(ctx);

	Type *arg_types[] = { Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };

	auto *function_type = FunctionType::get(Type::getInt32Ty(ctx), arg_types, false);
	auto *func = Function::Create(function_type, Function::ExternalLinkage, "test", test.get());

	auto *bb = BasicBlock::Create(ctx, "entry", func);
	auto *b1 = BasicBlock::Create(ctx, "a", func);
	auto *b2 = BasicBlock::Create(ctx, "b", func);
	auto *merge = BasicBlock::Create(ctx, "merge", func);

	Value *arg = &func->args().begin()[0];
	Value *arg2 = &func->args().begin()[1];

	builder.SetInsertPoint(bb);
	auto *cmp = builder.CreateICmpEQ(arg, ConstantInt::get(Type::getInt32Ty(ctx), 20));
	BranchInst::Create(b1, b2, cmp, bb);

	builder.SetInsertPoint(b1);
	auto *v1 = builder.CreateAdd(arg2, ConstantInt::get(Type::getInt32Ty(ctx), 40));
	builder.SetInsertPoint(b2);
	auto *v2 = builder.CreateMul(arg2, ConstantInt::get(Type::getInt32Ty(ctx), 40));
	BranchInst::Create(merge, b1);
	BranchInst::Create(merge, b2);

	builder.SetInsertPoint(merge);
	auto *phi = builder.CreatePHI(Type::getInt32Ty(ctx), 2);
	phi->addIncoming(v1, b1);
	phi->addIncoming(v2, b2);
	builder.CreateRet(phi);

	verifyFunction(*func, &errs());

	jitter.add_module(std::move(test));
	auto ptr = (int (*)(int, int))jitter.get_symbol_address("test");
	int v = ptr(20, 50);
	;
}
