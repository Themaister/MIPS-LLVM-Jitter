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

	auto *vec = VectorType::get(Type::getFloatTy(ctx), 8);
	auto *vecptr = PointerType::get(vec, 0);
	Type *arg_types[] = { vecptr };

	auto *function_type = FunctionType::get(Type::getVoidTy(ctx), arg_types, false);
	auto *func = Function::Create(function_type, Function::ExternalLinkage, "test", test.get());

	auto *bb = BasicBlock::Create(ctx, "entry", func);
	builder.SetInsertPoint(bb);

	Value *arg = &func->args().begin()[0];

	auto *loaded = builder.CreateAlignedLoad(arg, 4, "loaded");
	auto *added = builder.CreateFAdd(loaded, loaded);
	auto *cvec = ConstantVector::getSplat(8, ConstantFP::get(Type::getFloatTy(ctx), 40.0f));
	added = builder.CreateFMul(added, cvec);
	builder.CreateAlignedStore(added, arg, 4);
	builder.CreateRetVoid();

	verifyFunction(*func, &errs());

	jitter.add_module(std::move(test));
	auto ptr = (void (*)(float *))jitter.get_symbol_address("test");

	float blocks[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	ptr(blocks);
	;
}
