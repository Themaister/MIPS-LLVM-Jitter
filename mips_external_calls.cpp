#include "mips.hpp"

using namespace llvm;

namespace JITTIR
{
Value *MIPS::create_call(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr, Address expected_return)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

#define CALL_AGGRESSIVE_JIT
#ifdef CALL_AGGRESSIVE_JIT
	if (!calls.predict_return)
	{
		Type *types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *function_type = FunctionType::get(Type::getVoidTy(ctx), types, false);
		calls.predict_return = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
		                                              "__recompiler_predict_return", recompiler->get_current_module());

	}

	Value *values[] = {
			argument,
			ConstantInt::get(Type::getInt32Ty(ctx), addr),
			ConstantInt::get(Type::getInt32Ty(ctx), expected_return)
	};
	builder.CreateCall(calls.predict_return, values);

	// Eagerly compile all our call-sites as well, can facilitate inlining! :D
	JITTIR::Recompiler tmp(&blocks);
	tmp.set_jitter(&jitter);
	tmp.set_backend(this);
	JITTIR::Function tmp_func;
	tmp_func.set_entry_address(addr);
	tmp_func.set_backend(this);
	auto result = tmp.recompile_function(tmp_func, recompiler->get_current_module());

	Value *call_values[] = {argument};
	builder.CreateCall(result.function, call_values);
	return nullptr;
#else
	// Thunk out calls all the time, even when address is static.
	return create_call(recompiler, argument, bb, ConstantInt::get(Type::getInt32Ty(ctx), addr), expected_return);
#endif
}

Value *MIPS::create_call(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Address expected_return)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.call)
	{
		Type *stub_types[] = {Type::getInt32PtrTy(ctx)};
		FunctionType *stub_type = FunctionType::get(Type::getVoidTy(ctx), stub_types, false);
		PointerType *stub_ptr_type = PointerType::get(stub_type, 0);

		Type *types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *function_type = FunctionType::get(stub_ptr_type, types, false);
		calls.call = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
		                                    "__recompiler_call_addr", recompiler->get_current_module());
	}

	Value *values[] = {
			argument,
			addr,
			ConstantInt::get(Type::getInt32Ty(ctx), expected_return)
	};
	return builder.CreateCall(calls.call, values, "call_addr");
}

Value *MIPS::create_jump_indirect(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.jump_indirect)
	{
		Type *stub_types[] = {Type::getInt32PtrTy(ctx)};
		FunctionType *stub_type = FunctionType::get(Type::getVoidTy(ctx), stub_types, false);
		PointerType *stub_ptr_type = PointerType::get(stub_type, 0);

		Type *types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx)};
		auto *function_type = FunctionType::get(stub_ptr_type, types, false);
		calls.jump_indirect = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
		                                             "__recompiler_jump_indirect", recompiler->get_current_module());
	}

	Value *values[] = {argument, value};
	return builder.CreateCall(calls.jump_indirect, values, "jump_addr");
}

void MIPS::create_store32(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.store32)
	{
		Type *store_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.store32 = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                       "__recompiler_store32", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr, value};
	builder.CreateCall(calls.store32, values);
}

void MIPS::create_swl(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.swl)
	{
		Type *store_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.swl = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                   "__recompiler_swl", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr, value};
	builder.CreateCall(calls.swl, values);
}

void MIPS::create_swr(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.swr)
	{
		Type *store_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.swr = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                   "__recompiler_swr", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr, value};
	builder.CreateCall(calls.swr, values);
}

void MIPS::create_store16(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.store16)
	{
		Type *store_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.store16 = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                       "__recompiler_store16", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr, value};
	builder.CreateCall(calls.store16, values);
}

void MIPS::create_store8(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr, Value *value)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.store8)
	{
		Type *store_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *store_type = FunctionType::get(Type::getVoidTy(ctx), store_types, false);
		calls.store8 = llvm::Function::Create(store_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_store8", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr, value};
	builder.CreateCall(calls.store8, values);
}

Value *MIPS::create_lwl(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *old_value, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.lwl)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *load_type = FunctionType::get(Type::getInt32Ty(ctx), load_types, false);
		calls.lwl = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                   "__recompiler_lwl", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr, old_value};
	return builder.CreateCall(calls.lwl, values);
}

Value *MIPS::create_lwr(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *old_value, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.lwr)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *load_type = FunctionType::get(Type::getInt32Ty(ctx), load_types, false);
		calls.lwr = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                   "__recompiler_lwr", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr, old_value};
	return builder.CreateCall(calls.lwr, values);
}

Value *MIPS::create_load32(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.load32)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx)};
		auto *load_type = FunctionType::get(Type::getInt32Ty(ctx), load_types, false);
		calls.load32 = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_load32", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr};
	return builder.CreateCall(calls.load32, values);
}

Value *MIPS::create_load16(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.load16)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx)};
		auto *load_type = FunctionType::get(Type::getInt16Ty(ctx), load_types, false);
		calls.load16 = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_load16", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr};
	return builder.CreateCall(calls.load16, values);
}

Value *MIPS::create_load8(Recompiler *recompiler, Value *argument, BasicBlock *bb, Value *addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.load8)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx)};
		auto *load_type = FunctionType::get(Type::getInt8Ty(ctx), load_types, false);
		calls.load8 = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                     "__recompiler_load8", recompiler->get_current_module());
	}

	Value *values[] = {argument, addr};
	return builder.CreateCall(calls.load8, values);
}

void MIPS::create_sigill(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.sigill)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx)};
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.sigill = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                      "__recompiler_sigill", recompiler->get_current_module());
	}

	Value *values[] = {argument, ConstantInt::get(Type::getInt32Ty(ctx), addr)};
	builder.CreateCall(calls.sigill, values);
}

void MIPS::create_break(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr, uint32_t code)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.op_break)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.op_break = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                        "__recompiler_break", recompiler->get_current_module());
	}

	Value *values[] = {argument, ConstantInt::get(Type::getInt32Ty(ctx), addr),
	                   ConstantInt::get(Type::getInt32Ty(ctx), code)};
	builder.CreateCall(calls.op_break, values);
}

void MIPS::create_syscall(Recompiler *recompiler, Value *argument, BasicBlock *bb, Address addr, uint32_t code)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.op_syscall)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx), Type::getInt32Ty(ctx), Type::getInt32Ty(ctx)};
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.op_syscall = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                          "__recompiler_syscall", recompiler->get_current_module());
	}

	Value *values[] = {argument, ConstantInt::get(Type::getInt32Ty(ctx), addr),
	                   ConstantInt::get(Type::getInt32Ty(ctx), code)};
	builder.CreateCall(calls.op_syscall, values);
}

void MIPS::call_step(Recompiler *recompiler, Value *argument, BasicBlock *bb)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.step)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx)};
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.step = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                    "__recompiler_step", recompiler->get_current_module());
	}

	Value *values[] = {argument};
	builder.CreateCall(calls.step, values);
}

void MIPS::call_step_after(Recompiler *recompiler, Value *argument, BasicBlock *bb)
{
	IRBuilder<> builder(bb);
	auto &ctx = builder.getContext();

	if (!calls.step_after)
	{
		Type *load_types[] = {Type::getInt32PtrTy(ctx)};
		auto *load_type = FunctionType::get(Type::getVoidTy(ctx), load_types, false);
		calls.step_after = llvm::Function::Create(load_type, llvm::Function::ExternalLinkage,
		                                          "__recompiler_step_after", recompiler->get_current_module());
	}

	Value *values[] = {argument};
	builder.CreateCall(calls.step_after, values);
}
}
