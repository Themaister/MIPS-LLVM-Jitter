#include "mips.hpp"
#include "ir_recompile.hpp"
#include "register_tracker.hpp"
#include "mips_opcode.hpp"

using namespace llvm;

//#define LS_DEBUG
//#define STEP_DEBUG

#ifdef STEP_DEBUG
#define STEP() do { \
	tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr)); \
	tracker.flush(); \
	call_step(recompiler, tracker.get_argument(), bb); \
	tracker.invalidate(); \
} while(0)

#define STEP_AFTER() do { \
	tracker.flush(); \
	call_step_after(recompiler, tracker.get_argument(), bb); \
	tracker.invalidate(); \
} while(0)
#else
#define STEP() ((void)0)
#define STEP_AFTER() ((void)0)
#endif

namespace JITTIR
{
void MIPS::recompile_instruction(Recompiler *recompiler, BasicBlock *&bb,
                                 IRBuilder<> &builder, RegisterTracker &tracker, Address addr)
{
	auto &ctx = builder.getContext();
	auto instr = load_instr(addr);
	bool can_do_step_after = true;

	STEP();

	switch (instr.op)
	{
	case Op::NOP:
		break;

		// Arithmetic operations.
	case Op::ADD:
	case Op::ADDU:
		tracker.write_int(instr.rd, builder.CreateAdd(tracker.read_int(instr.rs), tracker.read_int(instr.rt),
		                                              tracker.get_twine(instr.rd)));
		break;

	case Op::SUB:
	case Op::SUBU:
		tracker.write_int(instr.rd, builder.CreateSub(tracker.read_int(instr.rs), tracker.read_int(instr.rt),
		                                              tracker.get_twine(instr.rd)));
		break;

	case Op::ADDI:
	case Op::ADDIU:
		tracker.write_int(instr.rt, builder.CreateAdd(tracker.read_int(instr.rs),
		                                              ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                              tracker.get_twine(instr.rt)));
		break;

	case Op::SLT:
	{
		Value *cmp = builder.CreateICmpSLT(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "SLTCmp");
		tracker.write_int(instr.rd,
		                  builder.CreateSelect(cmp, ConstantInt::get(Type::getInt32Ty(ctx), 1),
		                                       ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                       tracker.get_twine(instr.rd)));
		break;
	}

	case Op::SLTU:
	{
		Value *cmp = builder.CreateICmpULT(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "ULTCmp");
		tracker.write_int(instr.rd,
		                  builder.CreateSelect(cmp, ConstantInt::get(Type::getInt32Ty(ctx), 1),
		                                       ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                       tracker.get_twine(instr.rd)));
		break;
	}

	case Op::SLTI:
	{
		Value *cmp = builder.CreateICmpSLT(tracker.read_int(instr.rs),
		                                   ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SLTICmp");
		tracker.write_int(instr.rt,
		                  builder.CreateSelect(cmp, ConstantInt::get(Type::getInt32Ty(ctx), 1),
		                                       ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                       tracker.get_twine(instr.rt)));
		break;
	}

	case Op::SLTIU:
	{
		Value *cmp = builder.CreateICmpULT(tracker.read_int(instr.rs),
		                                   ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SLTIUCmp");
		tracker.write_int(instr.rt,
		                  builder.CreateSelect(cmp, ConstantInt::get(Type::getInt32Ty(ctx), 1),
		                                       ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                       tracker.get_twine(instr.rt)));
		break;
	}

	case Op::AND:
		tracker.write_int(instr.rd, builder.CreateAnd(tracker.read_int(instr.rs), tracker.read_int(instr.rt),
		                                              tracker.get_twine(instr.rd)));
		break;

	case Op::OR:
		tracker.write_int(instr.rd, builder.CreateOr(tracker.read_int(instr.rs), tracker.read_int(instr.rt),
		                                             tracker.get_twine(instr.rd)));
		break;

	case Op::XOR:
		tracker.write_int(instr.rd, builder.CreateXor(tracker.read_int(instr.rs), tracker.read_int(instr.rt),
		                                              tracker.get_twine(instr.rd)));
		break;

	case Op::NOR:
		tracker.write_int(instr.rd,
		                  builder.CreateNot(builder.CreateOr(tracker.read_int(instr.rs), tracker.read_int(instr.rt)),
		                                    tracker.get_twine(instr.rd)));
		break;

	case Op::ANDI:
		tracker.write_int(instr.rt, builder.CreateAnd(tracker.read_int(instr.rs),
		                                              ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.imm)),
		                                              tracker.get_twine(instr.rt)));
		break;

	case Op::ORI:
		tracker.write_int(instr.rt, builder.CreateOr(tracker.read_int(instr.rs),
		                                             ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.imm)),
		                                             tracker.get_twine(instr.rt)));
		break;

	case Op::XORI:
		tracker.write_int(instr.rt, builder.CreateXor(tracker.read_int(instr.rs),
		                                              ConstantInt::get(Type::getInt32Ty(ctx), uint16_t(instr.imm)),
		                                              tracker.get_twine(instr.rt)));
		break;

	case Op::SLL:
		tracker.write_int(instr.rd, builder.CreateShl(tracker.read_int(instr.rt),
		                                              ConstantInt::get(Type::getInt32Ty(ctx), instr.imm & 31),
		                                              tracker.get_twine(instr.rd)));
		break;

	case Op::SRL:
		tracker.write_int(instr.rd, builder.CreateLShr(tracker.read_int(instr.rt),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), instr.imm & 31),
		                                               tracker.get_twine(instr.rd)));
		break;

	case Op::SRA:
		tracker.write_int(instr.rd, builder.CreateAShr(tracker.read_int(instr.rt),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), instr.imm & 31),
		                                               tracker.get_twine(instr.rd)));
		break;

	case Op::SLLV:
		tracker.write_int(instr.rd, builder.CreateShl(tracker.read_int(instr.rt),
		                                              builder.CreateAnd(tracker.read_int(instr.rs),
		                                                                ConstantInt::get(Type::getInt32Ty(ctx), 31),
		                                                                "ShiftMask"),
		                                              tracker.get_twine(instr.rd)));
		break;

	case Op::SRLV:
		tracker.write_int(instr.rd, builder.CreateLShr(tracker.read_int(instr.rt),
		                                               builder.CreateAnd(tracker.read_int(instr.rs),
		                                                                 ConstantInt::get(Type::getInt32Ty(ctx), 31),
		                                                                 "ShiftMask"),
		                                               tracker.get_twine(instr.rd)));
		break;

	case Op::SRAV:
		tracker.write_int(instr.rd, builder.CreateAShr(tracker.read_int(instr.rt),
		                                               builder.CreateAnd(tracker.read_int(instr.rs),
		                                                                 ConstantInt::get(Type::getInt32Ty(ctx), 31),
		                                                                 "ShiftMask"),
		                                               tracker.get_twine(instr.rd)));
		break;

	case Op::LUI:
		tracker.write_int(instr.rt, ConstantInt::get(Type::getInt32Ty(ctx), (instr.imm & 0xffff) << 16));
		break;

	case Op::MULT:
	{
		auto *mul = builder.CreateMul(builder.CreateSExt(tracker.read_int(instr.rs), Type::getInt64Ty(ctx), "MulSExt"),
		                              builder.CreateSExt(tracker.read_int(instr.rt), Type::getInt64Ty(ctx), "MulSExt"),
		                              "Mul");

		tracker.write_int(REG_LO, builder.CreateTrunc(mul, Type::getInt32Ty(ctx), "LO"));
		tracker.write_int(REG_HI,
		                  builder.CreateTrunc(builder.CreateLShr(mul, ConstantInt::get(Type::getInt64Ty(ctx), 32)),
		                                      Type::getInt32Ty(ctx), "HI"));
		break;
	}

	case Op::MULTU:
	{
		auto *mul = builder.CreateMul(builder.CreateZExt(tracker.read_int(instr.rs), Type::getInt64Ty(ctx), "MulZExt"),
		                              builder.CreateZExt(tracker.read_int(instr.rt), Type::getInt64Ty(ctx), "MulZExt"),
		                              "Mul");

		tracker.write_int(REG_LO, builder.CreateTrunc(mul, Type::getInt32Ty(ctx), "LO"));
		tracker.write_int(REG_HI,
		                  builder.CreateTrunc(builder.CreateLShr(mul, ConstantInt::get(Type::getInt64Ty(ctx), 32)),
		                                      Type::getInt32Ty(ctx), "HI"));
		break;
	}

	case Op::DIV:
	{
		auto *div = builder.CreateSDiv(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "LO");
		auto *rem = builder.CreateSRem(tracker.read_int(instr.rs), tracker.read_int(instr.rt),
		                               "HI"); // Probably not correct.
		tracker.write_int(REG_LO, div);
		tracker.write_int(REG_HI, rem);
		break;
	}

	case Op::DIVU:
	{
		auto *div = builder.CreateUDiv(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "LO");
		auto *rem = builder.CreateURem(tracker.read_int(instr.rs), tracker.read_int(instr.rt),
		                               "HI"); // Probably not correct.
		tracker.write_int(REG_LO, div);
		tracker.write_int(REG_HI, rem);
		break;
	}

	case Op::MFHI:
		tracker.write_int(instr.rd, tracker.read_int(REG_HI));
		break;

	case Op::MFLO:
		tracker.write_int(instr.rd, tracker.read_int(REG_LO));
		break;

	case Op::MTHI:
		tracker.write_int(REG_HI, tracker.read_int(instr.rs));
		break;

	case Op::MTLO:
		tracker.write_int(REG_LO, tracker.read_int(instr.rs));
		break;

	case Op::J:
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		tracker.flush();
		break;

	case Op::JAL:
	{
		Address target = instr.imm;
		tracker.write_int(REG_RA, ConstantInt::get(Type::getInt32Ty(ctx), addr + 8));

		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.flush();
		auto *call = create_call(recompiler, tracker.get_argument(), bb, target, addr + 8);
		if (call)
		{
			Value *values[] = {tracker.get_argument()};
			builder.SetInsertPoint(bb);
			builder.CreateCall(call, values);
		}
		tracker.invalidate();
		break;
	}

	case Op::JR:
	{
		Value *target = tracker.read_int(instr.rs);
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.set_builder(&builder);
		tracker.flush();

		auto *call = create_jump_indirect(recompiler, tracker.get_argument(), bb, target);
		auto *bb_call = BasicBlock::Create(ctx, "IndirectJumpPath", recompiler->get_current_function());
		auto *bb_return = BasicBlock::Create(ctx, "IndirectJumpReturn", recompiler->get_current_function());
		builder.SetInsertPoint(bb);
		builder.CreateCondBr(
				builder.CreateICmpNE(call,
				                     ConstantPointerNull::get(static_cast<PointerType *>(call->getType())),
				                     "jump_addr_cmp"),
				bb_call, bb_return);

		builder.SetInsertPoint(bb_call);
		Value *values[] = {tracker.get_argument()};
		builder.CreateCall(call, values);
		BranchInst::Create(bb_return, bb_call);

		bb = bb_return;
		break;
	}

	case Op::JALR:
	{
		tracker.write_int(REG_RA, ConstantInt::get(Type::getInt32Ty(ctx), addr + 8));
		auto *target = tracker.read_int(instr.rs);

		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.flush();
		auto *call = create_call(recompiler, tracker.get_argument(), bb, target, addr + 8);
		Value *values[] = {tracker.get_argument()};
		builder.SetInsertPoint(bb);
		builder.CreateCall(call, values);
		tracker.invalidate();
		break;
	}

	case Op::BEQ:
	{
		auto *cmp = builder.CreateICmpEQ(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "BEQ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BNE:
	{
		auto *cmp = builder.CreateICmpNE(tracker.read_int(instr.rs), tracker.read_int(instr.rt), "BNE");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BLTZ:
	{
		auto *cmp = builder.CreateICmpSLT(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                  "BLTZ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BGEZ:
	{
		auto *cmp = builder.CreateICmpSGE(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                  "BGEZ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BGTZ:
	{
		auto *cmp = builder.CreateICmpSGT(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                  "BGTZ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BLEZ:
	{
		auto *cmp = builder.CreateICmpSLE(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                  "BLEZ");
		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);
		builder.SetInsertPoint(bb);
		tracker.flush();
		Address target = instr.imm;
		BranchInst::Create(recompiler->get_block_for_address(target),
		                   recompiler->get_block_for_address(addr + 8),
		                   cmp,
		                   bb);
		break;
	}

	case Op::BLTZAL:
	{
		auto *cmp = builder.CreateICmpSLT(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                  "BLTZ");
		Address target = instr.imm;
		tracker.write_int(REG_RA, ConstantInt::get(Type::getInt32Ty(ctx), addr + 8));

		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.flush();

		auto *bb_call = BasicBlock::Create(ctx, "IndirectCallPath", recompiler->get_current_function());
		auto *bb_merge = BasicBlock::Create(ctx, "IndirectCallMerge", recompiler->get_current_function());
		BranchInst::Create(bb_call, bb_merge, cmp, bb);
		bb = bb_merge;

		auto *call = create_call(recompiler, tracker.get_argument(), bb_call, target, addr + 8);
		if (call)
		{
			Value *values[] = {tracker.get_argument()};
			builder.SetInsertPoint(bb_call);
			builder.CreateCall(call, values);
		}
		tracker.invalidate();
		break;
	}

	case Op::BGEZAL:
	{
		auto *cmp = builder.CreateICmpSGE(tracker.read_int(instr.rs), ConstantInt::get(Type::getInt32Ty(ctx), 0),
		                                  "BGEZ");
		Address target = instr.imm;
		tracker.write_int(REG_RA, ConstantInt::get(Type::getInt32Ty(ctx), addr + 8));

		if (!mips_opcode_is_branch(load_instr(addr + 4).op))
			recompile_instruction(recompiler, bb, builder, tracker, addr + 4);

		tracker.flush();

		auto *bb_call = BasicBlock::Create(ctx, "IndirectCallPath", recompiler->get_current_function());
		auto *bb_merge = BasicBlock::Create(ctx, "IndirectCallMerge", recompiler->get_current_function());
		BranchInst::Create(bb_call, bb_merge, cmp, bb);
		bb = bb_merge;

		auto *call = create_call(recompiler, tracker.get_argument(), bb_call, target, addr + 8);
		if (call)
		{
			Value *values[] = {tracker.get_argument()};
			builder.SetInsertPoint(bb_call);
			builder.CreateCall(call, values);
		}
		tracker.invalidate();
		break;
	}

	case Op::SYSCALL:
	{
		tracker.flush();
		create_syscall(recompiler, tracker.get_argument(), bb, addr, instr.imm);
		tracker.invalidate();
		break;
	}

	case Op::SYNC:
	{
		// We have no multi-threading support, so this is a noop.
		break;
	}

	case Op::BREAK:
	{
		tracker.flush();
		create_break(recompiler, tracker.get_argument(), bb, addr, instr.imm);
		can_do_step_after = false;
		break;
	}

	case Op::LB:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load8(recompiler, tracker.get_argument(), bb,
		                            builder.CreateAdd(tracker.read_int(instr.rs),
		                                              ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                              "LBAddr"));
		builder.SetInsertPoint(bb);
		loaded = builder.CreateSExt(loaded, Type::getInt32Ty(ctx), tracker.get_twine(instr.rt));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LH:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load16(recompiler, tracker.get_argument(), bb,
		                             builder.CreateAdd(tracker.read_int(instr.rs),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                               "LHAddr"));
		builder.SetInsertPoint(bb);
		loaded = builder.CreateSExt(loaded, Type::getInt32Ty(ctx), tracker.get_twine(instr.rt));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LBU:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load8(recompiler, tracker.get_argument(), bb,
		                            builder.CreateAdd(tracker.read_int(instr.rs),
		                                              ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                              "LBAddr"));
		builder.SetInsertPoint(bb);
		loaded = builder.CreateZExt(loaded, Type::getInt32Ty(ctx), tracker.get_twine(instr.rt));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LHU:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load16(recompiler, tracker.get_argument(), bb,
		                             builder.CreateAdd(tracker.read_int(instr.rs),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                               "LHAddr"));
		builder.SetInsertPoint(bb);
		loaded = builder.CreateZExt(loaded, Type::getInt32Ty(ctx), tracker.get_twine(instr.rt));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LW:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load32(recompiler, tracker.get_argument(), bb,
		                             builder.CreateAdd(tracker.read_int(instr.rs),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                               "LWAddr"));
		builder.SetInsertPoint(bb);
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::SB:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_store8(recompiler, tracker.get_argument(), bb,
		              builder.CreateAdd(tracker.read_int(instr.rs),
		                                ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SBAddr"),
		              tracker.read_int(instr.rt));
		break;
	}

	case Op::SH:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_store16(recompiler, tracker.get_argument(), bb,
		               builder.CreateAdd(tracker.read_int(instr.rs),
		                                 ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SHAddr"),
		               tracker.read_int(instr.rt));
		break;
	}

	case Op::SW:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_store32(recompiler, tracker.get_argument(), bb,
		               builder.CreateAdd(tracker.read_int(instr.rs),
		                                 ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SWAddr"),
		               tracker.read_int(instr.rt));
		break;
	}

	case Op::LWL:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_lwl(recompiler, tracker.get_argument(), bb, tracker.read_int(instr.rt),
		                          builder.CreateAdd(tracker.read_int(instr.rs),
		                                            ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                            "LWLAddr"));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::LWR:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_lwr(recompiler, tracker.get_argument(), bb, tracker.read_int(instr.rt),
		                          builder.CreateAdd(tracker.read_int(instr.rs),
		                                            ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                            "LWRAddr"));
		tracker.write_int(instr.rt, loaded);
		break;
	}

	case Op::SWL:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_swl(recompiler, tracker.get_argument(), bb,
		           builder.CreateAdd(tracker.read_int(instr.rs),
		                             ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SWLAddr"),
		           tracker.read_int(instr.rt));
		break;
	}

	case Op::SWR:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_swr(recompiler, tracker.get_argument(), bb,
		           builder.CreateAdd(tracker.read_int(instr.rs),
		                             ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SWRAddr"),
		           tracker.read_int(instr.rt));
		break;
	}

	case Op::LWC0:
	case Op::SWC0:
		// TODO.
		break;

	case Op::LWC1:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		auto *loaded = create_load32(recompiler, tracker.get_argument(), bb,
		                             builder.CreateAdd(tracker.read_int(instr.rs),
		                                               ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)),
		                                               "LWC1Addr"));
		tracker.write_float(instr.rt, loaded);
		break;
	}

	case Op::SWC1:
	{
#ifdef LS_DEBUG
		tracker.write_int(REG_PC, ConstantInt::get(Type::getInt32Ty(ctx), addr));
		tracker.flush();
#endif
		create_store32(recompiler, tracker.get_argument(), bb,
		               builder.CreateAdd(tracker.read_int(instr.rs),
		                                 ConstantInt::get(Type::getInt32Ty(ctx), int16_t(instr.imm)), "SWAddr"),
		               tracker.read_float(instr.rt));
		break;
	}

	case Op::RDHWR_TLS:
		tracker.write_int(instr.rt, tracker.read_int(REG_TLS));
		break;

	default:
		can_do_step_after = false;
		tracker.flush();
		create_sigill(recompiler, tracker.get_argument(), bb, addr);
		break;
	}

	if (can_do_step_after && !mips_opcode_is_branch(instr.op))
		STEP_AFTER();
}

void MIPS::recompile_basic_block(
		Address start_addr, Address end_addr,
		Recompiler *recompiler, const Block &block, BasicBlock *bb, Value *args)
{
	RegisterTracker tracker(args);

	for (Address addr = start_addr; addr < end_addr; addr += 4)
	{
		IRBuilder<> builder(bb);
		tracker.set_builder(&builder);
		recompile_instruction(recompiler, bb, builder, tracker, addr);
		if (mips_opcode_is_branch(load_instr(addr).op))
			addr += 4;
	}

	if (block.terminator == Terminator::DirectBranch)
	{
		BranchInst::Create(recompiler->get_block_for_address(block.static_address_targets[0]), bb);
	}
	else if (block.terminator == Terminator::Exit)
	{
		IRBuilder<> builder(bb);
		builder.CreateRetVoid();
	}
}

void MIPS::get_block_from_address(Address addr, Block &block)
{
	block.block_start = addr;

	for (;;)
	{
		auto instruction = load_instr(addr);
		bool end_of_basic_block = mips_opcode_ends_basic_block(instruction.op);

		if (end_of_basic_block)
		{
			if (mips_opcode_is_branch(instruction.op) && !mips_opcode_is_branch(load_instr(addr + 4).op))
				block.block_end = addr + 8;
			else
				block.block_end = addr + 4;

			switch (instruction.op)
			{
			case Op::J:
				block.terminator = Terminator::DirectBranch;
				block.static_address_targets[0] = instruction.imm;
				break;

			case Op::JR:
			case Op::BREAK:
			case Op::Invalid:
				block.terminator = Terminator::Exit;
				break;

			case Op::BLTZ:
			case Op::BGEZ:
			case Op::BLEZ:
			case Op::BGTZ:
			case Op::BEQ:
			case Op::BNE:
				block.terminator = Terminator::SelectionBranch;
				block.static_address_targets[0] = instruction.imm;
				block.static_address_targets[1] = addr + 8;
				break;

			default:
				break;
			}

			break;
		}

		addr += 4;
	}
}

}