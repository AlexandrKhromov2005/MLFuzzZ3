// Branch-tracing instrumentation (ADR 0033 Шаг 3).
//
// LLVM 20 ModulePass, New PM plugin. For every user-level integer
// ICmpInst in the module the pass inserts, immediately before the
// comparison, a call to the runtime hook
//
//   void fuzzer_rt_log_branch_cmp(uint32_t site_id, uint64_t lhs,
//                                 uint64_t rhs, uint8_t predicate,
//                                 uint8_t bit_width);
//
// declared external here (the runtime, libmlfuzzz3_cov, owns the
// definition). This is deliberately a CALL, not an inline probe like
// EdgeCoveragePass: comparisons are rarer than blocks and the record
// write is awkward to inline, while a call gives a clean toggle
// boundary and keeps the channel independent (ADR 0033 Развилка 2).
//
// Per ICmp the pass emits:
//   lhs  = zext/sext operand0 to i64   (sext iff the predicate is
//          signed; zext for unsigned and eq/ne — "по знаковости")
//   rhs  = zext/sext operand1 to i64
//   call @fuzzer_rt_log_branch_cmp(i32 site_id, i64 lhs, i64 rhs,
//                                  i8 predicate, i8 bit_width)
//
// site_id is a deterministic 0-based module-order counter (functions
// in Module order, blocks in Function order, instructions in block
// order). Unlike EdgeCoveragePass there is no reserved 0 — the branch
// log has no per-guard sentinel.
//
// Scope (ADR 0033 Ограничения): only integer comparisons with operand
// width <= 64 bits are instrumented. Pointer, vector and >64-bit
// operands are skipped (deferred — u64 + bit_width cannot represent
// them losslessly).
//
// EdgeCoveragePass is NOT touched. When a target is built with both
// plugins, load this one FIRST so its PipelineStartEP callback runs
// before the edge pass and it never sees the edge pass's own inserted
// saturating-compare icmp.
//
// Registration: PipelineStartEPCallback, before the inliner — same
// mechanism as EdgeCoveragePass (ADR 0033 Развилка 2).

#include <cstdint>
#include <vector>

#include "SiteMap.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Compiler.h"

namespace {

using namespace llvm;

constexpr const char* kLogFnSymbol = "fuzzer_rt_log_branch_cmp";

// Predicate values — must match enum fuzzer_rt_cmp_kind in
// src/runtime/coverage/mlfuzzz3_branch.h (part of the ABI).
enum BranchCmpKind : uint8_t {
    kCmpEq = 0,
    kCmpNe = 1,
    kCmpUlt = 2,
    kCmpUle = 3,
    kCmpUgt = 4,
    kCmpUge = 5,
    kCmpSlt = 6,
    kCmpSle = 7,
    kCmpSgt = 8,
    kCmpSge = 9,
};

// Maps an LLVM integer compare predicate to the ABI enum. Returns
// false for anything that is not an integer predicate (should not
// happen for ICmpInst, but keeps the mapping total).
bool mapPredicate(CmpInst::Predicate pred, uint8_t& out) {
    switch (pred) {
        case CmpInst::ICMP_EQ:
            out = kCmpEq;
            return true;
        case CmpInst::ICMP_NE:
            out = kCmpNe;
            return true;
        case CmpInst::ICMP_ULT:
            out = kCmpUlt;
            return true;
        case CmpInst::ICMP_ULE:
            out = kCmpUle;
            return true;
        case CmpInst::ICMP_UGT:
            out = kCmpUgt;
            return true;
        case CmpInst::ICMP_UGE:
            out = kCmpUge;
            return true;
        case CmpInst::ICMP_SLT:
            out = kCmpSlt;
            return true;
        case CmpInst::ICMP_SLE:
            out = kCmpSle;
            return true;
        case CmpInst::ICMP_SGT:
            out = kCmpSgt;
            return true;
        case CmpInst::ICMP_SGE:
            out = kCmpSge;
            return true;
        default:
            return false;
    }
}

FunctionCallee getLogFn(Module& m) {
    LLVMContext& ctx = m.getContext();
    Type* void_ty = Type::getVoidTy(ctx);
    Type* i32 = Type::getInt32Ty(ctx);
    Type* i64 = Type::getInt64Ty(ctx);
    Type* i8 = Type::getInt8Ty(ctx);
    FunctionType* fty = FunctionType::get(void_ty, {i32, i64, i64, i8, i8},
                                          /*isVarArg=*/false);
    return m.getOrInsertFunction(kLogFnSymbol, fty);
}

// Widens an operand to i64 by zext or sext depending on signedness.
// Same-width (i64) operands pass through unchanged.
Value* widenToI64(IRBuilder<>& builder, Value* operand, bool is_signed) {
    Type* i64 = builder.getInt64Ty();
    if (is_signed) {
        return builder.CreateSExtOrBitCast(operand, i64, "bt.ext.s");
    }
    return builder.CreateZExtOrBitCast(operand, i64, "bt.ext.z");
}

bool instrumentCmp(ICmpInst* cmp, uint32_t site_id, FunctionCallee log_fn) {
    auto* op_ty = dyn_cast<IntegerType>(cmp->getOperand(0)->getType());
    if (op_ty == nullptr) {
        return false;  // pointer / vector operands — deferred
    }
    const unsigned width = op_ty->getBitWidth();
    if (width > 64) {
        return false;  // >64-bit operands — deferred
    }

    uint8_t predicate = 0;
    if (!mapPredicate(cmp->getPredicate(), predicate)) {
        return false;  // non-integer predicate — should not occur
    }
    const bool is_signed = cmp->isSigned();

    IRBuilder<> builder(cmp);
    Value* lhs = widenToI64(builder, cmp->getOperand(0), is_signed);
    Value* rhs = widenToI64(builder, cmp->getOperand(1), is_signed);

    Type* i32 = builder.getInt32Ty();
    Type* i8 = builder.getInt8Ty();
    builder.CreateCall(log_fn,
                       {ConstantInt::get(i32, site_id), lhs, rhs, ConstantInt::get(i8, predicate),
                        ConstantInt::get(i8, static_cast<uint64_t>(width))});
    return true;
}

class BranchTracePass : public PassInfoMixin<BranchTracePass> {
   public:
    PreservedAnalyses run(Module& m, ModuleAnalysisManager& /*mam*/) {
        FunctionCallee log_fn = getLogFn(m);

        // Snapshot the comparisons first: instrumentCmp inserts new
        // instructions, so collect targets before mutating.
        std::vector<ICmpInst*> cmps;
        for (Function& f : m) {
            if (f.isDeclaration()) {
                continue;
            }
            for (BasicBlock& bb : f) {
                for (Instruction& inst : bb) {
                    if (auto* cmp = dyn_cast<ICmpInst>(&inst)) {
                        cmps.push_back(cmp);
                    }
                }
            }
        }

        uint32_t site_id = 0;
        bool changed = false;
        std::vector<mlfuzzz3::sitemap::Row> site_rows;
        for (ICmpInst* cmp : cmps) {
            if (instrumentCmp(cmp, site_id, log_fn)) {
                site_rows.push_back({site_id, cmp});
                ++site_id;
                changed = true;
            }
        }
        // Побочная таблица сайтов: пишется только при заданном
        // MLFUZZZ3_SITEMAP_DIR и на инструментацию не влияет.
        mlfuzzz3::sitemap::WriteIfRequested(m, site_rows);
        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

}  // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BranchTracePass", "0.1", [](PassBuilder& pb) {
                pb.registerPipelineStartEPCallback(
                    [](ModulePassManager& mpm, OptimizationLevel /*level*/) {
                        mpm.addPass(BranchTracePass());
                    });
            }};
}
