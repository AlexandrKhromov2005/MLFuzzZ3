// Stage 2 edge-coverage instrumentation (ADR 0024).
//
// LLVM 20 ModulePass, New PM plugin. For every basic block of every
// non-declaration function in the module the pass inserts an inline
// probe at the first non-PHI insertion point that updates an AFL-style
// 64 KiB saturating 8-bit coverage bitmap.
//
// Per-block id (cur_loc) is assigned deterministically by module-order
// traversal (functions in their Module list order, blocks in their
// Function list order). Ids cycle through [1, 65535] when a module has
// more than 65535 basic blocks; id 0 is reserved.
//
// Inline IR per ADR 0024 §Inline IR:
//   prev = load i32 @__mlfuzzz3_prev_loc
//   idx  = (lshr prev, 1) ^ cur_loc
//   idx  = and idx, 0xFFFF
//   map  = load ptr @__mlfuzzz3_cov_map
//   cell = gep i8, map, idx
//   c    = load i8 cell
//   cnew = c == 255 ? c : c + 1
//   store i8 cnew, cell
//   store i32 (cur_loc >> 1), @__mlfuzzz3_prev_loc
//
// Globals:
//   @__mlfuzzz3_prev_loc — i32, thread_local (GeneralDynamic),
//       zero-initialized, linkonce_odr (single TLS slot after link).
//   @__mlfuzzz3_cov_map  — external ptr; runtime (libmlfuzzz3_cov, task-005)
//       owns the definition and stores the mmap'd bitmap base into it.
//
// Registration: PipelineStartEPCallback, i.e. before inliner — see
// ADR 0024 §Точка включения. We instrument the source CFG.

#include <cstdint>

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
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

constexpr uint32_t kMapSize = 1U << 16;
constexpr uint32_t kMapMask = kMapSize - 1U;

constexpr const char* kPrevLocSymbol = "__mlfuzzz3_prev_loc";
constexpr const char* kCovMapSymbol = "__mlfuzzz3_cov_map";

GlobalVariable* getOrCreatePrevLoc(Module& m) {
    if (auto* existing = m.getNamedGlobal(kPrevLocSymbol)) {
        return existing;
    }
    LLVMContext& ctx = m.getContext();
    Type* i32 = Type::getInt32Ty(ctx);
    return new GlobalVariable(m, i32, /*isConstant=*/false, GlobalValue::LinkOnceODRLinkage,
                              ConstantInt::get(i32, 0), kPrevLocSymbol,
                              /*InsertBefore=*/nullptr, GlobalValue::GeneralDynamicTLSModel);
}

GlobalVariable* getOrCreateCovMap(Module& m) {
    if (auto* existing = m.getNamedGlobal(kCovMapSymbol)) {
        return existing;
    }
    LLVMContext& ctx = m.getContext();
    PointerType* ptr_ty = PointerType::getUnqual(ctx);
    return new GlobalVariable(m, ptr_ty, /*isConstant=*/false, GlobalValue::ExternalLinkage,
                              /*Initializer=*/nullptr, kCovMapSymbol);
}

bool instrumentBlock(BasicBlock& bb, uint32_t cur_loc, GlobalVariable* prev_loc_gv,
                     GlobalVariable* cov_map_gv) {
    BasicBlock::iterator insert_pt = bb.getFirstInsertionPt();
    if (insert_pt == bb.end()) {
        return false;
    }

    LLVMContext& ctx = bb.getContext();
    Type* i32 = Type::getInt32Ty(ctx);
    Type* i8 = Type::getInt8Ty(ctx);
    PointerType* ptr_ty = PointerType::getUnqual(ctx);

    IRBuilder<> builder(&bb, insert_pt);

    Value* prev = builder.CreateLoad(i32, prev_loc_gv, /*isVolatile=*/false, "ec.prev");
    Value* prev_shr = builder.CreateLShr(prev, ConstantInt::get(i32, 1), "ec.prev.shr");
    Value* cur_const = ConstantInt::get(i32, cur_loc);
    Value* xored = builder.CreateXor(prev_shr, cur_const, "ec.xor");
    Value* idx = builder.CreateAnd(xored, ConstantInt::get(i32, kMapMask), "ec.idx");

    Value* map_ptr = builder.CreateLoad(ptr_ty, cov_map_gv, /*isVolatile=*/false, "ec.map");
    Value* cell = builder.CreateGEP(i8, map_ptr, idx, "ec.cell");
    Value* counter = builder.CreateLoad(i8, cell, /*isVolatile=*/false, "ec.c");

    // Saturating 8-bit add: keep 0xFF on overflow.
    Constant* sat_max = ConstantInt::get(i8, 0xFF);
    Value* at_max = builder.CreateICmpEQ(counter, sat_max, "ec.sat");
    Value* inc = builder.CreateAdd(counter, ConstantInt::get(i8, 1), "ec.inc");
    Value* new_counter = builder.CreateSelect(at_max, sat_max, inc, "ec.cnew");
    builder.CreateStore(new_counter, cell);

    Value* cur_shifted = ConstantInt::get(i32, (cur_loc >> 1U) & kMapMask);
    builder.CreateStore(cur_shifted, prev_loc_gv);
    return true;
}

class EdgeCoveragePass : public PassInfoMixin<EdgeCoveragePass> {
   public:
    PreservedAnalyses run(Module& m, ModuleAnalysisManager& /*mam*/) {
        GlobalVariable* prev_loc_gv = getOrCreatePrevLoc(m);
        GlobalVariable* cov_map_gv = getOrCreateCovMap(m);

        uint32_t next_id = 1;
        bool changed = false;
        for (Function& f : m) {
            if (f.isDeclaration()) {
                continue;
            }
            for (BasicBlock& bb : f) {
                uint32_t cur_loc = next_id;
                ++next_id;
                if (next_id >= kMapSize) {
                    next_id = 1;
                }
                changed |= instrumentBlock(bb, cur_loc, prev_loc_gv, cov_map_gv);
            }
        }
        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

}  // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "EdgeCoveragePass", "0.1", [](PassBuilder& pb) {
                pb.registerPipelineStartEPCallback(
                    [](ModulePassManager& mpm, OptimizationLevel /*level*/) {
                        mpm.addPass(EdgeCoveragePass());
                    });
            }};
}
