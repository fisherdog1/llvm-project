//===-- FunctionLoweringInfo.cpp ------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This implements routines for translating functions from LLVM IR into
// Machine IR.
//
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/FunctionLoweringInfo.h"
#include "llvm/ADT/APInt.h"
#include "llvm/Analysis/LegacyDivergenceAnalysis.h"
#include "llvm/CodeGen/Analysis.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/WasmEHFuncInfo.h"
#include "llvm/CodeGen/WinEHFuncInfo.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
using namespace llvm;

#define DEBUG_TYPE "function-lowering-info"

/// isUsedOutsideOfDefiningBlock - Return true if this instruction is used by
/// PHI nodes or outside of the basic block that defines it, or used by a
/// switch or atomic instruction, which may expand to multiple basic blocks.
static bool isUsedOutsideOfDefiningBlock(const Instruction *I) {
  if (I->use_empty()) return false;
  if (isa<PHINode>(I)) return true;
  const BasicBlock *BB = I->getParent();
  for (const User *U : I->users())
    if (cast<Instruction>(U)->getParent() != BB || isa<PHINode>(U))
      return true;

  return false;
}

static ISD::NodeType getPreferredExtendForValue(const Value *V) {
  // For the users of the source value being used for compare instruction, if
  // the number of signed predicate is greater than unsigned predicate, we
  // prefer to use SIGN_EXTEND.
  //
  // With this optimization, we would be able to reduce some redundant sign or
  // zero extension instruction, and eventually more machine CSE opportunities
  // can be exposed.
  ISD::NodeType ExtendKind = ISD::ANY_EXTEND;
  unsigned NumOfSigned = 0, NumOfUnsigned = 0;
  for (const User *U : V->users()) {
    if (const auto *CI = dyn_cast<CmpInst>(U)) {
      NumOfSigned += CI->isSigned();
      NumOfUnsigned += CI->isUnsigned();
    }
  }
  if (NumOfSigned > NumOfUnsigned)
    ExtendKind = ISD::SIGN_EXTEND;

  return ExtendKind;
}

void FunctionLoweringInfo::set(const Function &fn, MachineFunction &mf,
                               SelectionDAG *DAG) {
  Fn = &fn;
  MF = &mf;
  TLI = MF->getSubtarget().getTargetLowering();
  RegInfo = &MF->getRegInfo();
  const TargetFrameLowering *TFI = MF->getSubtarget().getFrameLowering();
  DA = DAG->getDivergenceAnalysis();

  // Check whether the function can return without sret-demotion.
  SmallVector<ISD::OutputArg, 4> Outs;
  CallingConv::ID CC = Fn->getCallingConv();

  GetReturnInfo(CC, Fn->getReturnType(), Fn->getAttributes(), Outs, *TLI,
                mf.getDataLayout());
  CanLowerReturn =
      TLI->CanLowerReturn(CC, *MF, Fn->isVarArg(), Outs, Fn->getContext());

  // If this personality uses funclets, we need to do a bit more work.
  DenseMap<const AllocaInst *, TinyPtrVector<int *>> CatchObjects;
  EHPersonality Personality = classifyEHPersonality(
      Fn->hasPersonalityFn() ? Fn->getPersonalityFn() : nullptr);
  if (isFuncletEHPersonality(Personality)) {
    // Calculate state numbers if we haven't already.
    WinEHFuncInfo &EHInfo = *MF->getWinEHFuncInfo();
    if (Personality == EHPersonality::MSVC_CXX)
      calculateWinCXXEHStateNumbers(&fn, EHInfo);
    else if (isAsynchronousEHPersonality(Personality))
      calculateSEHStateNumbers(&fn, EHInfo);
    else if (Personality == EHPersonality::CoreCLR)
      calculateClrEHStateNumbers(&fn, EHInfo);

    // Map all BB references in the WinEH data to MBBs.
    for (WinEHTryBlockMapEntry &TBME : EHInfo.TryBlockMap) {
      for (WinEHHandlerType &H : TBME.HandlerArray) {
        if (const AllocaInst *AI = H.CatchObj.Alloca)
          CatchObjects.insert({AI, {}}).first->second.push_back(
              &H.CatchObj.FrameIndex);
        else
          H.CatchObj.FrameIndex = INT_MAX;
      }
    }
  }
  if (Personality == EHPersonality::Wasm_CXX) {
    WasmEHFuncInfo &EHInfo = *MF->getWasmEHFuncInfo();
    calculateWasmEHInfo(&fn, EHInfo);
  }

  // Initialize the mapping of values to registers.  This is only set up for
  // instruction values that are used outside of the block that defines
  // them.
  const Align StackAlign = TFI->getStackAlign();
  for (const BasicBlock &BB : *Fn) {
    for (const Instruction &I : BB) {
      if (const AllocaInst *AI = dyn_cast<AllocaInst>(&I)) {
        Type *Ty = AI->getAllocatedType();
        Align TyPrefAlign = MF->getDataLayout().getPrefTypeAlign(Ty);
        // The "specified" alignment is the alignment written on the alloca,
        // or the preferred alignment of the type if none is specified.
        //
        // (Unspecified alignment on allocas will be going away soon.)
        Align SpecifiedAlign = AI->getAlign();

        // If the preferred alignment of the type is higher than the specified
        // alignment of the alloca, promote the alignment, as long as it doesn't
        // require realigning the stack.
        //
        // FIXME: Do we really want to second-guess the IR in isel?
        Align Alignment =
            std::max(std::min(TyPrefAlign, StackAlign), SpecifiedAlign);

        // Static allocas can be folded into the initial stack frame
        // adjustment. For targets that don't realign the stack, don't
        // do this if there is an extra alignment requirement.
        if (AI->isStaticAlloca() &&
            (TFI->isStackRealignable() || (Alignment <= StackAlign))) {
          const ConstantInt *CUI = cast<ConstantInt>(AI->getArraySize());
          uint64_t TySize =
              MF->getDataLayout().getTypeAllocSize(Ty).getKnownMinSize();

          TySize *= CUI->getZExtValue();   // Get total allocated size.
          if (TySize == 0) TySize = 1; // Don't create zero-sized stack objects.
          int FrameIndex = INT_MAX;
          auto Iter = CatchObjects.find(AI);
          if (Iter != CatchObjects.end() && TLI->needsFixedCatchObjects()) {
            FrameIndex = MF->getFrameInfo().CreateFixedObject(
                TySize, 0, /*IsImmutable=*/false, /*isAliased=*/true);
            MF->getFrameInfo().setObjectAlignment(FrameIndex, Alignment);
          } else {
            FrameIndex = MF->getFrameInfo().CreateStackObject(TySize, Alignment,
                                                              false, AI);
          }

          // Scalable vectors may need a special StackID to distinguish
          // them from other (fixed size) stack objects.
          if (isa<ScalableVectorType>(Ty))
            MF->getFrameInfo().setStackID(FrameIndex,
                                          TFI->getStackIDForScalableVectors());

          StaticAllocaMap[AI] = FrameIndex;
          // Update the catch handler information.
          if (Iter != CatchObjects.end()) {
            for (int *CatchObjPtr : Iter->second)
              *CatchObjPtr = FrameIndex;
          }
        } else {
          // FIXME: Overaligned static allocas should be grouped into
          // a single dynamic allocation instead of using a separate
          // stack allocation for each one.
          // Inform the Frame Information that we have variable-sized objects.
          MF->getFrameInfo().CreateVariableSizedObject(
              Alignment <= StackAlign ? Align(1) : Alignment, AI);
        }
      } else if (auto *Call = dyn_cast<CallBase>(&I)) {
        // Look for inline asm that clobbers the SP register.
        if (Call->isInlineAsm()) {
          Register SP = TLI->getStackPointerRegisterToSaveRestore();
          const TargetRegisterInfo *TRI = MF->getSubtarget().getRegisterInfo();
          std::vector<TargetLowering::AsmOperandInfo> Ops =
              TLI->ParseConstraints(Fn->getParent()->getDataLayout(), TRI,
                                    *Call);
          for (TargetLowering::AsmOperandInfo &Op : Ops) {
            if (Op.Type == InlineAsm::isClobber) {
              // Clobbers don't have SDValue operands, hence SDValue().
              TLI->ComputeConstraintToUse(Op, SDValue(), DAG);
              std::pair<unsigned, const TargetRegisterClass *> PhysReg =
                  TLI->getRegForInlineAsmConstraint(TRI, Op.ConstraintCode,
                                                    Op.ConstraintVT);
              if (PhysReg.first == SP)
                MF->getFrameInfo().setHasOpaqueSPAdjustment(true);
            }
          }
        }
        // Look for calls to the @llvm.va_start intrinsic. We can omit some
        // prologue boilerplate for variadic functions that don't examine their
        // arguments.
        if (const auto *II = dyn_cast<IntrinsicInst>(&I)) {
          if (II->getIntrinsicID() == Intrinsic::vastart)
            MF->getFrameInfo().setHasVAStart(true);
        }

        // If we have a musttail call in a variadic function, we need to ensure
        // we forward implicit register parameters.
        if (const auto *CI = dyn_cast<CallInst>(&I)) {
          if (CI->isMustTailCall() && Fn->isVarArg())
            MF->getFrameInfo().setHasMustTailInVarArgFunc(true);
        }
      }

      // Mark values used outside their block as exported, by allocating
      // a virtual register for them.
      if (isUsedOutsideOfDefiningBlock(&I))
        if (!isa<AllocaInst>(I) || !StaticAllocaMap.count(cast<AllocaInst>(&I)))
          InitializeRegForValue(&I);

      // Decide the preferred extend type for a value.
      PreferredExtendType[&I] = getPreferredExtendForValue(&I);
    }
  }

  // Create an initial MachineBasicBlock for each LLVM BasicBlock in F.  This
  // also creates the initial PHI MachineInstrs, though none of the input
  // operands are populated.
  for (const BasicBlock &BB : *Fn) {
    // Don't create MachineBasicBlocks for imaginary EH pad blocks. These blocks
    // are really data, and no instructions can live here.
    if (BB.isEHPad()) {
      const Instruction *PadInst = BB.getFirstNonPHI();
      // If this is a non-landingpad EH pad, mark this function as using
      // funclets.
      // FIXME: SEH catchpads do not create EH scope/funclets, so we could avoid
      // setting this in such cases in order to improve frame layout.
      if (!isa<LandingPadInst>(PadInst)) {
        MF->setHasEHScopes(true);
        MF->setHasEHFunclets(true);
        MF->getFrameInfo().setHasOpaqueSPAdjustment(true);
      }
      if (isa<CatchSwitchInst>(PadInst)) {
        assert(&*BB.begin() == PadInst &&
               "WinEHPrepare failed to remove PHIs from imaginary BBs");
        continue;
      }
      if (isa<FuncletPadInst>(PadInst))
        assert(&*BB.begin() == PadInst && "WinEHPrepare failed to demote PHIs");
    }

    MachineBasicBlock *MBB = mf.CreateMachineBasicBlock(&BB);
    MBBMap[&BB] = MBB;
    MF->push_back(MBB);

    // Transfer the address-taken flag. This is necessary because there could
    // be multiple MachineBasicBlocks corresponding to one BasicBlock, and only
    // the first one should be marked.
    if (BB.hasAddressTaken())
      MBB->setHasAddressTaken();

    // Mark landing pad blocks.
    if (BB.isEHPad())
      MBB->setIsEHPad();

    // Create Machine PHI nodes for LLVM PHI nodes, lowering them as
    // appropriate.
    for (const PHINode &PN : BB.phis()) {
      if (PN.use_empty())
        continue;

      // Skip empty types
      if (PN.getType()->isEmptyTy())
        continue;

      DebugLoc DL = PN.getDebugLoc();
      unsigned PHIReg = ValueMap[&PN];
      assert(PHIReg && "PHI node does not have an assigned virtual register!");

      SmallVector<EVT, 4> ValueVTs;
      ComputeValueVTs(*TLI, MF->getDataLayout(), PN.getType(), ValueVTs);
      for (EVT VT : ValueVTs) {
        unsigned NumRegisters = TLI->getNumRegisters(Fn->getContext(), VT);
        const TargetInstrInfo *TII = MF->getSubtarget().getInstrInfo();
        for (unsigned i = 0; i != NumRegisters; ++i)
          BuildMI(MBB, DL, TII->get(TargetOpcode::PHI), PHIReg + i);
        PHIReg += NumRegisters;
      }
    }
  }

  if (isFuncletEHPersonality(Personality)) {
    WinEHFuncInfo &EHInfo = *MF->getWinEHFuncInfo();

    // Map all BB references in the WinEH data to MBBs.
    for (WinEHTryBlockMapEntry &TBME : EHInfo.TryBlockMap) {
      for (WinEHHandlerType &H : TBME.HandlerArray) {
        if (H.Handler)
          H.Handler = MBBMap[H.Handler.get<const BasicBlock *>()];
      }
    }
    for (CxxUnwindMapEntry &UME : EHInfo.CxxUnwindMap)
      if (UME.Cleanup)
        UME.Cleanup = MBBMap[UME.Cleanup.get<const BasicBlock *>()];
    for (SEHUnwindMapEntry &UME : EHInfo.SEHUnwindMap) {
      const auto *BB = UME.Handler.get<const BasicBlock *>();
      UME.Handler = MBBMap[BB];
    }
    for (ClrEHUnwindMapEntry &CME : EHInfo.ClrEHUnwindMap) {
      const auto *BB = CME.Handler.get<const BasicBlock *>();
      CME.Handler = MBBMap[BB];
    }
  }

  else if (Personality == EHPersonality::Wasm_CXX) {
    WasmEHFuncInfo &EHInfo = *MF->getWasmEHFuncInfo();
    // Map all BB references in the Wasm EH data to MBBs.
    DenseMap<BBOrMBB, BBOrMBB> SrcToUnwindDest;
    for (auto &KV : EHInfo.SrcToUnwindDest) {
      const auto *Src = KV.first.get<const BasicBlock *>();
      const auto *Dest = KV.second.get<const BasicBlock *>();
      SrcToUnwindDest[MBBMap[Src]] = MBBMap[Dest];
    }
    EHInfo.SrcToUnwindDest = std::move(SrcToUnwindDest);
    DenseMap<BBOrMBB, SmallPtrSet<BBOrMBB, 4>> UnwindDestToSrcs;
    for (auto &KV : EHInfo.UnwindDestToSrcs) {
      const auto *Dest = KV.first.get<const BasicBlock *>();
      UnwindDestToSrcs[MBBMap[Dest]] = SmallPtrSet<BBOrMBB, 4>();
      for (const auto P : KV.second)
        UnwindDestToSrcs[MBBMap[Dest]].insert(
            MBBMap[P.get<const BasicBlock *>()]);
    }
    EHInfo.UnwindDestToSrcs = std::move(UnwindDestToSrcs);
  }
}

/// clear - Clear out all the function-specific state. This returns this
/// FunctionLoweringInfo to an empty state, ready to be used for a
/// different function.
void FunctionLoweringInfo::clear() {
  MBBMap.clear();
  ValueMap.clear();
  VirtReg2Value.clear();
  StaticAllocaMap.clear();
  LiveOutRegInfo.clear();
  VisitedBBs.clear();
  ArgDbgValues.clear();
  DescribedArgs.clear();
  ByValArgFrameIndexMap.clear();
  RegFixups.clear();
  RegsWithFixups.clear();
  StatepointStackSlots.clear();
  StatepointRelocationMaps.clear();
  PreferredExtendType.clear();
}

/// CreateReg - Allocate a single virtual register for the given type.
Register FunctionLoweringInfo::CreateReg(MVT VT, bool isDivergent) {
  return RegInfo->createVirtualRegister(
      MF->getSubtarget().getTargetLowering()->getRegClassFor(VT, isDivergent));
}

/// CreateRegs - Allocate the appropriate number of virtual registers of
/// the correctly promoted or expanded types.  Assign these registers
/// consecutive vreg numbers and return the first assigned number.
///
/// In the case that the given value has struct or array type, this function
/// will assign registers for each member or element.
///
Register FunctionLoweringInfo::CreateRegs(Type *Ty, bool isDivergent) {
  const TargetLowering *TLI = MF->getSubtarget().getTargetLowering();

  SmallVector<EVT, 4> ValueVTs;
  ComputeValueVTs(*TLI, MF->getDataLayout(), Ty, ValueVTs);

  Register FirstReg;
  for (unsigned Value = 0, e = ValueVTs.size(); Value != e; ++Value) {
    EVT ValueVT = ValueVTs[Value];
    MVT RegisterVT = TLI->getRegisterType(Ty->getContext(), ValueVT);

    unsigned NumRegs = TLI->getNumRegisters(Ty->getContext(), ValueVT);
    for (unsigned i = 0; i != NumRegs; ++i) {
      Register R = CreateReg(RegisterVT, isDivergent);
      if (!FirstReg) FirstReg = R;
    }
  }
  return FirstReg;
}

Register FunctionLoweringInfo::CreateRegs(const Value *V) {
  return CreateRegs(V->getType(), DA && DA->isDivergent(V) &&
                    !TLI->requiresUniformRegister(*MF, V));
}

/// GetLiveOutRegInfo - Gets LiveOutInfo for a register, returning NULL if the
/// register is a PHI destination and the PHI's LiveOutInfo is not valid. If
/// the register's LiveOutInfo is for a smaller bit width, it is extended to
/// the larger bit width by zero extension. The bit width must be no smaller
/// than the LiveOutInfo's existing bit width.
const FunctionLoweringInfo::LiveOutInfo *
FunctionLoweringInfo::GetLiveOutRegInfo(Register Reg, unsigned BitWidth) {
  if (!LiveOutRegInfo.inBounds(Reg))
    return nullptr;

  LiveOutInfo *LOI = &LiveOutRegInfo[Reg];
  if (!LOI->IsValid)
    return nullptr;

  if (BitWidth > LOI->Known.getBitWidth()) {
    LOI->NumSignBits = 1;
    LOI->Known = LOI->Known.anyext(BitWidth);
  }

  return LOI;
}

/// ComputePHILiveOutRegInfo - Compute LiveOutInfo for a PHI's destination
/// register based on the LiveOutInfo of its operands.
void FunctionLoweringInfo::ComputePHILiveOutRegInfo(const PHINode *PN) {
  Type *Ty = PN->getType();
  if (!Ty->isIntegerTy() || Ty->isVectorTy())
    return;

  SmallVector<EVT, 1> ValueVTs;
  ComputeValueVTs(*TLI, MF->getDataLayout(), Ty, ValueVTs);
  assert(ValueVTs.size() == 1 &&
         "PHIs with non-vector integer types should have a single VT.");
  EVT IntVT = ValueVTs[0];

  if (TLI->getNumRegisters(PN->getContext(), IntVT) != 1)
    return;
  IntVT = TLI->getTypeToTransformTo(PN->getContext(), IntVT);
  unsigned BitWidth = IntVT.getSizeInBits();

  Register DestReg = ValueMap[PN];
  if (!Register::isVirtualRegister(DestReg))
    return;
  LiveOutRegInfo.grow(DestReg);
  LiveOutInfo &DestLOI = LiveOutRegInfo[DestReg];

  Value *V = PN->getIncomingValue(0);
  if (isa<UndefValue>(V) || isa<ConstantExpr>(V)) {
    DestLOI.NumSignBits = 1;
    DestLOI.Known = KnownBits(BitWidth);
    return;
  }

  if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
    APInt Val = CI->getValue().zextOrSelf(BitWidth);
    DestLOI.NumSignBits = Val.getNumSignBits();
    DestLOI.Known = KnownBits::makeConstant(Val);
  } else {
    assert(ValueMap.count(V) && "V should have been placed in ValueMap when its"
                                "CopyToReg node was created.");
    Register SrcReg = ValueMap[V];
    if (!Register::isVirtualRegister(SrcReg)) {
      DestLOI.IsValid = false;
      return;
    }
    const LiveOutInfo *SrcLOI = GetLiveOutRegInfo(SrcReg, BitWidth);
    if (!SrcLOI) {
      DestLOI.IsValid = false;
      return;
    }
    DestLOI = *SrcLOI;
  }

  assert(DestLOI.Known.Zero.getBitWidth() == BitWidth &&
         DestLOI.Known.One.getBitWidth() == BitWidth &&
         "Masks should have the same bit width as the type.");

  for (unsigned i = 1, e = PN->getNumIncomingValues(); i != e; ++i) {
    Value *V = PN->getIncomingValue(i);
    if (isa<UndefValue>(V) || isa<ConstantExpr>(V)) {
      DestLOI.NumSignBits = 1;
      DestLOI.Known = KnownBits(BitWidth);
      return;
    }

    if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
      APInt Val = CI->getValue().zextOrSelf(BitWidth);
      DestLOI.NumSignBits = std::min(DestLOI.NumSignBits, Val.getNumSignBits());
      DestLOI.Known.Zero &= ~Val;
      DestLOI.Known.One &= Val;
      continue;
    }

    assert(ValueMap.count(V) && "V should have been placed in ValueMap when "
                                "its CopyToReg node was created.");
    Register SrcReg = ValueMap[V];
    if (!SrcReg.isVirtual()) {
      DestLOI.IsValid = false;
      return;
    }
    const LiveOutInfo *SrcLOI = GetLiveOutRegInfo(SrcReg, BitWidth);
    if (!SrcLOI) {
      DestLOI.IsValid = false;
      return;
    }
    DestLOI.NumSignBits = std::min(DestLOI.NumSignBits, SrcLOI->NumSignBits);
    DestLOI.Known = KnownBits::commonBits(DestLOI.Known, SrcLOI->Known);
  }
}

/// setArgumentFrameIndex - Record frame index for the byval
/// argument. This overrides previous frame index entry for this argument,
/// if any.
void FunctionLoweringInfo::setArgumentFrameIndex(const Argument *A,
                                                 int FI) {
  ByValArgFrameIndexMap[A] = FI;
}

/// getArgumentFrameIndex - Get frame index for the byval argument.
/// If the argument does not have any assigned frame index then 0 is
/// returned.
int FunctionLoweringInfo::getArgumentFrameIndex(const Argument *A) {
  auto I = ByValArgFrameIndexMap.find(A);
  if (I != ByValArgFrameIndexMap.end())
    return I->second;
  LLVM_DEBUG(dbgs() << "Argument does not have assigned frame index!\n");
  return INT_MAX;
}

Register FunctionLoweringInfo::getCatchPadExceptionPointerVReg(
    const Value *CPI, const TargetRegisterClass *RC) {
  MachineRegisterInfo &MRI = MF->getRegInfo();
  auto I = CatchPadExceptionPointers.insert({CPI, 0});
  Register &VReg = I.first->second;
  if (I.second)
    VReg = MRI.createVirtualRegister(RC);
  assert(VReg && "null vreg in exception pointer table!");
  return VReg;
}

const Value *
FunctionLoweringInfo::getValueFromVirtualReg(Register Vreg) {
  if (VirtReg2Value.empty()) {
    SmallVector<EVT, 4> ValueVTs;
    for (auto &P : ValueMap) {
      ValueVTs.clear();
      ComputeValueVTs(*TLI, Fn->getParent()->getDataLayout(),
                      P.first->getType(), ValueVTs);
      unsigned Reg = P.second;
      for (EVT VT : ValueVTs) {
        unsigned NumRegisters = TLI->getNumRegisters(Fn->getContext(), VT);
        for (unsigned i = 0, e = NumRegisters; i != e; ++i)
          VirtReg2Value[Reg++] = P.first;
      }
    }
  }
  return VirtReg2Value.lookup(Vreg);
}
