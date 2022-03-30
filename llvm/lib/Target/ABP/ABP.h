//===-- AVR.h - Top-level interface for AVR representation ------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the entry points for global functions defined in the LLVM
// AVR back-end.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ABP_H
#define LLVM_ABP_H

#include "llvm/CodeGen/SelectionDAGNodes.h"
#include "llvm/Target/TargetMachine.h"

namespace llvm {

class ABPTargetMachine;
class FunctionPass;

FunctionPass *createAVRISelDag(AVRTargetMachine &TM,
                               CodeGenOpt::Level OptLevel);
FunctionPass *createAVRExpandPseudoPass();
FunctionPass *createAVRFrameAnalyzerPass();
FunctionPass *createAVRRelaxMemPass();
FunctionPass *createAVRBranchSelectionPass();

void initializeAVRShiftExpandPass(PassRegistry &);
void initializeAVRExpandPseudoPass(PassRegistry &);
void initializeAVRRelaxMemPass(PassRegistry &);

/// Contains the AVR backend.
namespace ABP {

/// An integer that identifies all of the supported AVR address spaces.
enum AddressSpace {
  DataMemory,
  ProgramMemory,
};

/// Checks if a given type is a pointer to program memory.
template <typename T> bool isProgramMemoryAddress(T *V) {
  auto *PT = cast<PointerType>(V->getType());
  assert(PT != nullptr && "unexpected MemSDNode");
  return PT->getAddressSpace() == ProgramMemory;
}

template <typename T> AddressSpace getAddressSpace(T *V) {
  auto *PT = cast<PointerType>(V->getType());
  assert(PT != nullptr && "unexpected MemSDNode");
  unsigned AS = PT->getAddressSpace();
  if (AS < NumAddrSpaces)
    return static_cast<AddressSpace>(AS);
  return NumAddrSpaces;
}

inline bool isProgramMemoryAccess(MemSDNode const *N) {
  auto *V = N->getMemOperand()->getValue();
  if (V != nullptr && isProgramMemoryAddress(V))
    return true;
  return false;
}

// Get the index of the program memory bank.
//  -1: not program memory
//   0: ordinary program memory
// 1~5: extended program memory
inline int getProgramMemoryBank(MemSDNode const *N) {
  auto *V = N->getMemOperand()->getValue();
  if (V == nullptr || !isProgramMemoryAddress(V))
    return -1;
	
  return 1;
}

} // end of namespace AVR

} // end namespace llvm

#endif // LLVM_AVR_H
