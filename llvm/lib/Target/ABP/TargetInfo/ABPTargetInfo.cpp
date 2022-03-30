//===-- AVRTargetInfo.cpp - AVR Target Implementation ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "TargetInfo/ABPTargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
namespace llvm {
Target &getTheABPTarget() {
  static Target TheABPTarget;
  return TheABPTarget;
}
} // namespace llvm

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeABPTargetInfo() {
  llvm::RegisterTarget<llvm::Triple::abp> X(llvm::getTheABPTarget(), "abp",
                                            "Aaron's Bad Processor", "ABP");
}
