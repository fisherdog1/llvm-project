//===-- ABPMCTargetDesc.cpp - ABP Target Descriptions ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides ABP specific target descriptions.
//
//===----------------------------------------------------------------------===//

#include "ABPMCTargetDesc.h"
#include "TargetInfo/ABPTargetInfo.h"

#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCELFStreamer.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"

#define GET_INSTRINFO_MC_DESC
#include "ABPGenInstrInfo.inc"

#define GET_REGINFO_MC_DESC
#include "ABPGenRegisterInfo.inc"

using namespace llvm;

MCInstrInfo *llvm::createABPMCInstrInfo() {
  MCInstrInfo *X = new MCInstrInfo();
  InitABPMCInstrInfo(X);

  return X;
}

static MCRegisterInfo *createABPMCRegisterInfo(const Triple &TT) {
  MCRegisterInfo *X = new MCRegisterInfo();
  InitABPMCRegisterInfo(X, 0);

  return X;
}

static MCSubtargetInfo *createABPMCSubtargetInfo(const Triple &TT,
                                                 StringRef CPU, StringRef FS) {
  return createABPMCSubtargetInfoImpl(TT, CPU, /*TuneCPU*/ CPU, FS);
}

static MCInstPrinter *createABPMCInstPrinter(const Triple &T,
                                             unsigned SyntaxVariant,
                                             const MCAsmInfo &MAI,
                                             const MCInstrInfo &MII,
                                             const MCRegisterInfo &MRI) {
  if (SyntaxVariant == 0) {
    return new ABPInstPrinter(MAI, MII, MRI);
  }

  return nullptr;
}

static MCStreamer *createMCStreamer(const Triple &T, MCContext &Context,
                                    std::unique_ptr<MCAsmBackend> &&MAB,
                                    std::unique_ptr<MCObjectWriter> &&OW,
                                    std::unique_ptr<MCCodeEmitter> &&Emitter,
                                    bool RelaxAll) {
  return createELFStreamer(Context, std::move(MAB), std::move(OW),
                           std::move(Emitter), RelaxAll);
}

static MCTargetStreamer *
createABPObjectTargetStreamer(MCStreamer &S, const MCSubtargetInfo &STI) {
  return new ABPELFStreamer(S, STI);
}

static MCTargetStreamer *createMCAsmTargetStreamer(MCStreamer &S,
                                                   formatted_raw_ostream &OS,
                                                   MCInstPrinter *InstPrint,
                                                   bool isVerboseAsm) {
  return new ABPTargetAsmStreamer(S);
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeABPTargetMC() {
  // Register the MC asm info.
  RegisterMCAsmInfo<ABPMCAsmInfo> X(getTheABPTarget());

  // Register the MC instruction info.
  TargetRegistry::RegisterMCInstrInfo(getTheABPTarget(), createABPMCInstrInfo);

  // Register the MC register info.
  TargetRegistry::RegisterMCRegInfo(getTheABPTarget(), createABPMCRegisterInfo);

  // Register the MC subtarget info.
  TargetRegistry::RegisterMCSubtargetInfo(getTheABPTarget(),
                                          createABPMCSubtargetInfo);

  // Register the MCInstPrinter.
  TargetRegistry::RegisterMCInstPrinter(getTheABPTarget(),
                                        createABPMCInstPrinter);

  // Register the MC Code Emitter
  TargetRegistry::RegisterMCCodeEmitter(getTheABPTarget(),
                                        createABPMCCodeEmitter);

  // Register the obj streamer
  TargetRegistry::RegisterELFStreamer(getTheABPTarget(), createMCStreamer);

  // Register the obj target streamer.
  TargetRegistry::RegisterObjectTargetStreamer(getTheABPTarget(),
                                               createABPObjectTargetStreamer);

  // Register the asm target streamer.
  TargetRegistry::RegisterAsmTargetStreamer(getTheABPTarget(),
                                            createMCAsmTargetStreamer);

  // Register the asm backend (as little endian).
  TargetRegistry::RegisterMCAsmBackend(getTheABPTarget(), createABPAsmBackend);
}
