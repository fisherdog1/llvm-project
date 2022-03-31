//===-- ABPMCTargetDesc.h - ABP Target Descriptions -------------*- C++ -*-===//
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

#ifndef LLVM_ABP_MCTARGET_DESC_H
#define LLVM_ABP_MCTARGET_DESC_H

#include "llvm/Support/DataTypes.h"

#include <memory>

namespace llvm {

class MCAsmBackend;
class MCCodeEmitter;
class MCContext;
class MCInstrInfo;
class MCObjectTargetWriter;
class MCRegisterInfo;
class MCSubtargetInfo;
class MCTargetOptions;
class Target;

MCInstrInfo *createABPMCInstrInfo();

/// Creates a machine code emitter for ABP.
MCCodeEmitter *createABPMCCodeEmitter(const MCInstrInfo &MCII,
                                      const MCRegisterInfo &MRI,
                                      MCContext &Ctx);

/// Creates an assembly backend for ABP.
MCAsmBackend *createABPAsmBackend(const Target &T, const MCSubtargetInfo &STI,
                                  const MCRegisterInfo &MRI,
                                  const llvm::MCTargetOptions &TO);

/// Creates an ELF object writer for ABP.
std::unique_ptr<MCObjectTargetWriter> createABPELFObjectWriter(uint8_t OSABI);

} // end namespace llvm

#define GET_REGINFO_ENUM
#include "ABPGenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "ABPGenInstrInfo.inc"

#endif // LLVM_ABP_MCTARGET_DESC_H
