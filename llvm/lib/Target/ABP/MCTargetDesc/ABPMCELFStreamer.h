//===--------- ABPMCELFStreamer.h - ABP subclass of MCELFStreamer ---------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_ABP_MCTARGETDESC_ABPMCELFSTREAMER_H
#define LLVM_LIB_TARGET_ABP_MCTARGETDESC_ABPMCELFSTREAMER_H

#include "MCTargetDesc/ABPMCExpr.h"
#include "MCTargetDesc/ABPMCTargetDesc.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCELFStreamer.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectWriter.h"

namespace llvm {

const int SIZE_LONG = 4;
const int SIZE_WORD = 2;

class ABPMCELFStreamer : public MCELFStreamer {
  std::unique_ptr<MCInstrInfo> MCII;

public:
  ABPMCELFStreamer(MCContext &Context, std::unique_ptr<MCAsmBackend> TAB,
                   std::unique_ptr<MCObjectWriter> OW,
                   std::unique_ptr<MCCodeEmitter> Emitter)
      : MCELFStreamer(Context, std::move(TAB), std::move(OW),
                      std::move(Emitter)),
        MCII(createABPMCInstrInfo()) {}

  ABPMCELFStreamer(MCContext &Context, std::unique_ptr<MCAsmBackend> TAB,
                   std::unique_ptr<MCObjectWriter> OW,
                   std::unique_ptr<MCCodeEmitter> Emitter,
                   MCAssembler *Assembler)
      : MCELFStreamer(Context, std::move(TAB), std::move(OW),
                      std::move(Emitter)),
        MCII(createABPMCInstrInfo()) {}

  void emitValueForModiferKind(
      const MCSymbol *Sym, unsigned SizeInBytes, SMLoc Loc = SMLoc(),
      ABPMCExpr::VariantKind ModifierKind = ABPMCExpr::VK_ABP_None);
};

MCStreamer *createABPELFStreamer(Triple const &TT, MCContext &Context,
                                 std::unique_ptr<MCAsmBackend> MAB,
                                 std::unique_ptr<MCObjectWriter> OW,
                                 std::unique_ptr<MCCodeEmitter> CE);

} // end namespace llvm

#endif // LLVM_LIB_TARGET_ABP_MCTARGETDESC_ABPMCELFSTREAMER_H
