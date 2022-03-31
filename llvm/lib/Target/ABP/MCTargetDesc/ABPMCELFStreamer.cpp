//===--------- ABPMCELFStreamer.cpp - ABP subclass of MCELFStreamer -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a stub that parses a MCInst bundle and passes the
// instructions on to the real streamer.
//
//===----------------------------------------------------------------------===//
#include "MCTargetDesc/ABPMCELFStreamer.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCSymbol.h"

#define DEBUG_TYPE "avrmcelfstreamer"

using namespace llvm;

void ABPMCELFStreamer::emitValueForModiferKind(
    const MCSymbol *Sym, unsigned SizeInBytes, SMLoc Loc,
    ABPMCExpr::VariantKind ModifierKind) {
  MCSymbolRefExpr::VariantKind Kind = MCSymbolRefExpr::VK_ABP_NONE;
  if (ModifierKind == ABPMCExpr::VK_ABP_None) {
    Kind = MCSymbolRefExpr::VK_ABP_DIFF8;
    if (SizeInBytes == SIZE_LONG)
      Kind = MCSymbolRefExpr::VK_ABP_DIFF32;
    else if (SizeInBytes == SIZE_WORD)
      Kind = MCSymbolRefExpr::VK_ABP_DIFF16;
  } else if (ModifierKind == ABPMCExpr::VK_ABP_LO8)
    Kind = MCSymbolRefExpr::VK_ABP_LO8;
  else if (ModifierKind == ABPMCExpr::VK_ABP_HI8)
    Kind = MCSymbolRefExpr::VK_ABP_HI8;
  else if (ModifierKind == ABPMCExpr::VK_ABP_HH8)
    Kind = MCSymbolRefExpr::VK_ABP_HLO8;
  MCELFStreamer::emitValue(MCSymbolRefExpr::create(Sym, Kind, getContext()),
                           SizeInBytes, Loc);
}

namespace llvm {
MCStreamer *createABPELFStreamer(Triple const &TT, MCContext &Context,
                                 std::unique_ptr<MCAsmBackend> MAB,
                                 std::unique_ptr<MCObjectWriter> OW,
                                 std::unique_ptr<MCCodeEmitter> CE) {
  return new ABPMCELFStreamer(Context, std::move(MAB), std::move(OW),
                              std::move(CE));
}

} // end namespace llvm
