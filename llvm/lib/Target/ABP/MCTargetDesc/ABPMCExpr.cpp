//===-- ABPMCExpr.cpp - ABP specific MC expression classes ----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ABPMCExpr.h"

#include "llvm/MC/MCAsmLayout.h"
#include "llvm/MC/MCAssembler.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCValue.h"

namespace llvm {

namespace {

const struct ModifierEntry {
  const char *const Spelling;
  ABPMCExpr::VariantKind VariantKind;
} ModifierNames[] = {
    {"lo8", ABPMCExpr::VK_ABP_LO8},       {"hi8", ABPMCExpr::VK_ABP_HI8},
    {"hh8", ABPMCExpr::VK_ABP_HH8}, // synonym with hlo8
    {"hlo8", ABPMCExpr::VK_ABP_HH8},      {"hhi8", ABPMCExpr::VK_ABP_HHI8},

    {"pm", ABPMCExpr::VK_ABP_PM},         {"pm_lo8", ABPMCExpr::VK_ABP_PM_LO8},
    {"pm_hi8", ABPMCExpr::VK_ABP_PM_HI8}, {"pm_hh8", ABPMCExpr::VK_ABP_PM_HH8},

    {"lo8_gs", ABPMCExpr::VK_ABP_LO8_GS}, {"hi8_gs", ABPMCExpr::VK_ABP_HI8_GS},
    {"gs", ABPMCExpr::VK_ABP_GS},
};

} // end of anonymous namespace

const ABPMCExpr *ABPMCExpr::create(VariantKind Kind, const MCExpr *Expr,
                                   bool Negated, MCContext &Ctx) {
  return new (Ctx) ABPMCExpr(Kind, Expr, Negated);
}

void ABPMCExpr::printImpl(raw_ostream &OS, const MCAsmInfo *MAI) const {
  assert(Kind != VK_ABP_None);

  if (isNegated())
    OS << '-';

  OS << getName() << '(';
  getSubExpr()->print(OS, MAI);
  OS << ')';
}

bool ABPMCExpr::evaluateAsConstant(int64_t &Result) const {
  MCValue Value;

  bool isRelocatable =
      getSubExpr()->evaluateAsRelocatable(Value, nullptr, nullptr);

  if (!isRelocatable)
    return false;

  if (Value.isAbsolute()) {
    Result = evaluateAsInt64(Value.getConstant());
    return true;
  }

  return false;
}

bool ABPMCExpr::evaluateAsRelocatableImpl(MCValue &Result,
                                          const MCAsmLayout *Layout,
                                          const MCFixup *Fixup) const {
  MCValue Value;
  bool isRelocatable = SubExpr->evaluateAsRelocatable(Value, Layout, Fixup);

  if (!isRelocatable)
    return false;

  if (Value.isAbsolute()) {
    Result = MCValue::get(evaluateAsInt64(Value.getConstant()));
  } else {
    if (!Layout)
      return false;

    MCContext &Context = Layout->getAssembler().getContext();
    const MCSymbolRefExpr *Sym = Value.getSymA();
    MCSymbolRefExpr::VariantKind Modifier = Sym->getKind();
    if (Modifier != MCSymbolRefExpr::VK_None)
      return false;
    if (Kind == VK_ABP_PM) {
      Modifier = MCSymbolRefExpr::VK_ABP_PM;
    }

    Sym = MCSymbolRefExpr::create(&Sym->getSymbol(), Modifier, Context);
    Result = MCValue::get(Sym, Value.getSymB(), Value.getConstant());
  }

  return true;
}

int64_t ABPMCExpr::evaluateAsInt64(int64_t Value) const {
  if (Negated)
    Value *= -1;

  switch (Kind) {
  case ABPMCExpr::VK_ABP_LO8:
    Value &= 0xff;
    break;
  case ABPMCExpr::VK_ABP_HI8:
    Value &= 0xff00;
    Value >>= 8;
    break;
  case ABPMCExpr::VK_ABP_HH8:
    Value &= 0xff0000;
    Value >>= 16;
    break;
  case ABPMCExpr::VK_ABP_HHI8:
    Value &= 0xff000000;
    Value >>= 24;
    break;
  case ABPMCExpr::VK_ABP_PM_LO8:
  case ABPMCExpr::VK_ABP_LO8_GS:
    Value >>= 1; // Program memory addresses must always be shifted by one.
    Value &= 0xff;
    break;
  case ABPMCExpr::VK_ABP_PM_HI8:
  case ABPMCExpr::VK_ABP_HI8_GS:
    Value >>= 1; // Program memory addresses must always be shifted by one.
    Value &= 0xff00;
    Value >>= 8;
    break;
  case ABPMCExpr::VK_ABP_PM_HH8:
    Value >>= 1; // Program memory addresses must always be shifted by one.
    Value &= 0xff0000;
    Value >>= 16;
    break;
  case ABPMCExpr::VK_ABP_PM:
  case ABPMCExpr::VK_ABP_GS:
    Value >>= 1; // Program memory addresses must always be shifted by one.
    break;

  case ABPMCExpr::VK_ABP_None:
    llvm_unreachable("Uninitialized expression.");
  }
  return static_cast<uint64_t>(Value) & 0xff;
}

ABP::Fixups ABPMCExpr::getFixupKind() const {
  ABP::Fixups Kind = ABP::Fixups::LastTargetFixupKind;

  switch (getKind()) {
  case VK_ABP_LO8:
    Kind = isNegated() ? ABP::fixup_lo8_ldi_neg : ABP::fixup_lo8_ldi;
    break;
  case VK_ABP_HI8:
    Kind = isNegated() ? ABP::fixup_hi8_ldi_neg : ABP::fixup_hi8_ldi;
    break;
  case VK_ABP_HH8:
    Kind = isNegated() ? ABP::fixup_hh8_ldi_neg : ABP::fixup_hh8_ldi;
    break;
  case VK_ABP_HHI8:
    Kind = isNegated() ? ABP::fixup_ms8_ldi_neg : ABP::fixup_ms8_ldi;
    break;

  case VK_ABP_PM_LO8:
    Kind = isNegated() ? ABP::fixup_lo8_ldi_pm_neg : ABP::fixup_lo8_ldi_pm;
    break;
  case VK_ABP_PM_HI8:
    Kind = isNegated() ? ABP::fixup_hi8_ldi_pm_neg : ABP::fixup_hi8_ldi_pm;
    break;
  case VK_ABP_PM_HH8:
    Kind = isNegated() ? ABP::fixup_hh8_ldi_pm_neg : ABP::fixup_hh8_ldi_pm;
    break;
  case VK_ABP_PM:
  case VK_ABP_GS:
    Kind = ABP::fixup_16_pm;
    break;
  case VK_ABP_LO8_GS:
    Kind = ABP::fixup_lo8_ldi_gs;
    break;
  case VK_ABP_HI8_GS:
    Kind = ABP::fixup_hi8_ldi_gs;
    break;

  case VK_ABP_None:
    llvm_unreachable("Uninitialized expression");
  }

  return Kind;
}

void ABPMCExpr::visitUsedExpr(MCStreamer &Streamer) const {
  Streamer.visitUsedExpr(*getSubExpr());
}

const char *ABPMCExpr::getName() const {
  const auto &Modifier =
      llvm::find_if(ModifierNames, [this](ModifierEntry const &Mod) {
        return Mod.VariantKind == Kind;
      });

  if (Modifier != std::end(ModifierNames)) {
    return Modifier->Spelling;
  }
  return nullptr;
}

ABPMCExpr::VariantKind ABPMCExpr::getKindByName(StringRef Name) {
  const auto &Modifier =
      llvm::find_if(ModifierNames, [&Name](ModifierEntry const &Mod) {
        return Mod.Spelling == Name;
      });

  if (Modifier != std::end(ModifierNames)) {
    return Modifier->VariantKind;
  }
  return VK_ABP_None;
}

} // end of namespace llvm
