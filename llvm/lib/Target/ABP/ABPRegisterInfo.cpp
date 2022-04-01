//===-- ABPRegisterInfo.cpp - ABP Register Information --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the ABP implementation of the TargetRegisterInfo class.
//
//===----------------------------------------------------------------------===//

#include "ABPRegisterInfo.h"

#include "llvm/ADT/BitVector.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/IR/Function.h"

#include "ABP.h"
#include "ABPInstrInfo.h"
#include "ABPMachineFunctionInfo.h"
#include "ABPTargetMachine.h"
#include "MCTargetDesc/ABPMCTargetDesc.h"

#define GET_REGINFO_TARGET_DESC
#include "ABPGenRegisterInfo.inc"

namespace llvm {

ABPRegisterInfo::ABPRegisterInfo() : ABPGenRegisterInfo(0) {}

const uint16_t *
ABPRegisterInfo::getCalleeSavedRegs(const MachineFunction *MF) const {
  const ABPMachineFunctionInfo *AFI = MF->getInfo<ABPMachineFunctionInfo>();

  return AFI->isInterruptOrSignalHandler() ? CSR_Interrupts_SaveList
                                           : CSR_Normal_SaveList;
}

const uint32_t *
ABPRegisterInfo::getCallPreservedMask(const MachineFunction &MF,
                                      CallingConv::ID CC) const {
  return CSR_Normal_RegMask;
}

BitVector ABPRegisterInfo::getReservedRegs(const MachineFunction &MF) const {
  BitVector Reserved(getNumRegs());

  // Reserve the intermediate result registers r1 and r2
  // The result of instructions like 'mul' is always stored here.
  Reserved.set(ABP::R0);
  Reserved.set(ABP::R1);
  Reserved.set(ABP::R1R0);

  //  Reserve the stack pointer.
  Reserved.set(ABP::SPL);
  Reserved.set(ABP::SPH);
  Reserved.set(ABP::SP);

  // We tenatively reserve the frame pointer register r29:r28 because the
  // function may require one, but we cannot tell until register allocation
  // is complete, which can be too late.
  //
  // Instead we just unconditionally reserve the Y register.
  //
  // TODO: Write a pass to enumerate functions which reserved the Y register
  //       but didn't end up needing a frame pointer. In these, we can
  //       convert one or two of the spills inside to use the Y register.
  Reserved.set(ABP::R28);
  Reserved.set(ABP::R29);
  Reserved.set(ABP::R29R28);

  return Reserved;
}

const TargetRegisterClass *
ABPRegisterInfo::getLargestLegalSuperClass(const TargetRegisterClass *RC,
                                           const MachineFunction &MF) const {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  if (TRI->isTypeLegalForClass(*RC, MVT::i16)) {
    return &ABP::DREGSRegClass;
  }

  if (TRI->isTypeLegalForClass(*RC, MVT::i8)) {
    return &ABP::GPR8RegClass;
  }

  llvm_unreachable("Invalid register size");
}

/// Fold a frame offset shared between two add instructions into a single one.
static void foldFrameOffset(MachineBasicBlock::iterator &II, int &Offset,
                            Register DstReg) {
  MachineInstr &MI = *II;
  int Opcode = MI.getOpcode();

  // Don't bother trying if the next instruction is not an add or a sub.
  if ((Opcode != ABP::SUBIWRdK) && (Opcode != ABP::ADIWRdK)) {
    return;
  }

  // Check that DstReg matches with next instruction, otherwise the instruction
  // is not related to stack address manipulation.
  if (DstReg != MI.getOperand(0).getReg()) {
    return;
  }

  // Add the offset in the next instruction to our offset.
  switch (Opcode) {
  case ABP::SUBIWRdK:
    Offset += -MI.getOperand(2).getImm();
    break;
  case ABP::ADIWRdK:
    Offset += MI.getOperand(2).getImm();
    break;
  }

  // Finally remove the instruction.
  II++;
  MI.eraseFromParent();
}

void ABPRegisterInfo::eliminateFrameIndex(MachineBasicBlock::iterator II,
                                          int SPAdj, unsigned FIOperandNum,
                                          RegScavenger *RS) const {
  assert(SPAdj == 0 && "Unexpected SPAdj value");

  MachineInstr &MI = *II;
  DebugLoc dl = MI.getDebugLoc();
  MachineBasicBlock &MBB = *MI.getParent();
  const MachineFunction &MF = *MBB.getParent();
  const ABPTargetMachine &TM = (const ABPTargetMachine &)MF.getTarget();
  const TargetInstrInfo &TII = *TM.getSubtargetImpl()->getInstrInfo();
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  const TargetFrameLowering *TFI = TM.getSubtargetImpl()->getFrameLowering();
  int FrameIndex = MI.getOperand(FIOperandNum).getIndex();
  int Offset = MFI.getObjectOffset(FrameIndex);

  // Add one to the offset because SP points to an empty slot.
  Offset += MFI.getStackSize() - TFI->getOffsetOfLocalArea() + 1;
  // Fold incoming offset.
  Offset += MI.getOperand(FIOperandNum + 1).getImm();

  // This is actually "load effective address" of the stack slot
  // instruction. We have only two-address instructions, thus we need to
  // expand it into move + add.
  if (MI.getOpcode() == ABP::FRMIDX) {
    MI.setDesc(TII.get(ABP::MOVWRdRr));
    MI.getOperand(FIOperandNum).ChangeToRegister(ABP::R29R28, false);
    MI.RemoveOperand(2);

    assert(Offset > 0 && "Invalid offset");

    // We need to materialize the offset via an add instruction.
    unsigned Opcode;
    Register DstReg = MI.getOperand(0).getReg();
    assert(DstReg != ABP::R29R28 && "Dest reg cannot be the frame pointer");

    II++; // Skip over the FRMIDX (and now MOVW) instruction.

    // Generally, to load a frame address two add instructions are emitted that
    // could get folded into a single one:
    //  movw    r31:r30, r29:r28
    //  adiw    r31:r30, 29
    //  adiw    r31:r30, 16
    // to:
    //  movw    r31:r30, r29:r28
    //  adiw    r31:r30, 45
    if (II != MBB.end())
      foldFrameOffset(II, Offset, DstReg);

    // Select the best opcode based on DstReg and the offset size.
    switch (DstReg) {
    case ABP::R25R24:
    case ABP::R27R26:
    case ABP::R31R30: {
      if (isUInt<6>(Offset)) {
        Opcode = ABP::ADIWRdK;
        break;
      }
      LLVM_FALLTHROUGH;
    }
    default: {
      // This opcode will get expanded into a pair of subi/sbci.
      Opcode = ABP::SUBIWRdK;
      Offset = -Offset;
      break;
    }
    }

    MachineInstr *New = BuildMI(MBB, II, dl, TII.get(Opcode), DstReg)
                            .addReg(DstReg, RegState::Kill)
                            .addImm(Offset);
    New->getOperand(3).setIsDead();

    return;
  }

  // If the offset is too big we have to adjust and restore the frame pointer
  // to materialize a valid load/store with displacement.
  //: TODO: consider using only one adiw/sbiw chain for more than one frame
  //: index
  if (Offset > 62) {
    unsigned AddOpc = ABP::ADIWRdK, SubOpc = ABP::SBIWRdK;
    int AddOffset = Offset - 63 + 1;

    // For huge offsets where adiw/sbiw cannot be used use a pair of subi/sbci.
    if ((Offset - 63 + 1) > 63) {
      AddOpc = ABP::SUBIWRdK;
      SubOpc = ABP::SUBIWRdK;
      AddOffset = -AddOffset;
    }

    // It is possible that the spiller places this frame instruction in between
    // a compare and branch, invalidating the contents of SREG set by the
    // compare instruction because of the add/sub pairs. Conservatively save and
    // restore SREG before and after each add/sub pair.
    BuildMI(MBB, II, dl, TII.get(ABP::INRdA), ABP::R0).addImm(0x3f);

    MachineInstr *New = BuildMI(MBB, II, dl, TII.get(AddOpc), ABP::R29R28)
                            .addReg(ABP::R29R28, RegState::Kill)
                            .addImm(AddOffset);
    New->getOperand(3).setIsDead();

    // Restore SREG.
    BuildMI(MBB, std::next(II), dl, TII.get(ABP::OUTARr))
        .addImm(0x3f)
        .addReg(ABP::R0, RegState::Kill);

    // No need to set SREG as dead here otherwise if the next instruction is a
    // cond branch it will be using a dead register.
    BuildMI(MBB, std::next(II), dl, TII.get(SubOpc), ABP::R29R28)
        .addReg(ABP::R29R28, RegState::Kill)
        .addImm(Offset - 63 + 1);

    Offset = 62;
  }

  MI.getOperand(FIOperandNum).ChangeToRegister(ABP::R29R28, false);
  assert(isUInt<6>(Offset) && "Offset is out of range");
  MI.getOperand(FIOperandNum + 1).ChangeToImmediate(Offset);
}

Register ABPRegisterInfo::getFrameRegister(const MachineFunction &MF) const {
  const TargetFrameLowering *TFI = MF.getSubtarget().getFrameLowering();
  if (TFI->hasFP(MF)) {
    // The Y pointer register
    return ABP::R28;
  }

  return ABP::SP;
}

const TargetRegisterClass *
ABPRegisterInfo::getPointerRegClass(const MachineFunction &MF,
                                    unsigned Kind) const {
  // FIXME: Currently we're using ABP-gcc as reference, so we restrict
  // ptrs to Y and Z regs. Though ABP-gcc has buggy implementation
  // of memory constraint, so we can fix it and bit ABP-gcc here ;-)
  return &ABP::PTRDISPREGSRegClass;
}

void ABPRegisterInfo::splitReg(Register Reg, Register &LoReg,
                               Register &HiReg) const {
  assert(ABP::DREGSRegClass.contains(Reg) && "can only split 16-bit registers");

  LoReg = getSubReg(Reg, ABP::sub_lo);
  HiReg = getSubReg(Reg, ABP::sub_hi);
}

bool ABPRegisterInfo::shouldCoalesce(
    MachineInstr *MI, const TargetRegisterClass *SrcRC, unsigned SubReg,
    const TargetRegisterClass *DstRC, unsigned DstSubReg,
    const TargetRegisterClass *NewRC, LiveIntervals &LIS) const {
  if (this->getRegClass(ABP::PTRDISPREGSRegClassID)->hasSubClassEq(NewRC)) {
    return false;
  }

  return TargetRegisterInfo::shouldCoalesce(MI, SrcRC, SubReg, DstRC, DstSubReg,
                                            NewRC, LIS);
}

} // end of namespace llvm
