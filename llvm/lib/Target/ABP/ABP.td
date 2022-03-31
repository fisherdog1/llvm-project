//===-- AVR.td - Describe the AVR Target Machine ----------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//
// This is the top level entry point for the AVR target.
//===---------------------------------------------------------------------===//

//===---------------------------------------------------------------------===//
// Target-independent interfaces which we are implementing
//===---------------------------------------------------------------------===//

include "llvm/Target/Target.td"

//===---------------------------------------------------------------------===//
// AVR Device Definitions
//===---------------------------------------------------------------------===//

//TODO ABP

//===---------------------------------------------------------------------===//
// Register File Description
//===---------------------------------------------------------------------===//

include "ABPRegisterInfo.td"

//===---------------------------------------------------------------------===//
// Instruction Descriptions
//===---------------------------------------------------------------------===//

include "ABPInstrInfo.td"

def ABPInstrInfo : InstrInfo;

//===---------------------------------------------------------------------===//
// Calling Conventions
//===---------------------------------------------------------------------===//

//TODO ABP

//===---------------------------------------------------------------------===//
// Assembly Printers
//===---------------------------------------------------------------------===//

//TODO ABP

//===---------------------------------------------------------------------===//
// Assembly Parsers
//===---------------------------------------------------------------------===//

def ABPAsmParser : AsmParser {
  let ShouldEmitMatchRegisterName = 1;
  let ShouldEmitMatchRegisterAltName = 1; //?? what is this
}

//===---------------------------------------------------------------------===//
// Target Declaration
//===---------------------------------------------------------------------===//

def ABP : Target {
  let InstructionSet = ABPInstrInfo;
  let AssemblyParsers = [ABPAsmParser];
}
