//===-- AVRInstrInfo.td - AVR Instruction Formats ----------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// AVR Instruction Format Definitions.
//
//===----------------------------------------------------------------------===//

// A generic AVR instruction.
class ABPInst<dag outs, dag ins, string asmstr, list<dag> pattern>
    : Instruction {
  let Namespace = "ABP";

  dag OutOperandList = outs;
  dag InOperandList = ins;
  let AsmString = asmstr;
  let Pattern = pattern;

  field bits<32> SoftFail = 0;
}

/// A 16-bit AVR instruction.
class ABPInst16<dag outs, dag ins, string asmstr, list<dag> pattern>
    : ABPInst<outs, ins, asmstr, pattern> {
  field bits<16> Inst;
  let Size = 2;
}

class FRdRr<bits<4> opcode, dag outs, dag ins, string asmstr,
            list<dag> pattern> : ABPInst16<outs, ins, asmstr, pattern> {
  bits<4> rd;
  bits<4> rs;
  bits<4> rt;

  let Inst{15 - 12} = opcode;
  let Inst{11 - 8} = rd;
  let Inst{7 - 4} = rs;
  let Inst{3 - 0} = rt;
}