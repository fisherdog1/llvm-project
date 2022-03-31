//===-- ABPInstrInfo.td - AVR Instruction defs -------------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file describes the AVR instructions in TableGen format.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// Register / register instruction: <|opcode|ffrd|dddd|rrrr|>
// opcode = 4 bits.
// f = secondary opcode = 2 bits
// d = destination = 5 bits
// r = source = 5 bits
// (Accepts all registers)
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

//===----------------------------------------------------------------------===//
// AVR Type Profiles
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// AVR Specific Node Definitions
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// AVR predicates for subtarget features
//===----------------------------------------------------------------------===//


//===----------------------------------------------------------------------===//
//===----------------------------------------------------------------------===//
// AVR Instruction list
//===----------------------------------------------------------------------===//
//===----------------------------------------------------------------------===//


//===----------------------------------------------------------------------===//
// Addition
//===----------------------------------------------------------------------===//
let isCommutable = 1 in {
  // ADD Rd, Rr
  // Adds two 8-bit registers.
  def ADDRdRr
      : FRdRr<0b0000,
              (outs GPR8 : $rd),
              (ins GPR8 : $rs, GPR8 : $rt),
              "add\t$rd, $rs, $rt",
              [(set i8 : $rd, (add i8 : $rs, i8 : $rt))]>;
}