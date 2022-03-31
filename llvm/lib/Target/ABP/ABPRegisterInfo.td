//===-- ABPRegisterInfo.td - AVR Register defs -------------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//  Declarations that describe the AVR register file
//===----------------------------------------------------------------------===//

// 8-bit General purpose register definition.
class ABPReg<bits<16> num, string name, list<Register> subregs = [],
             list<string> altNames = []> : RegisterWithSubRegs<name, subregs> {
  field bits<16> Num = num;

  let HWEncoding = num;
  let Namespace = "ABP";
  let SubRegs = subregs;
  let AltNames = altNames;
}

// Subregister indices.
let Namespace = "ABP" in {
  def sub_lo : SubRegIndex<8>;
  def sub_hi : SubRegIndex<8, 8>;
}

let Namespace = "ABP" in { def ptr : RegAltNameIndex; }

//===----------------------------------------------------------------------===//
//  8-bit general purpose registers
//===----------------------------------------------------------------------===//

def R0 : ABPReg<0, "r0">, DwarfRegNum<[0]>;
def R1 : ABPReg<1, "r1">, DwarfRegNum<[1]>;
def R2 : ABPReg<2, "r2">, DwarfRegNum<[2]>;
def R3 : ABPReg<3, "r3">, DwarfRegNum<[3]>;
def R4 : ABPReg<4, "r4">, DwarfRegNum<[4]>;
def R5 : ABPReg<5, "r5">, DwarfRegNum<[5]>;
def R6 : ABPReg<6, "r6">, DwarfRegNum<[6]>;
def R7 : ABPReg<7, "r7">, DwarfRegNum<[7]>;
def R8 : ABPReg<8, "r8", [], ["AH"]>, DwarfRegNum<[8]>;
def R9 : ABPReg<9, "r9", [], ["AL"]>, DwarfRegNum<[9]>;
def R10 : ABPReg<10, "r10", [], ["BH"]>, DwarfRegNum<[10]>;
def R11 : ABPReg<11, "r11", [], ["BL"]>, DwarfRegNum<[11]>;
def R12 : ABPReg<12, "r12", [], ["CH"]>, DwarfRegNum<[12]>;
def R13 : ABPReg<13, "r13", [], ["CL"]>, DwarfRegNum<[13]>;
def R14 : ABPReg<14, "r14", [], ["DH"]>, DwarfRegNum<[14]>;
def R15 : ABPReg<15, "r15", [], ["DL"]>, DwarfRegNum<[15]>;
def SPH : ABPReg<16, "SPH">, DwarfRegNum<[16]>;
def SPL : ABPReg<17, "SPL">, DwarfRegNum<[17]>;

let SubRegIndices = [sub_lo, sub_hi], CoveredBySubRegs = 1 in {
  // 16 bit GPR pairs.
  def SP : ABPReg<32, "SP", [SPL, SPH]>, DwarfRegNum<[16]>;

  def R8R9 : ABPReg<8, "A", [R8, R9]>, DwarfRegNum<[8]>;
  def R10R11 : ABPReg<10, "B", [R10, R11]>, DwarfRegNum<[10]>;
  def R12R13 : ABPReg<12, "C", [R12, R13]>, DwarfRegNum<[12]>;
  def R14R15 : ABPReg<14, "D", [R14, R15]>, DwarfRegNum<[14]>;
}

//===----------------------------------------------------------------------===//
// Register Classes
//===----------------------------------------------------------------------===//

// Main 8-bit register class.
def GPR8 : RegisterClass<"ABP", [i8], 8,
                         ( add R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15)>;

// 16-bit register class for the ld and st instructions.
// AKA X,Y, and Z
def PTRREGS : RegisterClass<"ABP", [i16], 8,
                            (add R8R9, R10R11, R12R13, R14R15),
                            ptr>;

// Register class used for the stack read pseudo instruction.
def GPRSP : RegisterClass<"ABP", [i16], 8, (add SP)>;

// Status register.
//TODO ABP
