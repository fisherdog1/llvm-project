//===---- ABPAsmParser.cpp - Parse ABP assembly to MCInst instructions ----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ABP.h"
#include "TargetInfo/ABPTargetInfo.h"

#include "llvm/ADT/APInt.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstBuilder.h"
#include "llvm/MC/MCParser/MCAsmLexer.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCValue.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"

#include <sstream>

#define DEBUG_TYPE "abp-asm-parser"

using namespace llvm;

namespace {
/// Parses ABP assembly from a stream.
class ABPAsmParser : public MCTargetAsmParser {
  const MCSubtargetInfo &STI;
  MCAsmParser &Parser;
  const MCRegisterInfo *MRI;
  const std::string GENERATE_STUBS = "gs";

#define GET_ASSEMBLER_HEADER
#include "ABPGenAsmMatcher.inc"

  bool MatchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                               OperandVector &Operands, MCStreamer &Out,
                               uint64_t &ErrorInfo,
                               bool MatchingInlineAsm) override;

  bool ParseRegister(unsigned &RegNo, SMLoc &StartLoc, SMLoc &EndLoc) override;
  OperandMatchResultTy tryParseRegister(unsigned &RegNo, SMLoc &StartLoc,
                                        SMLoc &EndLoc) override;

  bool ParseInstruction(ParseInstructionInfo &Info, StringRef Name,
                        SMLoc NameLoc, OperandVector &Operands) override;

  bool ParseDirective(AsmToken DirectiveID) override;

  bool parseOperand(OperandVector &Operands);
  int parseRegisterName(unsigned (*matchFn)(StringRef));
  int parseRegisterName();
  int parseRegister(bool RestoreOnFailure = false);
  bool tryParseRegisterOperand(OperandVector &Operands);
  bool tryParseExpression(OperandVector &Operands);
  bool tryParseRelocExpression(OperandVector &Operands);
  void eatComma();

  unsigned validateTargetOperandClass(MCParsedAsmOperand &Op,
                                      unsigned Kind) override;

  bool emit(MCInst &Instruction, SMLoc const &Loc, MCStreamer &Out) const;
  bool invalidOperand(SMLoc const &Loc, OperandVector const &Operands,
                      uint64_t const &ErrorInfo);
  bool missingFeature(SMLoc const &Loc, uint64_t const &ErrorInfo);

  bool parseLiteralValues(unsigned SizeInBytes, SMLoc L);

public:
  ABPAsmParser(const MCSubtargetInfo &STI, MCAsmParser &Parser,
               const MCInstrInfo &MII, const MCTargetOptions &Options)
      : MCTargetAsmParser(Options, STI, MII), STI(STI), Parser(Parser) {
    MCAsmParserExtension::Initialize(Parser);
    MRI = getContext().getRegisterInfo();

    setAvailableFeatures(ComputeAvailableFeatures(STI.getFeatureBits()));
  }

  MCAsmParser &getParser() const { return Parser; }
  MCAsmLexer &getLexer() const { return Parser.getLexer(); }
};

//TODO ABP
/// An parsed ABP assembly operand.
class ABPOperand : public MCParsedAsmOperand {
  typedef MCParsedAsmOperand Base;
  enum KindTy { k_Immediate, k_Register, k_Token } Kind;

public:
  ABPOperand(StringRef Tok, SMLoc const &S)
      : Kind(k_Token), Tok(Tok), Start(S), End(S) {}
  ABPOperand(unsigned Reg, SMLoc const &S, SMLoc const &E)
      : Kind(k_Register), RegImm({Reg, nullptr}), Start(S), End(E) {}
  ABPOperand(MCExpr const *Imm, SMLoc const &S, SMLoc const &E)
      : Kind(k_Immediate), RegImm({0, Imm}), Start(S), End(E) {}

  union {
    StringRef Tok;
    RegisterImmediate RegImm;
  };

  SMLoc Start, End;

public:
  void addRegOperands(MCInst &Inst, unsigned N) const {
    assert(Kind == k_Register && "Unexpected operand kind");
    assert(N == 1 && "Invalid number of operands!");

    Inst.addOperand(MCOperand::createReg(getReg()));
  }

  void addExpr(MCInst &Inst, const MCExpr *Expr) const {
    // Add as immediate when possible
    if (!Expr)
      Inst.addOperand(MCOperand::createImm(0));
    else if (const MCConstantExpr *CE = dyn_cast<MCConstantExpr>(Expr))
      Inst.addOperand(MCOperand::createImm(CE->getValue()));
    else
      Inst.addOperand(MCOperand::createExpr(Expr));
  }

  void addImmOperands(MCInst &Inst, unsigned N) const {
    assert(Kind == k_Immediate && "Unexpected operand kind");
    assert(N == 1 && "Invalid number of operands!");

    const MCExpr *Expr = getImm();
    addExpr(Inst, Expr);
  }

  bool isReg() const override { return Kind == k_Register; }
  bool isImm() const override { return Kind == k_Immediate; }
  bool isToken() const override { return Kind == k_Token; }

  StringRef getToken() const {
    assert(Kind == k_Token && "Invalid access!");
    return Tok;
  }

  static std::unique_ptr<ABPOperand> CreateToken(StringRef Str, SMLoc S) {
    return std::make_unique<ABPOperand>(Str, S);
  }

  static std::unique_ptr<ABPOperand> CreateReg(unsigned RegNum, SMLoc S,
                                               SMLoc E) {
    return std::make_unique<ABPOperand>(RegNum, S, E);
  }

  static std::unique_ptr<ABPOperand> CreateImm(const MCExpr *Val, SMLoc S,
                                               SMLoc E) {
    return std::make_unique<ABPOperand>(Val, S, E);
  }

  void makeToken(StringRef Token) {
    Kind = k_Token;
    Tok = Token;
  }

  void makeReg(unsigned RegNo) {
    Kind = k_Register;
    RegImm = {RegNo, nullptr};
  }

  void makeImm(MCExpr const *Ex) {
    Kind = k_Immediate;
    RegImm = {0, Ex};
  }

  SMLoc getStartLoc() const override { return Start; }
  SMLoc getEndLoc() const override { return End; }

  void print(raw_ostream &O) const override {
    switch (Kind) {
    case k_Token:
      O << "Token: \"" << getToken() << "\"";
      break;
    case k_Register:
      O << "Register: " << getReg();
      break;
    case k_Immediate:
      O << "Immediate: \"" << *getImm() << "\"";
      break;
    }
    O << "\n";
  }
};

} // end anonymous namespace.

// Auto-generated Match Functions

/// Maps from the set of all register names to a register number.
/// \note Generated by TableGen.
static unsigned MatchRegisterName(StringRef Name);

/// Maps from the set of all alternative registernames to a register number.
/// \note Generated by TableGen.
static unsigned MatchRegisterAltName(StringRef Name);

bool ABPAsmParser::invalidOperand(SMLoc const &Loc,
                                  OperandVector const &Operands,
                                  uint64_t const &ErrorInfo) {
  SMLoc ErrorLoc = Loc;
  char const *Diag = nullptr;

  if (ErrorInfo != ~0U) {
    if (ErrorInfo >= Operands.size()) {
      Diag = "too few operands for instruction.";
    } else {
      ABPOperand const &Op = (ABPOperand const &)*Operands[ErrorInfo];

      // TODO: See if we can do a better error than just "invalid ...".
      if (Op.getStartLoc() != SMLoc()) {
        ErrorLoc = Op.getStartLoc();
      }
    }
  }

  if (!Diag) {
    Diag = "invalid operand for instruction";
  }

  return Error(ErrorLoc, Diag);
}

bool ABPAsmParser::missingFeature(llvm::SMLoc const &Loc,
                                  uint64_t const &ErrorInfo) {
  return Error(Loc, "instruction requires a CPU feature not currently enabled");
}

bool ABPAsmParser::emit(MCInst &Inst, SMLoc const &Loc, MCStreamer &Out) const {
  Inst.setLoc(Loc);
  Out.emitInstruction(Inst, STI);

  return false;
}

bool ABPAsmParser::MatchAndEmitInstruction(SMLoc Loc, unsigned &Opcode,
                                           OperandVector &Operands,
                                           MCStreamer &Out, uint64_t &ErrorInfo,
                                           bool MatchingInlineAsm) {
  MCInst Inst;
  unsigned MatchResult =
      MatchInstructionImpl(Operands, Inst, ErrorInfo, MatchingInlineAsm);

  switch (MatchResult) {
  case Match_Success:
    return emit(Inst, Loc, Out);
  case Match_MissingFeature:
    return missingFeature(Loc, ErrorInfo);
  case Match_InvalidOperand:
    return invalidOperand(Loc, Operands, ErrorInfo);
  case Match_MnemonicFail:
    return Error(Loc, "invalid instruction");
  default:
    return true;
  }
}

/// Parses a register name using a given matching function.
/// Checks for lowercase or uppercase if necessary.
int ABPAsmParser::parseRegisterName(unsigned (*matchFn)(StringRef)) {
  StringRef Name = Parser.getTok().getString();

  int RegNum = matchFn(Name);

  return RegNum;
}

int ABPAsmParser::parseRegisterName() {
  int RegNum = parseRegisterName(&MatchRegisterName);

  if (RegNum == ABP::NoRegister)
    RegNum = parseRegisterName(&MatchRegisterAltName);

  return RegNum;
}

int ABPAsmParser::parseRegister(bool RestoreOnFailure) {
  int RegNum = ABP::NoRegister;

  if (Parser.getTok().is(AsmToken::Identifier)) {
    // Check for register pair syntax
    if (Parser.getLexer().peekTok().is(AsmToken::Colon)) {
      AsmToken HighTok = Parser.getTok();
      Parser.Lex();
      AsmToken ColonTok = Parser.getTok();
      Parser.Lex(); // Eat high (odd) register and colon

      if (Parser.getTok().is(AsmToken::Identifier)) {
        // Convert lower (even) register to DREG
        RegNum = parseRegisterName();
      }
      if (RegNum == ABP::NoRegister && RestoreOnFailure) {
        getLexer().UnLex(std::move(ColonTok));
        getLexer().UnLex(std::move(HighTok));
      }
    } else {
      RegNum = parseRegisterName();
    }
  }
  return RegNum;
}

bool ABPAsmParser::tryParseRegisterOperand(OperandVector &Operands) {
  int RegNo = parseRegister();

  if (RegNo == ABP::NoRegister)
    return true;

  AsmToken const &T = Parser.getTok();
  Operands.push_back(ABPOperand::CreateReg(RegNo, T.getLoc(), T.getEndLoc()));
  Parser.Lex(); // Eat register token.

  return false;
}

bool ABPAsmParser::tryParseExpression(OperandVector &Operands) {
  SMLoc S = Parser.getTok().getLoc();

  if (!tryParseRelocExpression(Operands))
    return false;

  if ((Parser.getTok().getKind() == AsmToken::Plus ||
       Parser.getTok().getKind() == AsmToken::Minus) &&
      Parser.getLexer().peekTok().getKind() == AsmToken::Identifier) {
    // Don't handle this case - it should be split into two
    // separate tokens.
    return true;
  }

  // Parse (potentially inner) expression
  MCExpr const *Expression;
  if (getParser().parseExpression(Expression))
    return true;

  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  Operands.push_back(ABPOperand::CreateImm(Expression, S, E));
  return false;
}

bool ABPAsmParser::tryParseRelocExpression(OperandVector &Operands) {
  bool isNegated = false;
  ABPMCExpr::VariantKind ModifierKind = ABPMCExpr::VK_ABP_None;

  SMLoc S = Parser.getTok().getLoc();

  // Check for sign
  AsmToken tokens[2];
  size_t ReadCount = Parser.getLexer().peekTokens(tokens);

  if (ReadCount == 2) {
    if ((tokens[0].getKind() == AsmToken::Identifier &&
         tokens[1].getKind() == AsmToken::LParen) ||
        (tokens[0].getKind() == AsmToken::LParen &&
         tokens[1].getKind() == AsmToken::Minus)) {

      AsmToken::TokenKind CurTok = Parser.getLexer().getKind();
      if (CurTok == AsmToken::Minus || tokens[1].getKind() == AsmToken::Minus) {
        isNegated = true;
      } else {
        assert(CurTok == AsmToken::Plus);
        isNegated = false;
      }

      // Eat the sign
      if (CurTok == AsmToken::Minus || CurTok == AsmToken::Plus)
        Parser.Lex();
    }
  }

  // Check if we have a target specific modifier (lo8, hi8, &c)
  if (Parser.getTok().getKind() != AsmToken::Identifier ||
      Parser.getLexer().peekTok().getKind() != AsmToken::LParen) {
    // Not a reloc expr
    return true;
  }
  StringRef ModifierName = Parser.getTok().getString();
  ModifierKind = ABPMCExpr::getKindByName(ModifierName);

  if (ModifierKind != ABPMCExpr::VK_ABP_None) {
    Parser.Lex();
    Parser.Lex(); // Eat modifier name and parenthesis
    if (Parser.getTok().getString() == GENERATE_STUBS &&
        Parser.getTok().getKind() == AsmToken::Identifier) {
      std::string GSModName = ModifierName.str() + "_" + GENERATE_STUBS;
      ModifierKind = ABPMCExpr::getKindByName(GSModName);
      if (ModifierKind != ABPMCExpr::VK_ABP_None)
        Parser.Lex(); // Eat gs modifier name
    }
  } else {
    return Error(Parser.getTok().getLoc(), "unknown modifier");
  }

  if (tokens[1].getKind() == AsmToken::Minus ||
      tokens[1].getKind() == AsmToken::Plus) {
    Parser.Lex();
    assert(Parser.getTok().getKind() == AsmToken::LParen);
    Parser.Lex(); // Eat the sign and parenthesis
  }

  MCExpr const *InnerExpression;
  if (getParser().parseExpression(InnerExpression))
    return true;

  if (tokens[1].getKind() == AsmToken::Minus ||
      tokens[1].getKind() == AsmToken::Plus) {
    assert(Parser.getTok().getKind() == AsmToken::RParen);
    Parser.Lex(); // Eat closing parenthesis
  }

  // If we have a modifier wrap the inner expression
  assert(Parser.getTok().getKind() == AsmToken::RParen);
  Parser.Lex(); // Eat closing parenthesis

  MCExpr const *Expression =
      ABPMCExpr::create(ModifierKind, InnerExpression, isNegated, getContext());

  SMLoc E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  Operands.push_back(ABPOperand::CreateImm(Expression, S, E));

  return false;
}

bool ABPAsmParser::parseOperand(OperandVector &Operands) {
  LLVM_DEBUG(dbgs() << "parseOperand\n");

  switch (getLexer().getKind()) {
  default:
    return Error(Parser.getTok().getLoc(), "unexpected token in operand");

  case AsmToken::Identifier:
    // Try to parse a register, if it fails,
    // fall through to the next case.
    if (!tryParseRegisterOperand(Operands)) {
      return false;
    }
    LLVM_FALLTHROUGH;
  case AsmToken::LParen:
  case AsmToken::Integer:
  case AsmToken::Dot:
    return tryParseExpression(Operands);
  case AsmToken::Plus:
  case AsmToken::Minus: {
    // If the sign preceeds a number, parse the number,
    // otherwise treat the sign a an independent token.
    switch (getLexer().peekTok().getKind()) {
    case AsmToken::Integer:
    case AsmToken::BigNum:
    case AsmToken::Identifier:
    case AsmToken::Real:
      if (!tryParseExpression(Operands))
        return false;
      break;
    default:
      break;
    }
    // Treat the token as an independent token.
    Operands.push_back(ABPOperand::CreateToken(Parser.getTok().getString(),
                                               Parser.getTok().getLoc()));
    Parser.Lex(); // Eat the token.
    return false;
  }
  }

  // Could not parse operand
  return true;
}

OperandMatchResultTy ABPAsmParser::parseMemriOperand(OperandVector &Operands) {
  LLVM_DEBUG(dbgs() << "parseMemriOperand()\n");

  SMLoc E, S;
  MCExpr const *Expression;
  int RegNo;

  // Parse register.
  {
    RegNo = parseRegister();

    if (RegNo == ABP::NoRegister)
      return MatchOperand_ParseFail;

    S = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
    Parser.Lex(); // Eat register token.
  }

  // Parse immediate;
  {
    if (getParser().parseExpression(Expression))
      return MatchOperand_ParseFail;

    E = SMLoc::getFromPointer(Parser.getTok().getLoc().getPointer() - 1);
  }

  Operands.push_back(ABPOperand::CreateMemri(RegNo, Expression, S, E));

  return MatchOperand_Success;
}

bool ABPAsmParser::ParseRegister(unsigned &RegNo, SMLoc &StartLoc,
                                 SMLoc &EndLoc) {
  StartLoc = Parser.getTok().getLoc();
  RegNo = parseRegister(/*RestoreOnFailure=*/false);
  EndLoc = Parser.getTok().getLoc();

  return (RegNo == ABP::NoRegister);
}

OperandMatchResultTy ABPAsmParser::tryParseRegister(unsigned &RegNo,
                                                    SMLoc &StartLoc,
                                                    SMLoc &EndLoc) {
  StartLoc = Parser.getTok().getLoc();
  RegNo = parseRegister(/*RestoreOnFailure=*/true);
  EndLoc = Parser.getTok().getLoc();

  if (RegNo == ABP::NoRegister)
    return MatchOperand_NoMatch;
  return MatchOperand_Success;
}

void ABPAsmParser::eatComma() {
  if (getLexer().is(AsmToken::Comma)) {
    Parser.Lex();
  } else {
    // GCC allows commas to be omitted.
  }
}

bool ABPAsmParser::ParseInstruction(ParseInstructionInfo &Info,
                                    StringRef Mnemonic, SMLoc NameLoc,
                                    OperandVector &Operands) {
  Operands.push_back(ABPOperand::CreateToken(Mnemonic, NameLoc));

  bool first = true;
  while (getLexer().isNot(AsmToken::EndOfStatement)) {
    if (!first)
      eatComma();

    first = false;

    auto MatchResult = MatchOperandParserImpl(Operands, Mnemonic);

    if (MatchResult == MatchOperand_Success) {
      continue;
    }

    if (MatchResult == MatchOperand_ParseFail) {
      SMLoc Loc = getLexer().getLoc();
      Parser.eatToEndOfStatement();

      return Error(Loc, "failed to parse register and immediate pair");
    }

    if (parseOperand(Operands)) {
      SMLoc Loc = getLexer().getLoc();
      Parser.eatToEndOfStatement();
      return Error(Loc, "unexpected token in argument list");
    }
  }
  Parser.Lex(); // Consume the EndOfStatement
  return false;
}

bool ABPAsmParser::ParseDirective(llvm::AsmToken DirectiveID) {
  StringRef IDVal = DirectiveID.getIdentifier();
  if (IDVal.lower() == ".long") {
    parseLiteralValues(SIZE_LONG, DirectiveID.getLoc());
  } else if (IDVal.lower() == ".word" || IDVal.lower() == ".short") {
    parseLiteralValues(SIZE_WORD, DirectiveID.getLoc());
  } else if (IDVal.lower() == ".byte") {
    parseLiteralValues(1, DirectiveID.getLoc());
  }
  return true;
}

bool ABPAsmParser::parseLiteralValues(unsigned SizeInBytes, SMLoc L) {
  MCAsmParser &Parser = getParser();
  ABPMCELFStreamer &ABPStreamer =
      static_cast<ABPMCELFStreamer &>(Parser.getStreamer());
  AsmToken Tokens[2];
  size_t ReadCount = Parser.getLexer().peekTokens(Tokens);
  if (ReadCount == 2 && Parser.getTok().getKind() == AsmToken::Identifier &&
      Tokens[0].getKind() == AsmToken::Minus &&
      Tokens[1].getKind() == AsmToken::Identifier) {
    MCSymbol *Symbol = getContext().getOrCreateSymbol(".text");
    ABPStreamer.emitValueForModiferKind(Symbol, SizeInBytes, L,
                                        ABPMCExpr::VK_ABP_None);
    return false;
  }

  if (Parser.getTok().getKind() == AsmToken::Identifier &&
      Parser.getLexer().peekTok().getKind() == AsmToken::LParen) {
    StringRef ModifierName = Parser.getTok().getString();
    ABPMCExpr::VariantKind ModifierKind =
        ABPMCExpr::getKindByName(ModifierName);
    if (ModifierKind != ABPMCExpr::VK_ABP_None) {
      Parser.Lex();
      Parser.Lex(); // Eat the modifier and parenthesis
    } else {
      return Error(Parser.getTok().getLoc(), "unknown modifier");
    }
    MCSymbol *Symbol =
        getContext().getOrCreateSymbol(Parser.getTok().getString());
    ABPStreamer.emitValueForModiferKind(Symbol, SizeInBytes, L, ModifierKind);
    return false;
  }

  auto parseOne = [&]() -> bool {
    const MCExpr *Value;
    if (Parser.parseExpression(Value))
      return true;
    Parser.getStreamer().emitValue(Value, SizeInBytes, L);
    return false;
  };
  return (parseMany(parseOne));
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeABPAsmParser() {
  RegisterMCAsmParser<ABPAsmParser> X(getTheABPTarget());
}

#define GET_REGISTER_MATCHER
#define GET_MATCHER_IMPLEMENTATION
#include "ABPGenAsmMatcher.inc"

// Uses enums defined in ABPGenAsmMatcher.inc
unsigned ABPAsmParser::validateTargetOperandClass(MCParsedAsmOperand &AsmOp,
                                                  unsigned ExpectedKind) {
  ABPOperand &Op = static_cast<ABPOperand &>(AsmOp);
  MatchClassKind Expected = static_cast<MatchClassKind>(ExpectedKind);

  // If need be, GCC converts bare numbers to register names
  // It's ugly, but GCC supports it.
  if (Op.isImm()) {
    if (MCConstantExpr const *Const = dyn_cast<MCConstantExpr>(Op.getImm())) {
      int64_t RegNum = Const->getValue();
      std::ostringstream RegName;
      RegName << "r" << RegNum;
      RegNum = MatchRegisterName(RegName.str());
      if (RegNum != ABP::NoRegister) {
        Op.makeReg(RegNum);
        if (validateOperandClass(Op, Expected) == Match_Success) {
          return Match_Success;
        }
      }
      // Let the other quirks try their magic.
    }
  }

  if (Op.isReg()) {
    // If the instruction uses a register pair but we got a single, lower
    // register we perform a "class cast".
    if (isSubclass(Expected, MCK_DREGS)) {
      unsigned correspondingDREG = Op.getReg();

      if (correspondingDREG != ABP::NoRegister) {
        Op.makeReg(correspondingDREG);
        return validateOperandClass(Op, Expected);
      }
    }
  }
  return Match_InvalidOperand;
}
