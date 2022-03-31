add_llvm_component_group(ABP)

set(LLVM_TARGET_DEFINITIONS ABP.td)

tablegen(LLVM ABPGenAsmMatcher.inc -gen-asm-matcher)
tablegen(LLVM ABPGenRegisterInfo.inc -gen-register-info)
tablegen(LLVM ABPGenInstrInfo.inc -gen-instr-info)


add_public_tablegen_target(ABPCommonTableGen)

add_llvm_target(ABPCodeGen
  DEPENDS
  intrinsics_gen

  LINK_COMPONENTS
  AsmPrinter
  CodeGen
  Core
  MC
  ABPDesc
  ABPInfo
  # SelectionDAG
  Support
  Target

  ADD_TO_COMPONENT
  ABP
)

add_subdirectory(TargetInfo)

# MC not ported yet
# add_subdirectory(MCTargetDesc)

add_subdirectory(AsmParser)
