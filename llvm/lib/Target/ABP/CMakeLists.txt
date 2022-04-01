add_llvm_component_group(ABP)

set(LLVM_TARGET_DEFINITIONS ABP.td)

tablegen(LLVM ABPGenAsmMatcher.inc -gen-asm-matcher)
tablegen(LLVM ABPGenAsmWriter.inc -gen-asm-writer)
tablegen(LLVM ABPGenCallingConv.inc -gen-callingconv)
tablegen(LLVM ABPGenDAGISel.inc -gen-dag-isel)
tablegen(LLVM ABPGenDisassemblerTables.inc -gen-disassembler)
tablegen(LLVM ABPGenInstrInfo.inc -gen-instr-info)
tablegen(LLVM ABPGenMCCodeEmitter.inc -gen-emitter)
tablegen(LLVM ABPGenRegisterInfo.inc -gen-register-info)
tablegen(LLVM ABPGenSubtargetInfo.inc -gen-subtarget)


add_public_tablegen_target(ABPCommonTableGen)

add_llvm_target(ABPCodeGen
  ABPRegisterInfo.cpp

  DEPENDS
  intrinsics_gen

  LINK_COMPONENTS
  AsmPrinter
  CodeGen
  Core
  MC
  ABPDesc
  ABPInfo
  SelectionDAG
  Support
  Target

  ADD_TO_COMPONENT
  ABP
)

add_subdirectory(TargetInfo)

# MC not ported yet
add_subdirectory(MCTargetDesc)
add_subdirectory(AsmParser)
