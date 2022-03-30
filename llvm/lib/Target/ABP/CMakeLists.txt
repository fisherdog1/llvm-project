add_llvm_component_group(ABP)

set(LLVM_TARGET_DEFINITIONS ABP.td)

add_llvm_target(ABPCodeGen
  ABPAsmPrinter.cpp
  AVRExpandPseudoInsts.cpp
  AVRFrameLowering.cpp
  AVRInstrInfo.cpp
  AVRISelDAGToDAG.cpp
  AVRISelLowering.cpp
  AVRMCInstLower.cpp
  AVRRelaxMemOperations.cpp
  AVRRegisterInfo.cpp
  AVRShiftExpand.cpp
  AVRSubtarget.cpp
  AVRTargetMachine.cpp
  AVRTargetObjectFile.cpp

  DEPENDS
  intrinsics_gen

  LINK_COMPONENTS
  AsmPrinter
  CodeGen
  Core
  MC
  AVRDesc
  AVRInfo
  SelectionDAG
  Support
  Target

  ADD_TO_COMPONENT
  ABP
)

add_subdirectory(AsmParser)
add_subdirectory(MCTargetDesc)
add_subdirectory(TargetInfo)
