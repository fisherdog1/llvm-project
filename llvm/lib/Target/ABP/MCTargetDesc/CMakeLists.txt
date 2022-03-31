add_llvm_component_library(LLVMABPDesc
  ABPMCTargetDesc.cpp
  ABPMCELFStreamer.cpp
  ABPMCExpr.cpp

  LINK_COMPONENTS
  MC
  ABPInfo
  Support

  ADD_TO_COMPONENT
  ABP
)

add_dependencies(LLVMABPDesc ABPCommonTableGen)

