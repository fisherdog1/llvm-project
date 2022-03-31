add_llvm_component_library(LLVMABPAsmParser
  ABPAsmParser.cpp

  LINK_COMPONENTS
  MC
  MCParser
  ABPDesc
  ABPInfo
  Support

  ADD_TO_COMPONENT
  ABP
)

# this wasn't here in AVR
add_dependencies(LLVMABPAsmParser ABPCommonTableGen)