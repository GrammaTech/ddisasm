add_library(
  gtirb_decoder STATIC
  DatalogLoader.cpp
  DatalogProgram.cpp
  DatalogUtils.cpp
  ExceptionDecoder.cpp
  X64Decoder.cpp
  Arm64Decoder.cpp
  ElfLoader.cpp)

target_link_libraries(gtirb_decoder gtirb ${CAPSTONE} ${ehp_LIBRARIES})

target_compile_definitions(gtirb_decoder PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(gtirb_decoder PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(gtirb_decoder PRIVATE ${OPENMP_FLAGS})

if(ehp_INCLUDE_DIR)
  target_include_directories(gtirb_decoder PRIVATE ${ehp_INCLUDE_DIR})
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_compile_definitions(gtirb_decoder PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(gtirb_decoder PRIVATE _CRT_NONSTDC_NO_WARNINGS)

  set_common_msvc_options(gtirb_decoder)
endif()
