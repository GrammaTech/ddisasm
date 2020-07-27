# ##############################################################################
# Datalog Utils
# ##############################################################################

add_library(datalog_utils STATIC DatalogUtils.cpp DlOperandTable.cpp)

target_link_libraries(datalog_utils gtirb proto ${CAPSTONE})

target_compile_definitions(datalog_utils PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(datalog_utils PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(datalog_utils PRIVATE ${OPENMP_FLAGS})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_compile_definitions(datalog_utils PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(datalog_utils PRIVATE _CRT_NONSTDC_NO_WARNINGS)

  set_common_msvc_options(datalog_utils)
  set_souffle_msvc_options(datalog_utils)
else()
  target_compile_options(datalog_utils PRIVATE -O3)
endif()

# ##############################################################################
# GTIRB Decoder
# ##############################################################################

add_library(gtirb_decoder STATIC DlDecoder.cpp
  ExceptionDecoder.cpp DatalogLoader.cpp DatalogProgram.cpp
  ElfLoader.cpp X64Decoder.cpp)

target_link_libraries(gtirb_decoder datalog_utils gtirb ${ehp_LIBRARIES})

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
