# ============ Generic pass library =================

add_library(generic_pass STATIC AnalysisPass.cpp DatalogAnalysisPass.cpp
                                Interpreter.cpp)

target_link_libraries(generic_pass gtirb gtirb_pprinter gtirb_decoder)

if(SOUFFLE_INCLUDE_DIR)
  target_include_directories(generic_pass SYSTEM PRIVATE ${SOUFFLE_INCLUDE_DIR})
endif()

target_compile_definitions(generic_pass PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(generic_pass PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(generic_pass PRIVATE ${OPENMP_FLAGS})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  set_common_msvc_options(generic_pass)
endif()

# ============ Disassembly pass =================

add_library(disassembly_pass STATIC DisassemblyPass.cpp Disassembler.cpp)

if(SOUFFLE_INCLUDE_DIR)
  target_include_directories(disassembly_pass SYSTEM
                             PRIVATE ${SOUFFLE_INCLUDE_DIR})
endif()

target_link_libraries(disassembly_pass gtirb gtirb_pprinter)

target_compile_definitions(disassembly_pass PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(disassembly_pass PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(disassembly_pass PRIVATE ${OPENMP_FLAGS})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  set_common_msvc_options(disassembly_pass)
endif()

# ============ Scc pass =================

add_library(scc_pass STATIC SccPass.cpp)

target_link_libraries(scc_pass gtirb gtirb_pprinter)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  set_common_msvc_options(scc_pass)

  # The following warning is coming from the bgl, but only in release mode
  if(("${CMAKE_BUILD_TYPE}" STREQUAL "Release") OR ("${CMAKE_BUILD_TYPE}"
                                                    STREQUAL "RelWithDebInfo"))
    target_compile_options(
      scc_pass PRIVATE -wd4172) # returning address of local variable or
                                # temporary
  endif()
endif()

# ============ No return pass =================

set(NO_RETURN_DATALOG_SOURCES datalog/no_return_analysis.dl)
set(NO_RETURN_DATALOG_MAIN
    ${CMAKE_CURRENT_SOURCE_DIR}/datalog/no_return_analysis.dl)

set(NO_RETURN_CPP "${CMAKE_BINARY_DIR}/src/passes/souffle_no_return.cpp")

add_custom_command(
  OUTPUT ${NO_RETURN_CPP}
         # Souffle includes the path of the output file in the generated program
         # name. Change directory and use a relative path so the name does not
         # depend on build location.
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/src/passes"
  COMMAND
    ${SOUFFLE} ${NO_RETURN_DATALOG_MAIN} -g souffle_no_return.cpp -N
    souffle_no_return -jauto ${SOUFFLE_PREPROCESSOR_ARG}
  DEPENDS ${NO_RETURN_DATALOG_SOURCES})

add_library(no_return_pass STATIC NoReturnPass.cpp ${NO_RETURN_CPP})

if(SOUFFLE_INCLUDE_DIR)
  target_include_directories(no_return_pass SYSTEM
                             PRIVATE ${SOUFFLE_INCLUDE_DIR})
endif()

target_link_libraries(no_return_pass gtirb gtirb_pprinter gtirb_decoder)

target_compile_definitions(no_return_pass PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(no_return_pass PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(no_return_pass PRIVATE ${OPENMP_FLAGS})
if(SOUFFLE_INCLUDE_DIR)
  target_include_directories(no_return_pass SYSTEM
                             PRIVATE ${SOUFFLE_INCLUDE_DIR})
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  set_common_msvc_options(no_return_pass)

  set_souffle_msvc_options(no_return_pass)
else()
  target_compile_options(no_return_pass PRIVATE -O3)
endif()

# ============ Function inference pass =========

set(FUNCTION_INFERENCE_DATALOG_MAIN
    ${CMAKE_CURRENT_SOURCE_DIR}/datalog/function_inference.dl)
set(FUNCTION_INFERENCE_DATALOG_SOURCES datalog/function_inference.dl)
set(FUNCTION_INFERENCE_CPP
    "${CMAKE_BINARY_DIR}/src/passes/souffle_function_inference.cpp")

add_custom_command(
  OUTPUT ${FUNCTION_INFERENCE_CPP}
         # Souffle includes the path of the output file in the generated program
         # name. Change directory and use a relative path so the name does not
         # depend on build location.
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/src/passes"
  COMMAND
    ${SOUFFLE} ${FUNCTION_INFERENCE_DATALOG_MAIN} -g
    souffle_function_inference.cpp -N souffle_function_inference -jauto
    ${SOUFFLE_PREPROCESSOR_ARG}
  DEPENDS ${FUNCTION_INFERENCE_DATALOG_SOURCES})

add_library(function_inference_pass STATIC FunctionInferencePass.cpp
                                           ${FUNCTION_INFERENCE_CPP})

if(SOUFFLE_INCLUDE_DIR)
  target_include_directories(function_inference_pass SYSTEM
                             PRIVATE ${SOUFFLE_INCLUDE_DIR})
endif()

target_link_libraries(function_inference_pass gtirb gtirb_pprinter
                      gtirb_decoder)

target_compile_definitions(function_inference_pass PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(function_inference_pass PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(function_inference_pass PRIVATE ${OPENMP_FLAGS})
if(CAPSTONE_INCLUDE_DIR)
  target_include_directories(function_inference_pass
                             PRIVATE ${CAPSTONE_INCLUDE_DIR})
endif()
if(SOUFFLE_INCLUDE_DIR)
  target_include_directories(function_inference_pass SYSTEM
                             PRIVATE ${SOUFFLE_INCLUDE_DIR})
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  set_common_msvc_options(function_inference_pass)

  set_souffle_msvc_options(function_inference_pass)
else()
  target_compile_options(function_inference_pass PRIVATE -O3)
endif()
