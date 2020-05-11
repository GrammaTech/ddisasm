# ============ Scc pass =================

add_library(scc_pass STATIC SccPass.cpp)

target_link_libraries(scc_pass gtirb)

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

if(WIN32)
  set(NO_RETURN_DATALOG_MAIN
      "$$(wslpath ${CMAKE_CURRENT_SOURCE_DIR}/datalog/no_return_analysis.dl)")
else()
  set(NO_RETURN_DATALOG_MAIN
      ${CMAKE_CURRENT_SOURCE_DIR}/datalog/no_return_analysis.dl)
endif()

set(NO_RETURN_CPP "${CMAKE_BINARY_DIR}/src/passes/souffle_no_return.cpp")

add_custom_command(
  OUTPUT ${NO_RETURN_CPP}
         # Souffle includes the path of the output file in the generated program
         # name. Change directory and use a relative path so the name does not
         # depend on build location.
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/src/passes"
  COMMAND ${SOUFFLE} ${NO_RETURN_DATALOG_MAIN} -g souffle_no_return.cpp -jauto
  DEPENDS ${NO_RETURN_DATALOG_SOURCES})

add_library(no_return_pass STATIC NoReturnPass.cpp ${NO_RETURN_CPP})

target_link_libraries(no_return_pass gtirb datalog_utils)

target_compile_definitions(no_return_pass PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(no_return_pass PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(no_return_pass PRIVATE ${OPENMP_FLAGS})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  set_common_msvc_options(no_return_pass)

  set_souffle_msvc_options(no_return_pass)
else()
  target_compile_options(no_return_pass PRIVATE -O3)
endif()

# ============ Function inference pass =========

if(WIN32)
  set(FUNCTION_INFERENCE_DATALOG_MAIN
      "$$(wslpath ${CMAKE_CURRENT_SOURCE_DIR}/datalog/function_inference.dl)")
else()
  set(FUNCTION_INFERENCE_DATALOG_MAIN
      ${CMAKE_CURRENT_SOURCE_DIR}/datalog/function_inference.dl)
endif()

set(FUNCTION_INFERENCE_DATALOG_SOURCES datalog/function_inference.dl)

set(FUNCTION_INFERENCE_CPP
    "${CMAKE_BINARY_DIR}/src/passes/souffle_function_inference.cpp")

add_custom_command(
  OUTPUT ${FUNCTION_INFERENCE_CPP}
         # Souffle includes the path of the output file in the generated program
         # name. Change directory and use a relative path so the name does not
         # depend on build location.
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/src/passes"
  COMMAND ${SOUFFLE} ${FUNCTION_INFERENCE_DATALOG_MAIN} -g
          souffle_function_inference.cpp -jauto
  DEPENDS ${FUNCTION_INFERENCE_DATALOG_SOURCES})

add_library(function_inference_pass STATIC FunctionInferencePass.cpp
                                           ${FUNCTION_INFERENCE_CPP})

target_link_libraries(function_inference_pass gtirb datalog_utils)

target_compile_definitions(function_inference_pass PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(function_inference_pass PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(function_inference_pass PRIVATE ${OPENMP_FLAGS})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  set_common_msvc_options(function_inference_pass)

  set_souffle_msvc_options(function_inference_pass)
else()
  target_compile_options(function_inference_pass PRIVATE -O3)
endif()
