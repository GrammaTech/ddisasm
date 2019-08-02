# ===== generated souffle code =====
find_program(SOUFFLE souffle
  HINTS $ENV{PATH}
  DOC "souffle must be in your PATH to build disassembler.")
if(NOT SOUFFLE)
  message(FATAL_ERROR "souffle was not found in your PATH. Unable to build.")
endif()


set(DATALOG_SOURCES
    datalog/code_inference.dl
    datalog/code_inference_postprocess.dl
    datalog/cfg.dl
    datalog/data_access_analysis.dl
    datalog/empty_range.dl
    datalog/elf_binaries.dl
    datalog/exceptions.dl
    datalog/float_operations.dl
    datalog/function_inference.dl
    datalog/intra_procedural_cfg_completeness.dl
    datalog/intra_procedural_SCC.dl
    datalog/jump_operations.dl
    datalog/main.dl
    datalog/no_return_analysis.dl
    datalog/ordered_set.dl
    datalog/pe_binaries.dl
    datalog/pointer_reatribution.dl
    datalog/printable_chars.dl
    datalog/relative_jump_tables.dl
    datalog/symbolization.dl
    datalog/use_def_analysis.dl
    datalog/value_analysis.dl
    datalog/debug_stats.dl
    datalog/self_diagnose.dl)

if(NOT CORES)
  set(CORES "auto")
endif()

set(GENERATED_CPP "${CMAKE_BINARY_DIR}/src/souffle_disasm.cpp")
add_custom_command(OUTPUT ${GENERATED_CPP}
  # Souffle incldes the path of the output file in the generated
  # program name. Change directory and use a relative path so the name
  # does not depend on build location.
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/src/"
  COMMAND ${SOUFFLE} ${CMAKE_CURRENT_SOURCE_DIR}/datalog/main.dl -g souffle_disasm.cpp -j${CORES}
  DEPENDS ${DATALOG_SOURCES})

# determine what flags to use to specify -fopenmp.
if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  set(OPENMP_FLAGS -fopenmp)
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL Clang)
  set(OPENMP_FLAGS -fopenmp=libgomp)
endif()

# ===== souffle_disasm =====
# First build a static library of all the non-generated code.. This is
# just a hack to get CMake to use different compile flags (because the
# generated souffle code won't build with -Wall -Werror).
add_library(disasm_main STATIC
  disasm_main.cpp
  Dl_decoder.cpp
  Dl_operator.cpp
  Dl_instruction.cpp
  Dl_operator_table.cpp
  Elf_reader.cpp
  ExceptionDecoder.cpp
  LIEFBinaryReader.cpp)

target_compile_definitions(disasm_main PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(disasm_main PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(disasm_main PRIVATE -Wall -Wextra -Wpointer-arith)
target_compile_options(disasm_main PRIVATE -Werror)
target_compile_options(disasm_main PRIVATE ${OPENMP_FLAGS})
target_compile_options(disasm_main PRIVATE -O3)

if( ${GTIRB_USE_SYSTEM_BOOST} MATCHES "OFF" )
  add_dependencies(disasm_main Boost)
endif()

# ============ Detect how to use <experimental/filesystem> ============================
include(CheckCXXSourceCompiles)

set(EXPERIMENTAL_LIB "" CACHE STRING "The library to link with in order to use <experimental/filesystem>.")

if (NOT EXPERIMENTAL_LIB)
  set(EXFS_CODE "
  #include <experimental/filesystem>
  int main() {
    std::experimental::filesystem::path p{\"an/example/path\"};
    return std::experimental::filesystem::exists(p);
  }
  ")

  check_cxx_source_compiles("${EXFS_CODE}" EXFS_LINK_NONE)

  if(NOT EXFS_LINK_NONE)
    foreach(EXFS_LIB stdc++fs c++experimental c++fs)
      set(OLD_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
      list(APPEND CMAKE_REQUIRED_LIBRARIES ${EXFS_LIB})
      check_cxx_source_compiles("${EXFS_CODE}" EXFS_LINK_${EXFS_LIB}_OK)
      set(CMAKE_REQUIRED_LIBRARIES ${OLD_CMAKE_REQUIRED_LIBRARIES})

      if(EXFS_LINK_${EXFS_LIB}_OK)
        if(EXPERIMENTAL_LIB)
          message(FATAL_ERROR "multiple candidates for library to link for <experimental/filesystem>: ${EXPERIMENTAL_LIB} and ${EXFS_LIB}. Try giving the correct one explicitly with -DEXPERIMENTAL_LIB.")
        endif()
        set(EXPERIMENTAL_LIB ${EXFS_LIB})
      endif()
    endforeach()

    if (NOT EXPERIMENTAL_LIB)
      message(FATAL_ERROR "could not find library to link for <experimental/filesystem>. Try giving it explicitly with -DEXPERIMENTAL_LIB.")
    endif()
  endif()
endif()

target_include_directories(disasm_main
  PUBLIC
  ${LIEF_INCLUDE_DIRS}
)

target_link_libraries(disasm_main
  gtirb
  gtirb_pprinter
  ehp
  ${CAPSTONE}
  ${Boost_LIBRARIES}
  ${EXPERIMENTAL_LIB}
  ${LIBCPP_ABI}
  ${LIEF_LIBRARIES}
)

# Now combine the static library and generated code into an
# executable.
add_executable(ddisasm
  ${GENERATED_CPP})
target_link_libraries(ddisasm disasm_main)
target_compile_definitions(ddisasm PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(ddisasm PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(ddisasm PRIVATE ${OPENMP_FLAGS})
target_compile_options(ddisasm PRIVATE -O3)
target_compile_options(ddisasm PRIVATE -Wno-parentheses-equality)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  target_link_libraries(ddisasm gomp)
endif()

install(TARGETS ddisasm DESTINATION bin)

if(NOT BUILD_SHARED_LIBS)
  target_link_libraries(ddisasm -static-libstdc++)
endif()
