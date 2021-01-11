# ===== generated souffle code =====
# On windows, wsl is used to call souffle.  There is no good way to 'find'
# souffle in wsl, so we skip this step entirely and will hard-code the call.
if(NOT WIN32)
  find_program(
    SOUFFLE souffle
    HINTS $ENV{PATH}
    DOC "souffle must be in your PATH to build disassembler.")
  if(NOT SOUFFLE)
    message(FATAL_ERROR "souffle was not found in your PATH. Unable to build.")
  endif()
  if(NOT SOUFFLE_INCLUDE_DIR)
    get_filename_component(SOUFFLE_BIN_DIR ${SOUFFLE} DIRECTORY)
    get_filename_component(SOUFFLE_INCLUDE_DIR ${SOUFFLE_BIN_DIR}/../include
                           ABSOLUTE)
    if(NOT EXISTS ${SOUFFLE_INCLUDE_DIR}/souffle)
      message(WARNING "SOUFFLE_INCLUDE_DIR not found")
      unset(SOUFFLE_INCLUDE_DIR)
    endif()
    unset(SOUFFLE_BIN_DIR)
  endif()
else()
  set(SOUFFLE wsl souffle)
endif()

set(DATALOG_BASE_SOURCES
    datalog/bitmasks.dl
    datalog/code_inference.dl
    datalog/code_inference_postprocess.dl
    datalog/cfg.dl
    datalog/data_access_analysis.dl
    datalog/empty_range.dl
    datalog/elf_binaries.dl
    datalog/exceptions.dl
    datalog/basic_function_inference.dl
    datalog/main.dl
    datalog/pointer_reatribution.dl
    datalog/printable_chars.dl
    datalog/register_type_analysis.dl
    datalog/relative_jump_tables.dl
    datalog/symbolization.dl
    datalog/use_def_analysis.dl
    datalog/value_analysis.dl
    datalog/debug_stats.dl
    datalog/self_diagnose.dl)

set(DATALOG_X86_32_SOURCES
    datalog/intel/arch_x86_32.dl datalog/intel/float_operations.dl
    datalog/intel/jump_operations.dl datalog/intel/registers_x86_32.dl)

set(DATALOG_X86_64_SOURCES
    datalog/intel/arch_x86_64.dl datalog/intel/float_operations.dl
    datalog/intel/jump_operations.dl datalog/intel/registers_x86_64.dl)

set(DATALOG_ARM64_SOURCES
    datalog/arm64/arch_arm64.dl datalog/arm64/float_operations.dl
    datalog/arm64/jump_operations.dl datalog/arm64/registers.dl)

set(SOUFFLE_DATALOG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/datalog/)

set(GENERATED_X86_32_CPP souffle_disasm_x86_32.cpp)
if(WIN32)
  set(GENERATED_X86_32_CPP_PATH
      "$$(wslpath ${CMAKE_BINARY_DIR}/src/souffle_disasm_x86_32.cpp)")
else()
  set(GENERATED_X86_32_CPP_PATH
      "${CMAKE_BINARY_DIR}/src/souffle_disasm_x86_32.cpp")
endif()

add_custom_command(
  OUTPUT ${GENERATED_X86_32_CPP}
         # Souffle includes the path of the output file in the generated program
         # name. Change directory and use a relative path so the name does not
         # depend on build location.
  WORKING_DIRECTORY "${SOUFFLE_DATALOG_DIR}"
  COMMAND ${SOUFFLE} main.dl -g ${GENERATED_X86_32_CPP_PATH} -jauto -MARCH_IA32
  DEPENDS ${DATALOG_BASE_SOURCES} ${DATALOG_X86_32_SOURCES})

set(GENERATED_X86_64_CPP souffle_disasm_x86_64.cpp)
if(WIN32)
  set(GENERATED_X86_64_CPP_PATH
      "$$(wslpath ${CMAKE_BINARY_DIR}/src/souffle_disasm_x86_64.cpp)")
else()
  set(GENERATED_X86_64_CPP_PATH
      "${CMAKE_BINARY_DIR}/src/souffle_disasm_x86_64.cpp")
endif()

add_custom_command(
  OUTPUT ${GENERATED_X86_64_CPP}
         # Souffle includes the path of the output file in the generated program
         # name. Change directory and use a relative path so the name does not
         # depend on build location.
  WORKING_DIRECTORY "${SOUFFLE_DATALOG_DIR}"
  COMMAND ${SOUFFLE} main.dl -g ${GENERATED_X86_64_CPP_PATH} -jauto -MARCH_AMD64
  DEPENDS ${DATALOG_BASE_SOURCES} ${DATALOG_X86_64_SOURCES})

set(GENERATED_ARM64_CPP souffle_disasm_arm64.cpp)
if(WIN32)
  set(GENERATED_ARM64_CPP_PATH
      "$$(wslpath ${CMAKE_BINARY_DIR}/src/souffle_disasm_arm64.cpp)")
else()
  set(GENERATED_ARM64_CPP_PATH
      "${CMAKE_BINARY_DIR}/src/souffle_disasm_arm64.cpp")
endif()

add_custom_command(
  OUTPUT ${GENERATED_ARM64_CPP}
         # Souffle includes the path of the output file in the generated program
         # name. Change directory and use a relative path so the name does not
         # depend on build location.
  WORKING_DIRECTORY "${SOUFFLE_DATALOG_DIR}"
  COMMAND ${SOUFFLE} main.dl -g ${GENERATED_ARM64_CPP_PATH} -jauto -MARCH_ARM64
  DEPENDS ${DATALOG_BASE_SOURCES} ${DATALOG_ARM64_SOURCES})

# determine what flags to use to specify -fopenmp.
if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  set(OPENMP_FLAGS -fopenmp)
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL Clang)
  set(OPENMP_FLAGS -fopenmp=libgomp)
endif()

# Common settings for MSVC
function(set_common_msvc_options TARGET_NAME)

  target_compile_options(${TARGET_NAME} PRIVATE "-W4") # Sets warning level.

  # FIXME: Visual studio does not deactivate warnings so for now warnings do not
  # result in errors. target_compile_options(${TARGET_NAME} PRIVATE "-WX")

  # target_compile_options( ${TARGET_NAME} PRIVATE "-wd4127") # conditional
  # expression is constant

  # target_compile_options( ${TARGET_NAME} PRIVATE "-wd4244") # 'conversion'
  # conversion from 'type1' to 'type2', possible loss of data

  target_compile_options(${TARGET_NAME} PRIVATE "-permissive-")
  target_compile_options(${TARGET_NAME} PRIVATE "-EHsc")
  target_compile_options(${TARGET_NAME} PRIVATE "-bigobj")

  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Debug>:-D_DEBUG>)
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Debug>:-MDd>)
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Debug>:-Ob0>
  )# Disables inline expansion
  target_compile_options(
    ${TARGET_NAME} PRIVATE $<$<CONFIG:Debug>:-Od>) # Disables optimization,
                                                   # speeding compilation and
                                                   # simplifying debugging. http
                                                   # s://msdn.microsoft.com/en-
                                                   # us/library/k1ack8f1.aspx
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Debug>:-RTC1>
  )# Enables run-time error checking.
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Debug>:-Zi>
  )# Generates complete debugging information.

  target_compile_options(${TARGET_NAME}
                         PRIVATE $<$<CONFIG:RelWithDebInfo>:-D_NDEBUG>)
  target_compile_options(${TARGET_NAME}
                         PRIVATE $<$<CONFIG:RelWithDebInfo>:-DNDEBUG>)
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:RelWithDebInfo>:-MD>)
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:RelWithDebInfo>:-O2>
  )# Creates fast code.
  target_compile_options(
    ${TARGET_NAME} PRIVATE $<$<CONFIG:RelWithDebInfo>:-Ob2>) # The default
                                                             # value. Allows
                                                             # expansion of
                                                             # functions marked
                                                             # as inline,
                                                             # __inline, or
                                                             # __forceinline,
                                                             # and any other
                                                             # function that the
                                                             # compiler chooses.
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:RelWithDebInfo>:-Oi>
  )# Generates intrinsic functions.
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:RelWithDebInfo>:-Ot>
  )# Favors fast code.
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:RelWithDebInfo>:-Zi>
  )# Generates complete debugging information.

  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Release>:-D_NDEBUG>)
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Release>:-DNDEBUG>)
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Release>:-MD>)
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Release>:-O2>
  )# Creates fast code.
  target_compile_options(
    ${TARGET_NAME} PRIVATE $<$<CONFIG:Release>:-Ob2>) # The default value.
                                                      # Allows expansion of
                                                      # functions marked as
                                                      # inline, __inline, or
                                                      # __forceinline, and any
                                                      # other function that the
                                                      # compiler chooses.
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Release>:-Oi>
  )# Generates intrinsic functions.
  target_compile_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Release>:-Ot>
  )# Favors fast code.

endfunction()

# Disabled warnings for souffle projects on MSVC
function(set_souffle_msvc_options TARGET_NAME)
  target_compile_definitions(${TARGET_NAME} PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(${TARGET_NAME} PRIVATE _CRT_NONSTDC_NO_WARNINGS)

  # From cpp generated by souffle:
  target_compile_options(
    ${TARGET_NAME} PRIVATE -wd4146) # unary minus operator applied to unsigned
                                    # type, result still unsigned
  target_compile_options(
    ${TARGET_NAME} PRIVATE -wd4189) # 'identifier' : local variable is
                                    # initialized but not referenced

  # From souffle headers
  target_compile_options(
    ${TARGET_NAME} PRIVATE -wd4267) # conversion from 'type1' to 'type2',
                                    # possible loss of data

  target_compile_options(
    ${TARGET_NAME} PRIVATE -wd4456) # declaration of 'decl' hides previous local
                                    # declaration
endfunction()

# ====== builder ===========

add_subdirectory(gtirb-builder)

# ====== decoder ===========

add_subdirectory(gtirb-decoder)

# ====== passes ============

add_subdirectory(passes)

# ===== souffle_disasm =====
# First build a static library of all the non-generated code.. This is just a
# hack to get CMake to use different compile flags (because the generated
# souffle code won't build with -Wall -Werror).
add_library(disasm_main STATIC Disassembler.cpp Registration.cpp Main.cpp)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  target_compile_options(disasm_main PRIVATE -Wno-unused-parameter)
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Version.h.in"
               "${CMAKE_BINARY_DIR}/include/Version.h" @ONLY)
target_include_directories(
  disasm_main PRIVATE $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)
if(ehp_INCLUDE_DIR)
  target_include_directories(disasm_main PRIVATE ${ehp_INCLUDE_DIR})
endif()
if(CAPSTONE_INCLUDE_DIR)
  target_include_directories(disasm_main PRIVATE ${CAPSTONE_INCLUDE_DIR})
endif()
if(SOUFFLE_INCLUDE_DIR)
  target_include_directories(disasm_main PRIVATE ${SOUFFLE_INCLUDE_DIR})
endif()

target_compile_definitions(disasm_main PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(disasm_main PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(disasm_main PRIVATE ${OPENMP_FLAGS})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_compile_definitions(disasm_main PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(disasm_main PRIVATE _CRT_NONSTDC_NO_WARNINGS)

  set_msvc_lief_options(disasm_main)
  set_common_msvc_options(disasm_main)
else()
  target_compile_options(disasm_main PRIVATE -O3)
  target_compile_options(disasm_main PRIVATE -Wall)
  target_compile_options(disasm_main PRIVATE -Wextra -Wpointer-arith)
  target_compile_options(disasm_main PRIVATE -Werror)
endif()

if(${GTIRB_USE_SYSTEM_BOOST} MATCHES "OFF")
  add_dependencies(disasm_main Boost)
endif()

target_link_libraries(
  disasm_main
  gtirb
  gtirb_pprinter
  gtirb_builder
  gtirb_decoder
  ${Boost_LIBRARIES}
  ${EXPERIMENTAL_LIB}
  ${LIBCPP_ABI})

# Now combine the static library and generated code into an executable.
add_executable(ddisasm ${GENERATED_X86_32_CPP} ${GENERATED_X86_64_CPP}
                       ${GENERATED_ARM64_CPP})

if(DDISASM_STATIC_DRIVERS)
  if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    # We do not want to statically link in the STL here, as MSVC is a bit
    # prickly about STL ABIs.
  else()
    target_link_libraries(ddisasm PRIVATE -static-libstdc++ -static-libgcc)
  endif()
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_link_libraries(ddisasm disasm_main scc_pass no_return_pass
                        function_inference_pass)
  target_link_options(
    ddisasm PRIVATE /WHOLEARCHIVE:no_return_pass$<$<CONFIG:Debug>:d>
    /WHOLEARCHIVE:function_inference_pass$<$<CONFIG:Debug>:d>)
else()
  target_link_libraries(
    ddisasm PRIVATE disasm_main scc_pass -Wl,--whole-archive no_return_pass
                    function_inference_pass -Wl,--no-whole-archive)
endif()

target_compile_definitions(ddisasm PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(ddisasm PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(ddisasm PRIVATE ${OPENMP_FLAGS})
if(SOUFFLE_INCLUDE_DIR)
  target_include_directories(ddisasm PRIVATE ${SOUFFLE_INCLUDE_DIR})
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_link_options(ddisasm PRIVATE -NODEFAULTLIB:LIBCMTD)

  set_common_msvc_options(ddisasm)

  set_souffle_msvc_options(ddisasm)
else()
  target_compile_options(ddisasm PRIVATE -O3)
  target_compile_options(ddisasm PRIVATE -Wno-parentheses-equality
                                         -Wno-unused-parameter)
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  if(DDISASM_STATIC_DRIVERS)
    target_link_libraries(ddisasm PRIVATE -l:libgomp.a)
  else()
    target_link_libraries(ddisasm PRIVATE gomp)
  endif()
endif()

if(DDISASM_ENABLE_TESTS)
  add_subdirectory(tests)
endif()

if(UNIX
   AND NOT CYGWIN
   AND ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo" OR "${CMAKE_BUILD_TYPE}"
                                                           STREQUAL "Debug")
   AND ${DDISASM_STRIP_DEBUG_SYMBOLS})
  string(
    RANDOM
    LENGTH 32
    ALPHABET "abcdef0123456789" BUILD_ID)
  string(SUBSTRING "${BUILD_ID}" 0 2 BUILD_ID_PREFIX)
  string(SUBSTRING "${BUILD_ID}" 2 32 BUILD_ID_SUFFIX)
  target_link_libraries(ddisasm PRIVATE "-Wl,--build-id=0x${BUILD_ID}")
  add_custom_command(
    TARGET ddisasm
    POST_BUILD
    COMMAND objcopy --only-keep-debug $<TARGET_FILE:ddisasm>
            ${CMAKE_BINARY_DIR}/bin/${BUILD_ID_SUFFIX}.debug
    COMMAND objcopy --strip-debug $<TARGET_FILE:ddisasm>)
  install(
    FILES "${CMAKE_BINARY_DIR}/bin/${BUILD_ID_SUFFIX}.debug"
    COMPONENT debug-file
    DESTINATION "lib/debug/.build-id/${BUILD_ID_PREFIX}")
endif()

install(
  TARGETS ddisasm
  COMPONENT ddisasm
  DESTINATION bin)

if(BUILD_FUNINFER)
  # ===== souffle_funinfer =====

  add_executable(funinfer FunInfer.cpp)

  target_include_directories(
    funinfer PRIVATE $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)

  if(${GTIRB_USE_SYSTEM_BOOST} MATCHES "OFF")
    add_dependencies(funinfer Boost)
  endif()

  if(DDISASM_STATIC_DRIVERS)
    if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
      # We do not want to statically link in the STL here, as MSVC is a bit
      # prickly about STL ABIs.
    else()
      target_link_libraries(funinfer PRIVATE -static-libstdc++ -static-libgcc)
    endif()
  endif()

  target_link_libraries(
    funinfer
    PRIVATE gtirb
            gtirb_decoder
            scc_pass
            ${CAPSTONE}
            ${Boost_LIBRARIES}
            ${EXPERIMENTAL_LIB}
            ${LIBCPP_ABI}
            scc_pass)

  if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    target_link_libraries(funinfer PRIVATE scc_pass no_return_pass
                                           function_inference_pass)
    target_link_options(
      funinfer PRIVATE /WHOLEARCHIVE:no_return_pass$<$<CONFIG:Debug>:d>
      /WHOLEARCHIVE:function_inference_pass$<$<CONFIG:Debug>:d>)
  else()
    target_link_libraries(
      funinfer PRIVATE -Wl,--whole-archive no_return_pass
                       function_inference_pass -Wl,--no-whole-archive)
  endif()

  target_compile_options(funinfer PRIVATE ${OPENMP_FLAGS})

  if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    target_link_options(funinfer PRIVATE -NODEFAULTLIB:LIBCMTD)
    set_common_msvc_options(funinfer)
  else()
    target_compile_options(funinfer PRIVATE -O3)
    target_compile_options(funinfer PRIVATE -Wall)
    target_compile_options(funinfer PRIVATE -Wextra -Wpointer-arith)
    target_compile_options(funinfer PRIVATE -Werror)
  endif()

  if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
    if(DDISASM_STATIC_DRIVERS)
      target_link_libraries(funinfer PRIVATE -l:libgomp.a)
    else()
      target_link_libraries(funinfer PRIVATE gomp pthread)
    endif()
  endif()

  install(TARGETS funinfer DESTINATION bin)
endif()
