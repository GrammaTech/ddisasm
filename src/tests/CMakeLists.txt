set(PROJECT_NAME TestDdisasm)

include_directories(${GTEST_INCLUDE_DIRS})

if(UNIX AND NOT WIN32)
  set(SYSLIBS dl)
else()
  set(SYSLIBS)
endif()

add_executable(
  TestDdisasm
  ../Registration.cpp
  Main.Test.cpp
  SccPass.Test.cpp
  NoReturnPass.Test.cpp
  ElfReader.Test.cpp
  RawReader.Test.cpp
  CompositeLoader.Test.cpp
  ArchiveReader.Test.cpp
  InstructionRelations.Test.cpp)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_link_libraries(
    ${PROJECT_NAME}
    ${SYSLIBS}
    ${Boost_LIBRARIES}
    gtest
    gtest_main
    gtirb
    gtirb_builder
    gtirb_decoder
    ddisasm_datalog
    scc_pass
    no_return_pass)
  target_link_options(
    ${PROJECT_NAME} PRIVATE /WHOLEARCHIVE:ddisasm_datalog$<$<CONFIG:Debug>:d>
    /WHOLEARCHIVE:no_return_pass$<$<CONFIG:Debug>:d>)
else()
  if(APPLE)
    target_link_libraries(
      ${PROJECT_NAME}
      ${SYSLIBS}
      ${Boost_LIBRARIES}
      gtest
      gtest_main
      gtirb
      gtirb_builder
      gtirb_decoder
      scc_pass
      -Wl,-all_load
      ddisasm_datalog
      no_return_pass
      -Wl,-noall_load)
  else()
    target_link_libraries(
      ${PROJECT_NAME}
      ${SYSLIBS}
      ${Boost_LIBRARIES}
      gtest
      gtest_main
      gtirb
      gtirb_builder
      gtirb_decoder
      scc_pass
      -Wl,--whole-archive
      ddisasm_datalog
      no_return_pass
      -Wl,--no-whole-archive)
  endif()
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(${PROJECT_NAME} PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(${PROJECT_NAME} PRIVATE ${OPENMP_FLAGS})
if(SOUFFLE_INCLUDE_DIR)
  target_include_directories(${PROJECT_NAME} SYSTEM
                             PRIVATE ${SOUFFLE_INCLUDE_DIR})
endif()

if(CAPSTONE_INCLUDE_DIR)
  target_include_directories(${PROJECT_NAME} PRIVATE ${CAPSTONE_INCLUDE_DIR})
endif()
if(ehp_INCLUDE_DIR)
  target_include_directories(${PROJECT_NAME} PRIVATE ${ehp_INCLUDE_DIR})
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  target_link_libraries(${PROJECT_NAME} gomp)
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE -EHsc)
  target_link_options(${PROJECT_NAME} PRIVATE /NODEFAULTLIB:LIBCMTD)
  set_msvc_lief_options(${PROJECT_NAME})
  set_common_msvc_options(${PROJECT_NAME})
endif()

# Add tests to make test
add_test(
  NAME TestDdisasm
  COMMAND $<TARGET_FILE:${PROJECT_NAME}>
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/")
