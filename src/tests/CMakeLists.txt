set(PROJECT_NAME TestDdisasm)

include_directories(${GTEST_INCLUDE_DIRS})

if(UNIX AND NOT WIN32)
  set(SYSLIBS dl)
else()
  set(SYSLIBS)
endif()

add_executable(TestDdisasm Main.Test.cpp SccPass.Test.cpp NoReturnPass.Test.cpp
                           ElfReader.Test.cpp)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_link_libraries(
    ${PROJECT_NAME}
    ${SYSLIBS}
    ${Boost_LIBRARIES}
    gtest
    gtest_main
    gtirb
    gtirb_builder
    scc_pass
    no_return_pass)
  target_link_options(${PROJECT_NAME} PRIVATE
                      /WHOLEARCHIVE:no_return_pass$<$<CONFIG:Debug>:d>)
else()
  target_link_libraries(
    ${PROJECT_NAME}
    ${SYSLIBS}
    ${Boost_LIBRARIES}
    gtest
    gtest_main
    gtirb
    gtirb_builder
    scc_pass
    -Wl,--whole-archive
    no_return_pass
    -Wl,--no-whole-archive)
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(${PROJECT_NAME} PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(${PROJECT_NAME} PRIVATE ${OPENMP_FLAGS})

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
