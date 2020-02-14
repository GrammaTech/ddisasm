set(PROJECT_NAME TestDdisasm)

include_directories(${GTEST_INCLUDE_DIRS})

if(UNIX AND NOT WIN32)
  set(SYSLIBS dl)
else()
  set(SYSLIBS)
endif()

add_executable(TestDdisasm GtirbZeroBuilder.Test.cpp LIEFBinaryReader.Test.cpp
                           SccPass.Test.cpp NoReturnPass.Test.cpp)

add_library(zero_builder STATIC ../GtirbZeroBuilder.cpp ../LIEFBinaryReader.cpp)

target_link_libraries(zero_builder gtirb ${LIEF_LIBRARIES})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_link_libraries(
    ${PROJECT_NAME}
    ${SYSLIBS}
    ${Boost_LIBRARIES}
    gtest
    gtest_main
    gtirb
    scc_pass
    no_return_pass
    zero_builder)
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
    scc_pass
    -Wl,--whole-archive
    no_return_pass
    -Wl,--no-whole-archive
    zero_builder)
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(${PROJECT_NAME} PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(${PROJECT_NAME} PRIVATE ${OPENMP_FLAGS})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  target_link_libraries(${PROJECT_NAME} gomp)
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE -EHsc)
  target_link_options(${PROJECT_NAME} PRIVATE /NODEFAULTLIB:LIBCMTD)
endif()

# Add tests to make test
add_test(
  NAME TestDdisasm
  COMMAND $<TARGET_FILE:${PROJECT_NAME}>
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/")
