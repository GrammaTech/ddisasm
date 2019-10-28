SET(PROJECT_NAME TestDdisasm)

include_directories(${GTEST_INCLUDE_DIRS})

IF(UNIX AND NOT WIN32)
        SET(SYSLIBS
                dl
        )
ELSE()
        SET(SYSLIBS
        )
ENDIF()

add_executable(TestDdisasm
        SccPass.Test.cpp
        NoReturnPass.Test.cpp)

target_link_libraries(${PROJECT_NAME}
        ${SYSLIBS}
        ${Boost_LIBRARIES}
        gtest
        gtest_main
        gtirb
        scc_pass
        -Wl,--whole-archive
        no_return_pass
        -Wl,--no-whole-archive
)

target_compile_definitions(${PROJECT_NAME} PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(${PROJECT_NAME} PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(${PROJECT_NAME} PRIVATE ${OPENMP_FLAGS})

if(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  target_link_libraries(${PROJECT_NAME} gomp)
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE -EHsc)
endif()

# Add tests to make test
add_test(NAME TestDdisasm COMMAND $<TARGET_FILE:${PROJECT_NAME}>)
