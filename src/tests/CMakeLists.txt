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
)

# Add tests to make test
add_test(NAME TestDdisasm COMMAND $<TARGET_FILE:${PROJECT_NAME}>)
