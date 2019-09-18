
#============ Scc pass =================

add_library(scc_pass STATIC
  SccPass.cpp)

target_link_libraries(scc_pass
  gtirb)


#============ No return pass =================

set(NO_RETURN_DATALOG_SOURCES
    datalog/no_return_analysis.dl)

set(NO_RETURN_CPP "${CMAKE_BINARY_DIR}/src/passes/souffle_no_return.cpp")

add_custom_command(OUTPUT ${NO_RETURN_CPP}
  # Souffle incldes the path of the output file in the generated
  # program name. Change directory and use a relative path so the name
  # does not depend on build location.
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/src/passes"
  COMMAND ${SOUFFLE} ${CMAKE_CURRENT_SOURCE_DIR}/datalog/no_return_analysis.dl -g souffle_no_return.cpp -j${CORES}
  DEPENDS ${NO_RETURN_DATALOG_SOURCES})



add_library(no_return_pass STATIC
  NoReturnPass.cpp
  GtirbToDatalog.cpp
  ${NO_RETURN_CPP}
  )

target_link_libraries(no_return_pass
  gtirb)

target_compile_definitions(no_return_pass PRIVATE __EMBEDDED_SOUFFLE__)
target_compile_definitions(no_return_pass PRIVATE RAM_DOMAIN_SIZE=64)
target_compile_options(no_return_pass PRIVATE ${OPENMP_FLAGS})
target_compile_options(no_return_pass PRIVATE -O3)
