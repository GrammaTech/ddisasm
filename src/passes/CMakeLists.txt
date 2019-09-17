

add_library(scc_pass STATIC
  SccPass.cpp)

target_link_libraries(scc_pass
  gtirb)