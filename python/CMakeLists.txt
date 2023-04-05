function(make_absolute variable path)
  file(READ_SYMLINK "${path}" link_path)
  if(NOT IS_ABSOLUTE "${link_path}")
    get_filename_component(dir "${path}" DIRECTORY)
    set(path "${dir}/${link_path}")
  endif()
  set(${variable}
      "${path}"
      PARENT_SCOPE)
endfunction()

if(DDISASM_RELEASE_VERSION)
  set(DDISASM_PYTHON_DEV_SUFFIX "")
else()
  set(DDISASM_PYTHON_DEV_SUFFIX ".dev")
endif()

# TODO: GTIRB_RELEASE_VERSION or GTIRB_PYTHON_DEV_SUFFIX should come from the
# GTIRB conan files and not get guessed at here.
if(DDISASM_RELEASE_VERSION)
  set(GTIRB_PYTHON_DEV_SUFFIX "")
else()
  set(GTIRB_PYTHON_DEV_SUFFIX ".dev")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/setup.py @ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/version.py @ONLY)

find_library(GTIRB_LIBRARY_PATH gtirb)
make_absolute(GTIRB_LIBRARY_PATH ${GTIRB_LIBRARY_PATH})

find_library(PPRINTER_LIBRARY_PATH gtirb_pprinter)
make_absolute(PPRINTER_LIBRARY_PATH ${PPRINTER_LIBRARY_PATH})

find_library(LAYOUT_LIBRARY_PATH gtirb_layout)
make_absolute(LAYOUT_LIBRARY_PATH ${LAYOUT_LIBRARY_PATH})

find_library(CAPSTONE_LIBRARY_PATH capstone)
make_absolute(CAPSTONE_LIBRARY_PATH ${CAPSTONE_LIBRARY_PATH})

file(GLOB PY_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/ddisasm/*.py)

add_custom_target(pyddisasm ALL DEPENDS ${PY_SOURCES} ddisasm)
add_custom_command(
  TARGET pyddisasm
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/src"
          "${CMAKE_CURRENT_BINARY_DIR}/src"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/README.md"
          "${CMAKE_CURRENT_BINARY_DIR}/"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/version.py"
          "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/"
  COMMAND ${CMAKE_COMMAND} -E make_directory
          "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/.libs/"
  COMMAND ${CMAKE_COMMAND} -E copy ${GTIRB_LIBRARY_PATH}
          "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/.libs/"
  COMMAND ${CMAKE_COMMAND} -E copy ${GTIRB_LIBRARY_PATH}
          "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/.libs/"
  COMMAND ${CMAKE_COMMAND} -E copy ${PPRINTER_LIBRARY_PATH}
          "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/.libs/"
  COMMAND ${CMAKE_COMMAND} -E copy ${LAYOUT_LIBRARY_PATH}
          "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/.libs/"
  COMMAND ${CMAKE_COMMAND} -E copy ${CAPSTONE_LIBRARY_PATH}
          "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/.libs/"
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ddisasm>
          "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/")
if(UNIX AND NOT APPLE)
  add_custom_command(
    TARGET pyddisasm
    COMMAND patchelf --set-rpath '$$ORIGIN/.libs'
            "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/ddisasm"
    COMMAND patchelf --set-rpath '$$ORIGIN'
            "${CMAKE_CURRENT_BINARY_DIR}/src/ddisasm/.libs/*")
endif()

# Convenience targets for installing python
find_program(PYTHON3 "python3")
add_custom_target(
  python-wheel
  DEPENDS pyddisasm
  COMMAND "${PYTHON3}" setup.py bdist_wheel)
