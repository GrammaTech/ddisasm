#
# Cmake Configuration
#

# We use 3.12.1 to ease compatability with gtirb-pprinter.
cmake_minimum_required(VERSION 3.12.1)

# Get version
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/version.txt" ver)

string(REGEX MATCH "VERSION_MAJOR ([0-9]*)" _ ${ver})
set(DDISASM_MAJOR_VERSION ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_MINOR ([0-9]*)" _ ${ver})
set(DDISASM_MINOR_VERSION ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_PATCH ([0-9]*)" _ ${ver})
set(DDISASM_PATCH_VERSION ${CMAKE_MATCH_1})

project(
  DDISASM
  VERSION
    "${DDISASM_MAJOR_VERSION}.${DDISASM_MINOR_VERSION}.${DDISASM_PATCH_VERSION}"
)

#
# Global Options (CMake)
#

option(DDISASM_ARM_32 "Whether or not ARM support is built." ON)
option(DDISASM_ARM_64 "Whether or not ARM64 support is built." ON)
option(DDISASM_MIPS_32 "Whether or not MIPS support is built." ON)
option(DDISASM_X86_32 "Whether or not x86_32 support is built." ON)
option(DDISASM_X86_64 "Whether or not x86_64 support is built." ON)
option(DDISASM_SOUFFLE_PROFILING "Whether to generate Souffle profiles." OFF)

option(DDISASM_GENERATE_MANY "Whether to have Souffle generate multiple files."
       OFF)
option(DDISASM_RELEASE_VERSION
       "Whether or not to build Python package versions without dev suffixes."
       OFF)

if(NOT DEFINED DDISASM_BUILD_REVISION)
  execute_process(
    COMMAND git log --pretty=format:%h -n 1
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    OUTPUT_VARIABLE DDISASM_BUILD_REVISION
    ERROR_QUIET)
endif()
if(DDISASM_BUILD_REVISION STREQUAL "")
  set(DDISASM_BUILD_REVISION "UNKNOWN")
endif()

string(TIMESTAMP DDISASM_BUILD_DATE "%Y-%m-%d")

if(DDISASM_ARM_64)
  list(APPEND DDISASM_ARCH_LIST "ARM64")
endif()
if(DDISASM_X86_32)
  list(APPEND DDISASM_ARCH_LIST "IA32")
endif()
if(DDISASM_X86_64)
  list(APPEND DDISASM_ARCH_LIST "X64")
endif()
if(DDISASM_ARM_32)
  list(APPEND DDISASM_ARCH_LIST "ARM32")
endif()
if(DDISASM_MIPS_32)
  list(APPEND DDISASM_ARCH_LIST "MIPS32")
endif()
list(JOIN DDISASM_ARCH_LIST "+" DDISASM_BUILD_ARCH_TARGETS)

option(DDISASM_ENABLE_TESTS "Enable building and running unit tests." ON)

option(ENABLE_CONAN "Use Conan to inject dependencies" OFF)

if(ENABLE_CONAN)
  include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
  conan_basic_setup(TARGETS)
endif()

# The libraries can be static while the drivers can link in other things in a
# shared manner. This option allows for this possibility.
option(
  DDISASM_STATIC_DRIVERS
  "Attempt to make any driver executables as statically-linked as possible.
Implies DDISASM_BUILD_SHARED_LIBS=OFF."
  OFF)

if(DDISASM_STATIC_DRIVERS)
  set(Boost_USE_STATIC_LIBS ON)

  if(WIN32)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
  else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  endif()
endif()

# This just sets the builtin BUILD_SHARED_LIBS, but if defaults to ON instead of
# OFF.
option(DDISASM_BUILD_SHARED_LIBS "Build shared libraries." ON)
option(DDISASM_USE_SYSTEM_BOOST "Use system-wide installation of Boost." OFF)
if(DDISASM_STATIC_DRIVERS OR NOT DDISASM_BUILD_SHARED_LIBS)
  set(BUILD_SHARED_LIBS OFF)
else()
  set(BUILD_SHARED_LIBS ON)
endif()

# Determine whether or not to strip debug symbols and set the build-id. This is
# only really needed when we are building ubuntu *-dbg packages
option(DDISASM_STRIP_DEBUG_SYMBOLS
       "Whether or not to strip debug symbols and set the build-id." OFF)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
if(WIN32)
  set(CMAKE_DEBUG_POSTFIX
      "d"
      CACHE STRING "add a postfix, usually d on windows")
endif()
set(CMAKE_RELEASE_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_RELWITHDEBINFO_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_MINSIZEREL_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_EXTENSIONS OFF)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
# Error if it's not available
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specifically check for gcc-7 or later. gcc-5 is installed on many systems and
# will accept -std=c++17, but does not fully support the standard.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0.0")
    message(FATAL_ERROR "gcc 7 or later is required to build gtirb")
  endif()
endif()

set(CMAKE_CXX_VISIBILITY_PRESET hidden)

# If we're using libc++, we need to manually include libc++abi (unlike with
# using libstdc++, which automatically does this)
include(CheckCXXSourceCompiles)

check_cxx_source_compiles(
  "
  #include <ciso646>
  int main() {
    return _LIBCPP_VERSION;
  }
"
  USING_LIBCPP)

if(USING_LIBCPP)
  if(BUILD_SHARED_LIBS)
    find_library(LIBCPP_ABI NAMES c++abi)
  else()
    find_library(LIBCPP_ABI NAMES libc++abi.a)
  endif()

  if(NOT LIBCPP_ABI)
    message(FATAL_ERROR "libc++abi not found")
  endif()
endif()

# Using libstdc++'s std::filesystem in GCC 8 needs to have libstdc++fs linked
# in. Because one could use libstdc++ with Clang instead of gcc, we detect
# whether to use the flag by just trying it out.
check_cxx_source_compiles(
  "
  #include <ciso646>
  int main() {
    return _GLIBCXX_RELEASE;
  }
  "
  USING_LIBSTDCXX)

if(USING_LIBSTDCXX)
  include(CMakePushCheckState)
  cmake_push_check_state(RESET)

  set(CMAKE_REQUIRED_FLAGS -std=c++17)
  check_cxx_source_compiles(
    "
    #include <filesystem>
    int main() {
        return std::filesystem::path(\"/\").is_absolute() ? 0 : 1;
    }
    "
    LIBSTDCXX_WORKS_WITHOUT_LIBFS)

  if(NOT LIBSTDCXX_WORKS_WITHOUT_LIBFS)
    set(CMAKE_REQUIRED_LIBRARIES stdc++fs)
    check_cxx_source_compiles(
      "
      #include <filesystem>
      int main() {
        return std::filesystem::path(\"/\").is_absolute() ? 0 : 1;
      }
      "
      LIBSTDCXX_WORKS_WITH_LIBFS)

    if(LIBSTDCXX_WORKS_WITH_LIBFS)
      set(LIBSTDCXX_FS stdc++fs)
    else()
      message(FATAL_ERROR "could not determine how to link std::filesystem")
    endif()
  endif()

  cmake_pop_check_state()
endif()

# ---------------------------------------------------------------------------
# gtirb
# ---------------------------------------------------------------------------
find_package(gtirb 2.2.0 REQUIRED)

add_definitions(-DGTIRB_WRAP_UTILS_IN_NAMESPACE)

# ---------------------------------------------------------------------------
# pretty-printer
# ---------------------------------------------------------------------------
find_package(gtirb_pprinter 2.0.0 REQUIRED)

# ---------------------------------------------------------------------------
# libehp
# ---------------------------------------------------------------------------

# ehp builds the necessary cmake files, but does not install them. If
# find_package fails, fall back to looking for the library and header file
# directly.

if(NOT ehp_LIBRARIES OR NOT ehp_INCLUDE_DIR)
  find_package(ehp QUIET)
  if(ehp_FOUND)
    # When find_package finds ehp, it runs add_library(ehp) which this project
    # must link against by name.
    set(ehp_LIBRARIES ehp)
  else()
    find_library(
      ehp_LIBRARIES
      NAMES ehp
      HINTS ${ehp_ROOT}/lib $ENV{ehp_ROOT}/lib)
    if(ehp_LIBRARIES)
      message(STATUS "Found ehp: ${ehp_LIBRARIES}")
    else()
      message(
        SEND_ERROR
          "could not find ehp library file\n"
          "Try setting \"ehp_ROOT\" to the ehp installation directory, or set "
          "\"ehp_DIR\" to the ehp build directory.")
    endif()

    find_path(
      ehp_INCLUDE_DIR
      NAMES ehp.hpp
      HINTS ${ehp_ROOT}/include $ENV{ehp_ROOT}/include)
    if(ehp_INCLUDE_DIR)
      message(STATUS "Found ehp: ${ehp_INCLUDE_DIR}")
    else()
      message(
        SEND_ERROR
          "could not find ehp header file: ehp.hpp\n"
          "Try setting \"ehp_ROOT\" to the ehp installation directory, or set "
          "\"ehp_DIR\" to the ehp build directory.")
    endif()
  endif()
endif()

# ---------------------------------------------------------------------------
# Boost
# ---------------------------------------------------------------------------
#
# Note: we would like to use std::filsystem. However, currently, std::filesystem
# is not provided in clang 6 or gcc 7, both of which are the default installed
# versions for Ubuntu 18. Instead in that context, one can use the
# "experimental" version fo filesystem. But we've decided that it's simpler to
# just use boost::filesystem instead until we (eventually) drop support for
# Ubuntu 18.
set(BOOST_COMPONENTS filesystem program_options system)
find_package(Boost 1.67 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

# Boost versions 1.70.0+ may use Boost's provided CMake support rather than
# CMake's internal Boost support. The former uses "Boost::boost" and so on,
# while the latter uses "Boost_BOOST" and so on. This normalizes the two cases
# to use Boost_INCLUDE_DIRS and Boost_LIBRARIES.
if(TARGET Boost::headers)
  get_target_property(Boost_INCLUDE_DIRS Boost::headers
                      INTERFACE_INCLUDE_DIRECTORIES)
  foreach(BOOST_COMPONENT ${BOOST_COMPONENTS})
    list(APPEND Boost_LIBRARIES Boost::${BOOST_COMPONENT})
  endforeach()
endif()

include_directories(${Boost_INCLUDE_DIRS})

# ---------------------------------------------------------------------------
# capstone
# ---------------------------------------------------------------------------
if(BUILD_SHARED_LIBS)
  find_library(CAPSTONE NAMES capstone)
else()
  find_library(CAPSTONE NAMES libcapstone.a)
endif()

if(CAPSTONE)
  find_program(CSTOOL "cstool")
  # When using conan to install the dependencies but CMake to do the build, the
  # capstone libraries may not be findable by the loader. Set LD_LIBRARY path to
  # fix this.
  get_filename_component(CAPSTONE_LIB_DIR "${CAPSTONE}" DIRECTORY)
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E env
            "LD_LIBRARY_PATH=$ENV{LD_LIBRARY_PATH}:${CAPSTONE_LIB_DIR}" #
            "${CSTOOL}" "-v" OUTPUT_VARIABLE CSTOOL_VERSION)
  string(REGEX MATCH "v([0-9]+\.[0-9]+\.[0-9]+)" CSTOOL_VERSION
               "${CSTOOL_VERSION}")
  set(CSTOOL_VERSION "${CMAKE_MATCH_1}")
endif()

if(NOT CAPSTONE OR "${CSTOOL_VERSION}" VERSION_LESS "5.0.1")
  message(
    FATAL_ERROR
      " No Capstone installation found.\n"
      " - If Capstone is not installed, install it from souce.\n"
      "   You can get the latest version of Capstone at:\n"
      "       http://www.capstone-engine.org/\n"
      " - If Capstone is installed, make sure the installation location is in your PATH,\n"
      "   and it is at least version 5.0.1.\n")
endif()

if(NOT CAPSTONE_INCLUDE_DIR)
  get_filename_component(CAPSTONE_LIB_DIR ${CAPSTONE} DIRECTORY)
  get_filename_component(CAPSTONE_INCLUDE_DIR ${CAPSTONE_LIB_DIR}/../include
                         ABSOLUTE)
  if(NOT EXISTS ${CAPSTONE_INCLUDE_DIR}/capstone)
    message(WARNING "CAPSTONE_INCLUDE_DIR not found")
    unset(CAPSTONE_INCLUDE_DIR)
  endif()
  unset(CAPSTONE_LIB_DIR)
endif()

# ---------------------------------------------------------------------------
# LIEF
# ---------------------------------------------------------------------------
if(ENABLE_CONAN)
  set(LIEF_LIBRARIES CONAN_PKG::lief)
else()
  find_package(LIEF 0.16.6 REQUIRED COMPONENTS STATIC)
endif()

# ---------------------------------------------------------------------------
# Google Test Application
# ---------------------------------------------------------------------------
if(DDISASM_ENABLE_TESTS)
  enable_testing()
  # Pull in Google Test
  # https://github.com/google/googletest/tree/master/googletest#incorporating-
  # into-an-existing-cmake-project

  # Download and unpack googletest at configure time
  configure_file(CMakeLists.googletest googletest-download/CMakeLists.txt)

  execute_process(
    COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    RESULT_VARIABLE result
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download")

  if(result)
    message(WARNING "CMake step for googletest failed: ${result}")
  endif()

  execute_process(
    COMMAND "${CMAKE_COMMAND}" --build .
    RESULT_VARIABLE result
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download")

  if(result)
    message(WARNING "Build step for googletest failed: ${result}")
  endif()

  # Prevent overriding the parent project's compiler/linker settings on Windows
  set(gtest_force_shared_crt
      ON
      CACHE BOOL "" FORCE)

  # Add googletest directly to our build. This defines the gtest and gtest_main
  # targets.
  add_subdirectory("${CMAKE_BINARY_DIR}/googletest-src"
                   "${CMAKE_BINARY_DIR}/googletest-build" EXCLUDE_FROM_ALL)

  include_directories("${gtest_SOURCE_DIR}/include")
endif()

# ---------------------------------------------------------------------------
# source files
# ---------------------------------------------------------------------------

add_subdirectory(src)
add_subdirectory(doc)

option(DDISASM_RELEASE_VERSION "Build Python ddisasm package." OFF)
if(DDISASM_BUILD_PYTHON_PACKAGE)
  add_subdirectory(python)
endif()

if(DDISASM_ENABLE_TESTS)
  find_program(PYTHON "python3")

  add_test(
    NAME python_tests
    COMMAND
      ${PYTHON} -u -m unittest discover tests "*_test.py" -v
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/")
endif()

# ---------------------------------------------------------------------------
# Package policy enforcement
# ---------------------------------------------------------------------------

if(DDISASM_PACKAGE_POLICY)
  set(PACKAGE_POLICY ${DDISASM_PACKAGE_POLICY})
elseif(ENABLE_CONAN OR WIN32)
  set(PACKAGE_POLICY conan)
else()
  set(PACKAGE_POLICY unix)
endif()

if(PACKAGE_POLICY STREQUAL "unix")

  # Provides copyright file for Unix packages.
  install(
    FILES ${CMAKE_SOURCE_DIR}/LICENSE.txt
    COMPONENT license
    DESTINATION share/doc/ddisasm
    RENAME copyright)

elseif(PACKAGE_POLICY STREQUAL "conan")

  # Provides LICENSE.txt for Conan packages
  install(
    FILES ${CMAKE_SOURCE_DIR}/LICENSE.txt
    COMPONENT license
    DESTINATION licenses)

endif()
# ---------------------------------------------------------------------------
# Package generation with cpack
# ---------------------------------------------------------------------------
set(CPACK_PROJECT_CONFIG_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cpack-config.cmake)

set(CMAKE_PROJECT_HOMEPAGE_URL https://github.com/grammatech/ddisasm)
set(CPACK_PACKAGE_VERSION_MAJOR ${DDISASM_MAJOR_VERSION})
set(CPACK_PACKAGE_VERSION_MINOR ${DDISASM_MINOR_VERSION})
set(CPACK_PACKAGE_VERSION_PATCH ${DDISASM_PATCH_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "A fast disassembler which is accurate enough for the resulting assembly code to be reassembled. The disassembler implemented using the datalog (souffle) declarative logic programming language to compile disassembly rules and heuristics."
)
set(CPACK_PACKAGE_VEDOR "GrammaTech Inc.")
set(CPACK_PACKAGE_CONTACT gtirb@grammatech.com)
set(CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_CURRENT_SOURCE_DIR}/README.md)
set(CPACK_PACKAGE_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt)

set(CPACK_DEBIAN_PACKAGE_SECTION devel)

set(CPACK_DDISASM_VERSION "${PROJECT_VERSION}")
set(CPACK_GTIRB_VERSION "${gtirb_VERSION}")
set(CPACK_GTIRB_PPRINTER_VERSION "${gtirb_pprinter_VERSION}")

include(CPack)

# ---------------------------------------------------------------------------
# Report architecture support and features built
# ---------------------------------------------------------------------------

message("Architecture support to be built:")
message("    ARM32     ${DDISASM_ARM_32}")
message("    ARM64     ${DDISASM_ARM_64}")
message("    MIPS32    ${DDISASM_MIPS_32}")
message("    X86_32    ${DDISASM_X86_32}")
message("    X86_64    ${DDISASM_X86_64}")
