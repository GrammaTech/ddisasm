#
# Cmake Configuration
#

# Need 3.9 to support CXX_STANDARD=17 and protobuf
CMAKE_MINIMUM_REQUIRED(VERSION 3.9.0)

PROJECT(DDISASM)

#
# Global Options (CMake)
#

# This just sets the builtin BUILD_SHARED_LIBS, but if defaults to ON
# instead of OFF.
option(DDISASM_BUILD_SHARED_LIBS "Build shared libraries." ON)
option(DDISASM_USE_SYSTEM_BOOST "Use system-wide installation of Boost." OFF)
if(DDISASM_BUILD_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ON)
else()
  set(BUILD_SHARED_LIBS OFF)
endif()

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
if (WIN32)
  set(CMAKE_DEBUG_POSTFIX          "d" CACHE STRING "add a postfix, usually d on windows")
endif()
set(CMAKE_RELEASE_POSTFIX        ""  CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_RELWITHDEBINFO_POSTFIX ""  CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_MINSIZEREL_POSTFIX     ""  CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_EXTENSIONS OFF)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
# Error if it's not available
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specifically check for gcc-7 or later. gcc-5 is installed on many
# systems and will accept -std=c++17, but does not fully support the
# standard.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0.0")
    message(FATAL_ERROR "gcc 7 or later is required to build gtirb")
  endif()
endif()

set(CMAKE_CXX_VISIBILITY_PRESET hidden)

# If we're using libc++, we need to manually include libc++abi
# (unlike with using libstdc++, which automatically does this)
include(CheckCXXSourceCompiles)

check_cxx_source_compiles("
  #include <ciso646>
  int main() {
    return _LIBCPP_VERSION;
  }
" USING_LIBCPP)

if(USING_LIBCPP)
  if (BUILD_SHARED_LIBS)
    find_library(LIBCPP_ABI NAMES c++abi)
  else()
    find_library(LIBCPP_ABI NAMES libc++abi.a)
  endif()

  if(NOT LIBCPP_ABI)
    message(FATAL_ERROR "libc++abi not found")
  endif()
endif()

# ---------------------------------------------------------------------------
# gtirb
# ---------------------------------------------------------------------------

find_package(gtirb REQUIRED)

# ---------------------------------------------------------------------------
# pretty-printer
# ---------------------------------------------------------------------------

find_package(gtirb_pprinter REQUIRED)

# ---------------------------------------------------------------------------
# libehp
# ---------------------------------------------------------------------------

find_package(ehp REQUIRED)


# ---------------------------------------------------------------------------
# Boost
# ---------------------------------------------------------------------------
find_package(Boost 1.67 REQUIRED COMPONENTS program_options)

if(NOT Boost_LIBRARIES)
  message(FATAL_ERROR "\
Boost was detected as being installed, but no libraries were found.
Try specifying -DBoost_NO_BOOST_CMAKE=ON on the command line.")
endif()

include_directories(${Boost_INCLUDE_DIRS})

# ---------------------------------------------------------------------------
# capstone
# ---------------------------------------------------------------------------
if (BUILD_SHARED_LIBS)
  find_library(CAPSTONE NAMES capstone)
else()
  find_library(CAPSTONE NAMES libcapstone.a)
endif()

if(NOT CAPSTONE)
  message(FATAL_ERROR
  " No Capstone installation found.\n"
  " - If Capstone is not installed, install it from souce.\n"
  "   You can get the latest version of Capstone at:\n"
  "       http://www.capstone-engine.org/\n"
  " - If Capstone is installed, make sure the installation location is in your PATH,\n"
  "   and it is at least version 4.0.1.\n"
  )
endif()

# ---------------------------------------------------------------------------
# source files
# ---------------------------------------------------------------------------
add_subdirectory(src)
add_subdirectory(doc)
