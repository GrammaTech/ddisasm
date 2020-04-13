#!/bin/bash

# Called in gitlab-ci.yml

# These options prevent false negatives in the jobs which use this script.
# They also make failures of the script more transparent.
set -o xtrace
set -o nounset
set -o errexit
set -o pipefail

BUILD_TYPE=$1

mkdir gtirb/build
pushd gtirb/build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G "Ninja" -DBOOST_ROOT=\"C:\\Boost\" -DCMAKE_PREFIX_PATH=\"C:\\Program Files (x86)\\protobuf\" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DPYTHON=C:\\Python38\\python.exe -DCMAKE_INSTALL_PREFIX=\"C:\\gtirb-$BUILD_TYPE\" .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja -j 1 && ninja install"
PATH="$PATH:$(pwd)/bin"
popd

mkdir gtirb-pprinter/build
pushd gtirb-pprinter/build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G \"Ninja\" -DBOOST_ROOT=\"C:\\Boost\" -DCMAKE_CXX_FLAGS=\"/DBOOST_ALL_DYN_LINK\" -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=1 -DCAPSTONE=\"C:\\capstone-${BUILD_TYPE}\\lib\\capstone.lib\" -DCAPSTONE_INCLUDE_DIRS=\"C:\\capstone-${BUILD_TYPE}\\include\" -DCMAKE_PROGRAM_PATH=\"C:\\capstone-${BUILD_TYPE}\\bin\" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja"
popd

mkdir libehp/build
pushd libehp/build
cd ..
cd build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G \"Ninja\" -DEHP_BUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=${BUILD_TYPE} .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja"
popd

mkdir build
cd build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G \"Ninja\" -DBOOST_ROOT=\"C:\\Boost\" -DCAPSTONE=\"C:\\capstone-${BUILD_TYPE}\\lib\\capstone.lib\" -DLIEF_ROOT=\"C:\\lief-${BUILD_TYPE}\" -DDDISASM_USE_SYSTEM_BOOST=ON -DDDISASM_BUILD_SHARED_LIBS=ON -DCMAKE_CXX_FLAGS=\"/I C:\\capstone-${BUILD_TYPE}\\include /I C:\\users\\vagrant\\AppData\\local\\Packages\\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\\localstate\\rootfs\\usr\\local\\include /DBOOST_ALL_DYN_LINK\" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DPYTHON=C:\\Python38\\python.exe .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja"
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\ctest.exe -V"
