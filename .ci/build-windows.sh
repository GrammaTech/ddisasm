
#!/bin/bash

# Called in gitlab-ci.yml

# These options prevent false negatives in the jobs which use this script.
# They also make failures of the script more transparent.
set -o xtrace
set -o nounset
set -o errexit
set -o pipefail

BUILD_TYPE=$1

# Install GTIRB
GTIRB_BRANCH=$((grep -Eo "check_gtirb_branch\([^)]+" CMakeLists.txt || echo "master") | sed 's/check_gtirb_branch(//')
curl -L https://git.grammatech.com/rewriting/gtirb/-/jobs/artifacts/${GTIRB_BRANCH}/download?job=build-windows-msvc-${BUILD_TYPE,,} --output "gtirb-artifacts.zip"
unzip gtirb-artifacts.zip
unzip GTIRB-*-win64.zip

# Install the pretty printer
GTIRB_PPRINTER_BRANCH=$((grep -Eo "check_gtirb_pprinter_branch\([^)]+" CMakeLists.txt || echo "master") | sed 's/check_gtirb_pprinter_branch(//')
curl -L https://git.grammatech.com/rewriting/gtirb-pprinter/-/jobs/artifacts/${GTIRB_PPRINTER_BRANCH}/download?job=build-windows-${BUILD_TYPE,,} --output "gtirb-pprinter-artifacts.zip"
unzip gtirb-pprinter-artifacts.zip
unzip gtirb_pprinter-*-win64.zip

# Install libehp
mkdir libehp/build
pushd libehp/build
cd ..
cd build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G \"Ninja\" -DEHP_BUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=${BUILD_TYPE} .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja"
popd

# Build ddisasm
GTIRB_DIR=$(cygpath -m $(realpath $(find ./ -type d -name GTIRB-*-win64)/lib/gtirb))
GTIRB_PPRINTER_DIR=$(cygpath -m $(realpath $(find ./ -type d -name gtirb_pprinter-*-win64)/lib/gtirb_pprinter))
mkdir build
cd build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G \"Ninja\" -DBOOST_ROOT=\"C:\\Boost\" -DCAPSTONE=\"C:\\capstone-${BUILD_TYPE}\\lib\\capstone.lib\" -DLIEF_ROOT=\"C:\\lief-${BUILD_TYPE}\" -DDDISASM_USE_SYSTEM_BOOST=ON -DDDISASM_BUILD_SHARED_LIBS=ON -DCMAKE_CXX_FLAGS=\"/I C:\\capstone-${BUILD_TYPE}\\include /I C:\\users\\vagrant\\AppData\\local\\Packages\\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\\localstate\\rootfs\\usr\\local\\include /DBOOST_ALL_DYN_LINK\" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_PROGRAM_PATH=\"C:\\capstone-${BUILD_TYPE}\\bin\" -DPYTHON=C:\\Python38\\python.exe  -Dgtirb_DIR=$GTIRB_DIR -Dgtirb_pprinter_DIR=$GTIRB_PPRINTER_DIR .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja"
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\ctest.exe -V"
