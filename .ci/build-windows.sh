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
FIXED_BUILD_TYPE=$(echo $BUILD_TYPE | sed 's/Debug/Debug/;s/RelWithDebInfo/Release/')
curl -L https://git.grammatech.com/rewriting/gtirb/-/jobs/artifacts/${GTIRB_BRANCH}/download?job=build-windows-msvc-${BUILD_TYPE,,} --output "gtirb-artifacts.zip"
unzip gtirb-artifacts.zip

# Install GTIRB python API
curl -L https://git.grammatech.com/rewriting/gtirb/-/jobs/artifacts/${GTIRB_BRANCH}/download?job=python-wheel --output "gtirb-wheel.zip"
unzip gtirb-wheel.zip
python -m pip install pip --upgrade && python -m pip install gtirb-*-py*.whl

# Install the pretty printer
GTIRB_PPRINTER_BRANCH=$((grep -Eo "check_gtirb_pprinter_branch\([^)]+" CMakeLists.txt | sed 's/check_gtirb_pprinter_branch(//') || echo "master")
curl -L https://git.grammatech.com/rewriting/gtirb-pprinter/-/jobs/artifacts/${GTIRB_PPRINTER_BRANCH}/download?job=build-windows-msvc-${BUILD_TYPE,,} --output "gtirb-pprinter-artifacts.zip"
unzip gtirb-pprinter-artifacts.zip

# Install libehp
mkdir -p libehp/build
pushd libehp/build
cd ..
cd build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G \"Ninja\" -DEHP_BUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=${BUILD_TYPE} .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja"
popd

# Build ddisasm
GTIRB_DIR=$(cygpath -m $(realpath $(find ./ -type d -name GTIRB-*-win64)/lib/gtirb))
GTIRB_PPRINTER_DIR=$(cygpath -m $(realpath $(find ./ -type d -name gtirb_pprinter-*-win64)/lib/gtirb_pprinter))
mkdir -p build
cd build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G \"Ninja\" -DBOOST_ROOT=\"C:\\Boost\" -DCAPSTONE=\"C:\\capstone-${FIXED_BUILD_TYPE}\\lib\\capstone.lib\" -DLIEF_ROOT=\"C:\\lief-${FIXED_BUILD_TYPE}\" -DDDISASM_USE_SYSTEM_BOOST=ON -DDDISASM_BUILD_SHARED_LIBS=ON -DCMAKE_CXX_FLAGS=\"/I C:\\capstone-${FIXED_BUILD_TYPE}\\include /I C:\\users\\vagrant\\AppData\\local\\Packages\\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\\localstate\\rootfs\\usr\\local\\include /DBOOST_ALL_DYN_LINK\" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_PROGRAM_PATH=\"C:\\capstone-${FIXED_BUILD_TYPE}\\bin\" -DPYTHON=C:\\Python38\\python.exe  -Dgtirb_DIR=$GTIRB_DIR -Dgtirb_pprinter_DIR=$GTIRB_PPRINTER_DIR .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja"

# Generate windows package
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cpack.exe -G ZIP"

# Collect extra dlls needed to run ddisasm, including pdbs
ZIP_FILE=(DDISASM-*-win64.zip)
BASE_DIRECTORY="${ZIP_FILE%.*}"
unzip $ZIP_FILE
cp /cygdrive/c/Boost/lib/boost_*-vc141-mt$(echo $BUILD_TYPE | sed 's/Debug/-gd/;s/RelWithDebInfo//')-x64-1_67.dll $BASE_DIRECTORY/bin/
cp $GTIRB_DIR/../../bin/gtirb$(echo $BUILD_TYPE | sed 's/Debug/d/;s/RelWithDebInfo//').{dll,pdb} $BASE_DIRECTORY/bin
cp $GTIRB_PPRINTER_DIR/../../bin/gtirb_pprinter$(echo $BUILD_TYPE | sed 's/Debug/d/;s/RelWithDebInfo//').{dll,pdb} $BASE_DIRECTORY/bin/
cp bin/ddisasm.pdb $BASE_DIRECTORY/bin
cp -r ./$BASE_DIRECTORY ../

# Test ddisasm
cp $BASE_DIRECTORY/bin/*.dll ./bin

# We don't run the tests on the debug build because they take over 3 hours.
if [ "$BUILD_TYPE" == 'RelWithDebInfo' ]; then
  DDISASM_BIN=$(cygpath -w $(pwd)/bin)
  PATH="$PATH;$DDISASM_BIN" cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\ctest.exe -V"
fi
