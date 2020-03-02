#!/bin/bash

# This script is called in the linux Dockerfiles.

# These options prevent false negatives in the jobs which use this script.
# They also make failures of the script more transparent.
set -o xtrace
set -o nounset
set -o errexit
set -o pipefail

CXX_COMPILER=$1

# Build GTIRB
rm -rf /ddisasm/gtirb/build /ddisasm/gtirb/CMakeCache.txt /ddisasm/gtirb/CMakeFiles /ddisasm/gtirb/CMakeScripts
cd /ddisasm/gtirb/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} -DGTIRB_JAVA_API=OFF && cd build && which sudo 2>&1 >/dev/null && sudo make install || make install

# Build gtirb-pprinter
rm -rf /ddisasm/gtirb-pprinter/build /ddisasm/gtirb-pprinter/CMakeCache.txt /ddisasm/gtirb-pprinter/CMakeFiles /ddisasm/gtirb-pprinter/CMakeScripts
cd /ddisasm/gtirb-pprinter/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} && cd build &&  make

# Build ehp
rm -rf /ddisasm/libehp/build /ddisasm/libehp/CMakeCache.txt /ddisasm/libehp/CMakeFiles /ddisasm/libehp/CMakeScripts
cd /ddisasm/libehp/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} && cd build &&  make

# Build ddisasm
rm -rf /ddisasm/build /ddisasm/CMakeCache.txt /ddisasm/CMakeFiles /ddisasm/CMakeScripts
cd /ddisasm
cmake ./  -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} -DLIEF_ROOT=/usr/ && cd build && make
