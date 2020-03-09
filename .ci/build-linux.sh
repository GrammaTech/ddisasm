#!/bin/bash

# This script is called in the linux Dockerfiles.

# These options prevent false negatives in the jobs which use this script.
# They also make failures of the script more transparent.
set -o xtrace
set -o nounset
set -o errexit
set -o pipefail

CXX_COMPILER=$1

# Build ddisasm
rm -rf /ddisasm/build /ddisasm/CMakeCache.txt /ddisasm/CMakeFiles /ddisasm/CMakeScripts
cd /ddisasm
cmake ./  -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} -DLIEF_ROOT=/usr/ && cd build && make
