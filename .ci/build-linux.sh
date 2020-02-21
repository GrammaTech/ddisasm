#!/bin/bash

# This script is called in the linux Dockerfiles.

CXX_COMPILER=$1

# Build ddisasm
rm -rf /ddisasm/build /ddisasm/CMakeCache.txt /ddisasm/CMakeFiles /ddisasm/CMakeScripts
cd /ddisasm
cmake ./  -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} -DLIEF_ROOT=/usr/ && cd build && make
