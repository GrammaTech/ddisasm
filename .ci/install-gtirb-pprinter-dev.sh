#!/bin/bash
# Build gtirb-pprinter from $GTIRB_PPRINTER_DEV_BRANCH against the GTIRB
# already installed from APT, then install it into /usr/local.
#
# The APT "unstable" gtirb-pprinter packages are built from gtirb-pprinter
# master, which lacks ISA support and AuxData schemas (e.g. elfTlsBaseAddress)
# that only exist on $GTIRB_PPRINTER_DEV_BRANCH. Jobs on non-release branches
# use this script instead of installing gtirb-pprinter from APT.
#
# The install tree is staged in $GTIRB_PPRINTER_DEV_STAGING so that the build
# job can pass it to downstream jobs as an artifact; if the staging directory
# already exists, the build is skipped and the staged tree is installed
# directly.
set -euo pipefail

GTIRB_PPRINTER_DEV_STAGING="${CI_PROJECT_DIR:-$(pwd)}/gtirb-pprinter-dev-staging"
GTIRB_PPRINTER_DEV_BRANCH="${GTIRB_PPRINTER_DEV_BRANCH:-reaffirm/experimental-isas}"
SOURCE_ROOT="$(mktemp -d)"

# build_and_stage_pprinter
#   Clone gtirb-pprinter at $GTIRB_PPRINTER_DEV_BRANCH, build it, and install
#   it both into the staging directory and into /usr/local.
# Inputs:
#   $GTIRB_PPRINTER_DEV_BRANCH  - gtirb-pprinter branch to clone
#   $GTIRB_PPRINTER_DEV_STAGING - staging directory for the install tree
# Outputs:
#   Installed files under $GTIRB_PPRINTER_DEV_STAGING/usr/local and /usr/local
build_and_stage_pprinter() {
  local source_dir="$SOURCE_ROOT/gtirb-pprinter"

  git clone --depth 1 -b "$GTIRB_PPRINTER_DEV_BRANCH" \
    https://git.grammatech.com/rewriting/gtirb-pprinter.git "$source_dir"
  cmake -S "$source_dir" -B "$source_dir/build" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
  cmake --build "$source_dir/build" -j8
  DESTDIR="$GTIRB_PPRINTER_DEV_STAGING" cmake --install "$source_dir/build"
  cmake --install "$source_dir/build"
}

if [[ -d "$GTIRB_PPRINTER_DEV_STAGING/usr/local" ]]; then
  echo "Installing staged gtirb-pprinter from $GTIRB_PPRINTER_DEV_STAGING"
  cp -a "$GTIRB_PPRINTER_DEV_STAGING/usr/local/." /usr/local/
else
  echo "Building gtirb-pprinter branch $GTIRB_PPRINTER_DEV_BRANCH from source"
  build_and_stage_pprinter
fi

ldconfig
rm -rf "$SOURCE_ROOT"
