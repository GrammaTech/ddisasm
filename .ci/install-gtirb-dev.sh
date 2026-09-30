#!/bin/bash
# Build GTIRB from $GTIRB_DEV_BRANCH and gtirb-pprinter (master) against it,
# then install both into /usr/local.
#
# The APT "unstable" packages are built from GTIRB master, which lacks schema
# changes that only exist on $GTIRB_DEV_BRANCH. Jobs on non-release branches
# use this script instead of installing libgtirb-dev from APT.
#
# The install tree is staged in $GTIRB_DEV_STAGING so that the build job can
# pass it to downstream jobs as an artifact; if the staging directory already
# exists, the build is skipped and the staged tree is installed directly.
set -euo pipefail

GTIRB_DEV_STAGING="${CI_PROJECT_DIR:-$(pwd)}/gtirb-dev-staging"
GTIRB_PPRINTER_DEV_BRANCH="${GTIRB_PPRINTER_DEV_BRANCH:-master}"
SOURCE_ROOT="$(mktemp -d)"

# build_and_stage
#   Clone a repository branch, build it, and install it both into the staging
#   directory and into /usr/local (so later builds can find it).
# Inputs:
#   $1 - repository name under git.grammatech.com/rewriting
#   $2 - branch to clone
#   $@ - (remaining) extra CMake arguments
# Outputs:
#   Installed files under $GTIRB_DEV_STAGING/usr/local and /usr/local
build_and_stage() {
  local repo_name="$1"
  local branch="$2"
  shift 2
  local source_dir="$SOURCE_ROOT/$repo_name"

  git clone --depth 1 -b "$branch" \
    "https://git.grammatech.com/rewriting/$repo_name.git" "$source_dir"
  cmake -S "$source_dir" -B "$source_dir/build" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
    "$@"
  cmake --build "$source_dir/build" -j8
  DESTDIR="$GTIRB_DEV_STAGING" cmake --install "$source_dir/build"
  cmake --install "$source_dir/build"
}

if [[ -d "$GTIRB_DEV_STAGING/usr/local" ]]; then
  echo "Installing staged GTIRB from $GTIRB_DEV_STAGING"
  cp -a "$GTIRB_DEV_STAGING/usr/local/." /usr/local/
else
  echo "Building GTIRB branch $GTIRB_DEV_BRANCH from source"
  build_and_stage gtirb "$GTIRB_DEV_BRANCH" \
    -DGTIRB_ENABLE_TESTS=OFF \
    -DGTIRB_PY_API=OFF \
    -DGTIRB_CL_API=OFF \
    -DGTIRB_JAVA_API=OFF \
    -DGTIRB_DOCUMENTATION=OFF \
    -DGTIRB_RUN_CLANG_TIDY=OFF
  build_and_stage gtirb-pprinter "$GTIRB_PPRINTER_DEV_BRANCH"
fi

ldconfig
rm -rf "$SOURCE_ROOT"
