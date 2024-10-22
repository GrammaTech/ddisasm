
# Building Ddisasm

## Dependencies

Ddisasm uses C++17, and requires a compiler which supports
that standard such as gcc 9, clang 6, or MSVC 2017.

To build Ddisasm from source, the following requirements should be installed:

- [gtirb](https://github.com/grammatech/gtirb) version 1.12.1 or later
- [gtirb-pprinter](https://github.com/grammatech/gtirb-pprinter), version 2.0.0 or later
- [Capstone](http://www.capstone-engine.org/), version 5.0.1 or later
  - GrammaTech builds and tests using the [GrammaTech/capstone](https://github.com/GrammaTech/capstone) fork.
- [Souffle](https://souffle-lang.github.io), version 2.4  with support for 64 bit numbers (via `-DSOUFFLE_DOMAIN_64BIT=1` during configuration)

For linux:
```bash
git clone -b 2.4 https://github.com/souffle-lang/souffle
cd souffle
cmake . -Bbuild -DCMAKE_BUILD_TYPE=Release -DSOUFFLE_USE_CURSES=0 -DSOUFFLE_USE_SQLITE=0 -DSOUFFLE_DOMAIN_64BIT=1
cd build
make install -j4
```

- [libehp](https://git.zephyr-software.com/opensrc/libehp) or GrammaTech's [mirror](https://github.com/GrammaTech/libehp), version 1.0.0 or higher
- [LIEF](https://lief.quarkslab.com/), version 0.13.2 or higher

Our [Dockerfile](https://github.com/GrammaTech/ddisasm/blob/main/Dockerfile)
is a good reference of how all the dependencies can be installed.

Note that these versions are newer than what your package manager may provide
by default: This is true on Ubuntu 20, Debian 10, and others. Prefer building
these dependencies from sources to avoid versioning problems. Alternatively,
you can use the GrammaTech PPA to get the correct versions of the dependencies.
See the [GTIRB readme](https://github.com/GrammaTech/gtirb/#installing) for
instructions on using the GrammaTech PPA.

## Building ddisasm
Use the following options to configure cmake:

- You can tell CMake which compiler to use with
  `-DCMAKE_CXX_COMPILER=<compiler>`.

- You can tell CMake about the paths to its dependencies as follows:

| Option               | Description                                 |
|----------------------|---------------------------------------------|
| `gtirb_DIR`          | Path to the GTIRB build directory.          |
| `gtirb_pprinter_DIR` | Path to the gtirb-pprinter build directory. |
| `LIEF_DIR`           | Path to the LIEF build directory.           |

- ddisasm can make use of GTIRB in static library form (instead of
 shared library form, the default) if you use the flag
 `-DDDISASM_BUILD_SHARED_LIBS=OFF`.

- You can tell CMake to use ccache with the flag
  `-DCMAKE_CXX_COMPILER_LAUNCHER=ccache`. This is especially useful
  when Souffle is configured to generate multiple files.

- For development, you can ask Souffle to generate multiple files per
  target with `-DDDISASM_GENERATE_MANY=ON`. This results in a slower
  initial build time, but recompilation will be faster.

Once the dependencies are installed, you can configure and build as
follows:

```
$ cmake ./ -Bbuild
$ cd build
$ make
```

When using `-DDDISASM_GENERATE_MANY=ON`, it is safe to aggressively
parallelize the build (e.g. `-j$(nproc)`). This is not recommended
otherwise, as memory usage by the compiler is high.

### Debug build options

One can selectively turn off ddisasm's various architecture support modules to speed up compilation time during development.
For example:
```
$ cmake ./ -Bbuild -DDDISASM_ARM_64=OFF -DDDISASM_X86_32=OFF
```
will deactivate ARM_64 and X86_32 support.
