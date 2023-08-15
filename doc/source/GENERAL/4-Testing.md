## Testing

### Prerequisites

The tests that are run will depend on your platform. On Linux, only linux tests
will be run, whereas on Windows, only Windows tests will be run.

Linux tests include test of:

- Binaries of multiple ISAs
- Windows binaries compiled with mingw and run with Wine

That means that in order to run the test, you need to install a few dependencies:

1. GCC and Clang
2. GCC cross compilers for:
    - arm
    - aarch64
    - mips

3. Wine and mingw and uasm

Take a look at [how we build our testing environment](https://github.com/GrammaTech/ddisasm/blob/main/.ci/Dockerfile.ubuntu20#L88) for an exhaustive list.


### Running the Tests

To run the test suite, run:

```
cd build && PATH=$(pwd)/bin:$PATH ctest
```
