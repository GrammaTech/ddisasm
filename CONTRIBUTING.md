# Contributing

## Code of Conduct

Please read the [DDisasm Code of Conduct](CODE_OF_CONDUCT.md).

## Contributor License Agreement

We ask that all contributors complete our Contributor License
Agreement (CLA), which can be found at
[GrammaTech-CLA-ddisasm.pdf](./GrammaTech-CLA-ddisasm.pdf),
and email the completed form to `CLA@GrammaTech.com`.  Under this
agreement contributors retain the copyright to their work but grants
GrammaTech unlimited license to the work.

## Code Requirements

Please follow the Code Requirements in
[gtirb/CONTRIBUTING](https://github.com/GrammaTech/gtirb/blob/master/CONTRIBUTING.md#code-requirements).

# Developer's Guide

This section outlines information useful for developers interested in
contributing to ddisasm.

## Souffle interpreter

For accelerated development of datalog logic, ddisasm can also execute the
Souffle interpreter. To invoke the interpreter, specify a `--debug-dir`
directory path and the `--intepreter` parameter with the path of ddisasm's
datalog entry.

For example:
```
$ cd ddisasm/examples/ex1
$ make
$ mkdir dbg
$ ddisasm --debug-dir dbg --interpreter ../../src/datalog/main.dl --asm ex.s ex
```

## Profiling

Maintaining ddisasm's high performance for disassembling binaries, both large
and small, is an important goal of the project. Profiling new contributions is
a necessary step to ensure they do not introduce performance regressions.

To assist with this, ddisasm can execute
[Souffle's profiler](https://souffle-lang.github.io/profiler) by passing
`--profile` argument, specifing the file path of the generated profile
log file.

For the default configuration of ddisasm, `--profile` can only be used
along with `--interpreter`. For example:

```
$ ddisasm --debug-dir dbg --interpreter src/datalog/main.dl --profile ddisasm.prof --asm ex.s examples/ex1/ex
```

Profiling with the interpreter is relatively slow, however. As an
alternative, ddisasm can be compiled with profiling support by passing
`-DDDISASM_SOUFFLE_PROFILING=ON` to cmake. In this case, the
`--interpreter` argument should be omitted.

This generates `ddisasm.prof`, which can be used with `souffleprof` to generate a HTML report:

```
$ souffleprof -j ddisasm.prof
SouffleProf
Generating HTML files...
file output to: profiler_html/1.html
```
