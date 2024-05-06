# Rewriting hello world



## Disassemble


Ddisasm can be used to disassemble a binary into the [GTIRB](https://github.com/grammatech/gtirb) representation:

``` bash
ddisasm examples/ex1/ex --ir ex.gtirb
```


## Transform (optional)

Once you have the GTIRB representation, you can make programmatic changes to the
binary using [GTIRB](https://github.com/grammatech/gtirb) or [gtirb-rewriting](https://github.com/grammatech/gtirb-rewriting).
Take a look at [GTIRB's Documentation](https://grammatech.github.io/gtirb/)
and [gtirb-rewriting's Documentation](https://github.com/GrammaTech/gtirb-rewriting/blob/main/doc/Getting-Started.md)
for information about how to examine and transform GTIRB files.


## Reassemble

Once you have made changes to the GTIRB, you can use [gtirb-pprinter](https://github.com/grammatech/gtirb-pprinter) to produce
a new version of the binary:

```bash
gtirb-pprinter ex.gtirb -b ex_rewritten
```

Internally, `gtirb-pprinter` will generate an assembly file and invoke the compiler/assembler (e.g. gcc)
to produce a new binary. `gtirb-pprinter` will take care or generating all the necessary command line
options to generate a new binary, including compilation options, library dependencies, or version linker scripts.

You can also use `gtirb-pprinter` to generate an assembly listing for manual modification:

```bash
gtirb-pprinter ex.gtirb --asm ex.s
```

This assembly listing can then be manually recompiled:

```bash
gcc -nostartfiles ex.s -o ex_rewritten
```

## Run

You can run the rewritten program now:

```
./ex_rewritten
```


Congratulations!
