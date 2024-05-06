import argparse
import contextlib
import gtirb
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from timeit import default_timer as timer
from typing import Collection, List, Optional

import platform

import asm_db
import check_gtirb


class bcolors:
    """
    Define some colors for printing in the terminal
    """

    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"

    @classmethod
    def okblue(cls, *args):
        return cls.OKBLUE + " ".join(args) + cls.ENDC

    @classmethod
    def okgreen(cls, *args):
        return cls.OKGREEN + " ".join(args) + cls.ENDC

    @classmethod
    def warning(cls, *args):
        return cls.WARNING + " ".join(args) + cls.ENDC

    @classmethod
    def fail(cls, *args):
        return cls.FAIL + " ".join(args) + cls.ENDC


@contextlib.contextmanager
def get_target(binary, strip_exe, strip, sstrip, extra_strip_flags=None):
    if strip:
        print("# stripping binary\n")
        stripped_binary = binary.with_suffix(".stripped")
        shutil.copy(binary, stripped_binary)
        binary = stripped_binary

        cmd = build_chroot_wrapper() + [
            strip_exe,
            "--strip-unneeded",
            stripped_binary,
        ]
        if extra_strip_flags:
            cmd.extend(extra_strip_flags)

        completed_process = subprocess.run(cmd)
        if completed_process.returncode != 0:
            print(bcolors.fail("# strip failed\n"))
            binary = None
    if sstrip:
        print("# stripping sections\n")
        sstripped_binary = binary.with_suffix(".sstripped")
        shutil.copy(binary, sstripped_binary)
        binary = sstripped_binary

        completed_process = subprocess.run(
            build_chroot_wrapper() + ["sstrip", sstripped_binary]
        )
        if completed_process.returncode != 0:
            print(bcolors.fail("# sstrip failed\n"))
            binary = None
    try:
        yield binary
    finally:
        if strip:
            stripped_binary.unlink(missing_ok=True)
        if sstrip:
            sstripped_binary.unlink(missing_ok=True)


@contextlib.contextmanager
def cd(new_dir):
    prev_dir = os.getcwd()
    os.chdir(str(new_dir))
    try:
        yield
    finally:
        os.chdir(prev_dir)


def resolve_chroot_root(chroot: str) -> str:
    """Get the root path for a chroot"""
    if not chroot:
        return None

    schroot_result = subprocess.run(
        ["schroot", "--location", "--chroot", chroot],
        capture_output=True,
        encoding="utf-8",
    )
    chroot_root_path = schroot_result.stdout.strip()
    return chroot_root_path


# These chroot options support running the end-to-end tests in OS chroots in
# the nightly tests.
MAKE_CHROOT = os.getenv("E2E_MAKE_CHROOT", None)
MAKE_CHROOT_ROOT = resolve_chroot_root(MAKE_CHROOT)


def build_chroot_wrapper() -> List[str]:
    """Build command for executing in the configured chroot"""
    if MAKE_CHROOT:
        chroot_cwd_path = os.path.relpath(os.getcwd(), MAKE_CHROOT_ROOT)
        wrapper = [
            "schroot",
            "--chroot",
            MAKE_CHROOT,
            "--directory",
            chroot_cwd_path,
            "--preserve-environment",
            "--",
        ]
    else:
        wrapper = []
    return wrapper


def make(target="") -> List[str]:
    target = [] if target == "" else [target]

    if platform.system() == "Linux":
        return build_chroot_wrapper() + ["make", "-e"] + target
    elif platform.system() == "Windows":
        return ["nmake", "/E", "/F", "Makefile.windows"] + target
    else:
        raise Exception(f"Unsupported platform {platform.system()}")


def quote_args(*args):
    return " ".join(shlex.quote(arg) for arg in args)


def compile(
    compiler,
    cxx_compiler,
    optimizations,
    extra_flags,
    exec_wrapper=None,
    arch=None,
):
    """
    Clean the project and compile it using the compiler
    'compiler', the cxx compiler 'cxx_compiler' and the flags in
    'optimizations' and 'extra_flags'
    """
    # Copy the current environment and modify the copy.
    env = dict(os.environ)
    env["CC"] = compiler
    env["CXX"] = cxx_compiler
    env["CFLAGS"] = quote_args(optimizations, *extra_flags)
    env["CXXFLAGS"] = quote_args(optimizations, *extra_flags)
    if exec_wrapper:
        env["EXEC"] = exec_wrapper
    if arch:
        env["TARGET_ARCH"] = arch
    completedProcess = subprocess.run(make("clean"), env=env)
    if completedProcess.returncode == 0:
        completedProcess = subprocess.run(make(), env=env)
    return completedProcess.returncode == 0


@dataclass
class DisassemblyResult:
    process: subprocess.CompletedProcess
    ir_path: Path
    elapsed_time: float

    def ir(self) -> gtirb.IR:
        return gtirb.IR.load_protobuf(self.ir_path)


def disassemble(
    binary: Path,
    output: Optional[Path] = None,
    strip_exe: str = "strip",
    strip: bool = False,
    sstrip: bool = False,
    extra_args: Collection[str] = (),
    extra_strip_flags: Collection[str] = (),
    check=True,
) -> DisassemblyResult:
    """
    Disassemble the binary 'binary', creating `{binary}.gtirb`

    If check=True, raises an exception if disassembly fails.
    """
    if output is None:
        output = binary.with_suffix(".gtirb")

    with get_target(
        binary, strip_exe, strip, sstrip, extra_strip_flags=extra_strip_flags
    ) as target_binary:
        print(f"# Disassembling {target_binary}\n")
        start = timer()
        process = subprocess.run(
            ["ddisasm", target_binary, "--ir", output, "-j", "1"]
            + list(extra_args),
            timeout=300,
            check=check,
        )
        time_spent = timer() - start

    return DisassemblyResult(process, output, time_spent)


def binary_print(
    ir_path: Path,
    binary_path: Path,
    check=True,
    build_object=False,
    extra_flags=(),
    compiler: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """
    Binary-print an IR.

    If check=True, raises an exception if binary-printing fails.
    """
    cmd = [
        "gtirb-pprinter",
        "--dummy-so=no",
        ir_path,
        "--binary",
        binary_path,
    ]

    with contextlib.ExitStack() as stack:
        if MAKE_CHROOT:
            # Generate a script that executes the compiler in the chroot, and
            # instruct gtirb-pprinter to use this script instead of gcc.
            chroot_args = build_chroot_wrapper()
            chroot_args.append(compiler or "gcc")
            chroot_args.append("$@")
            script_content = (
                "#!/bin/bash\n"
                # Copy intermediate files generated by gtirb-pprinter into the
                # chroot tmp directory, so they exist where they are specified
                # by the arguments generated by gtirb-pprinter.
                f"cp -r /tmp {MAKE_CHROOT_ROOT}\n"
                # Run gcc in the chroot.
                f'{" ".join(chroot_args)}\n'
                # gtirb-pprinter creates results in /tmp and then copies to
                # the destination, so we have to copy /tmp files back.
                f"cp -r {MAKE_CHROOT_ROOT}/tmp/* /tmp\n"
                # Clean up the files we created.
                f"rm -r {MAKE_CHROOT_ROOT}/tmp/*\n"
            )

            tmpdir = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            chroot_script = tmpdir / "compile.sh"
            chroot_script.write_text(script_content)
            chroot_script.chmod(chroot_script.stat().st_mode | stat.S_IXUSR)

            cmd.append(f"--use-gcc={chroot_script}")
        elif compiler:
            cmd.append(f"--use-gcc={compiler}")
        if build_object:
            cmd.append("--object")
        for flag in extra_flags:
            cmd.append(f"--compiler-arg={flag}")

        print("# Binary printing", ir_path, "into", binary_path)
        return subprocess.run(
            cmd,
            check=check,
        )


def link(
    linker: str, binary: Path, obj: List[Path], extra_flags: List[str]
) -> bool:
    """Link a reassembled object file into a new binary."""
    print("# Linking", ", ".join(map(str, obj)), "into", binary)
    cmd = (
        build_chroot_wrapper() + [linker] + obj + ["-o", binary] + extra_flags
    )
    print("link command:", " ".join(map(str, cmd)))
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        print(bcolors.fail("# Linking failed\n"))
        return False
    print(bcolors.okgreen("# Linking succeed"))
    return True


def test(
    compiler: Optional[str] = None, exec_wrapper: Optional[str] = None
) -> bool:
    """
    Test the project with  'make check'.
    """
    print("# testing\n")
    env = dict(os.environ)
    if compiler:
        env["CC"] = compiler
    if exec_wrapper:
        env["EXEC"] = exec_wrapper
    completedProcess = subprocess.run(make("check"), env=env, timeout=60)
    if completedProcess.returncode != 0:
        print(bcolors.fail("# Testing FAILED\n"))
        return False
    else:
        print(bcolors.okgreen("# Testing SUCCEED\n"))
        return True


def asm_print(ir_path: Path, asm_path: Path) -> subprocess.CompletedProcess:
    """
    Print assembly from `ir_path`.

    Expects a single-module IR.
    """
    return subprocess.run(
        [
            "gtirb-pprinter",
            ir_path,
            "--asm",
            asm_path,
        ]
    )


def disassemble_reassemble_test(
    make_dir,
    binary,
    extra_compile_flags=[],
    extra_reassemble_flags=(),
    extra_link_flags=[],
    reassembly_compiler=None,
    c_compilers=["gcc", "clang"],
    cxx_compilers=["g++", "clang++"],
    optimizations=["-O0", "-O1", "-O2", "-O3", "-Os"],
    linker=None,
    strip_exe="strip",
    strip=False,
    sstrip=False,
    skip_test=False,
    skip_reassemble=False,
    exec_wrapper=None,
    arch=None,
    extra_ddisasm_flags=[],
    cfg_checks=None,
    upload=True,
):
    """
    Disassemble, reassemble and test an example with the given compilers and
    optimizations.
    """
    assert len(c_compilers) == len(cxx_compilers)
    error_count = 0
    binary_path = Path(binary)

    with cd(make_dir):

        for compiler, cxx_compiler in zip(c_compilers, cxx_compilers):
            for optimization in optimizations:
                print(
                    bcolors.okblue(
                        "Project",
                        str(make_dir),
                        "with",
                        compiler,
                        "and",
                        optimization,
                        *extra_compile_flags,
                    )
                )
                if not compile(
                    compiler,
                    cxx_compiler,
                    optimization,
                    extra_compile_flags,
                    exec_wrapper,
                    arch,
                ):
                    error_count += 1
                    continue

                ir_path = binary_path.with_name(binary_path.name + ".gtirb")
                disassemble_result = disassemble(
                    binary_path,
                    ir_path,
                    strip_exe=strip_exe,
                    strip=strip,
                    sstrip=sstrip,
                    extra_args=extra_ddisasm_flags,
                    check=False,
                )

                print(f"Time: {disassemble_result.elapsed_time}s")

                if disassemble_result.process.returncode == 0:
                    print(bcolors.okgreen("Disassembly succeed"))
                    # Do some GTIRB checks
                    module = disassemble_result.ir().modules[0]
                    error_count += check_gtirb.run_checks(
                        module, cfg_checks or []
                    )

                    # Print assembly source (for upload to database, but
                    # always print to catch errors)
                    asm_path = Path(binary + ".s")
                    asm_print_result = asm_print(ir_path, asm_path)
                    if asm_print_result.returncode != 0:
                        print(bcolors.fail("Printing assembly failed"))
                        error_count += 1
                        continue
                    elif upload:
                        print(bcolors.okgreen("Printing assembly succeed"))
                        # upload to assembly database
                        asm_db.upload(
                            os.path.basename(make_dir),
                            asm_path,
                            [compiler, cxx_compiler],
                            [optimization] + extra_compile_flags,
                            strip,
                        )

                else:
                    print(bcolors.fail("Disassembly failed"))
                    error_count += 1
                    continue

                if linker:
                    binary_print_path = binary_path.with_suffix(".o")
                else:
                    binary_print_path = binary_path

                if not skip_reassemble:
                    binary_print_result = binary_print(
                        ir_path,
                        binary_print_path,
                        check=False,
                        compiler=reassembly_compiler,
                        build_object=bool(linker),
                        extra_flags=extra_reassemble_flags,
                    )
                    if binary_print_result.returncode != 0:
                        error_count += 1
                        continue

                if linker and not link(
                    linker,
                    # strip .o suffix for e.g. binary "ex.o" or "ex.exe.o"
                    binary_path.with_suffix("")
                    if binary_path.suffix == ".o"
                    else binary_path,
                    [binary_print_path],
                    extra_link_flags,
                ):
                    error_count += 1
                    continue
                if skip_test or skip_reassemble:
                    print(bcolors.warning(" No testing"))
                    continue
                if not test(reassembly_compiler, exec_wrapper):
                    error_count += 1
    return error_count == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Disassemble reassemble and test a project with ddisasm"
    )
    parser.add_argument("make_dir", help="project to test")
    parser.add_argument("binary", help="binary within the project")
    parser.add_argument("--extra_compile_flags", nargs="*", type=str)
    parser.add_argument("--extra_reassemble_flags", nargs="*", type=str)
    parser.add_argument("--extra_link_flags", nargs="*", type=str)
    parser.add_argument("--reassembly_compiler", type=str, default="gcc")
    parser.add_argument("--c_compilers", nargs="*", type=str)
    parser.add_argument("--cxx_compilers", nargs="*", type=str)
    parser.add_argument("--optimizations", nargs="*", type=str)
    parser.add_argument("--strip_exe", type=str, default="strip")
    parser.add_argument(
        "--strip",
        help="strip binaries before disassembling",
        action="store_true",
    )
    parser.add_argument(
        "--sstrip",
        help="strip sections before disassembling",
        action="store_true",
    )
    parser.add_argument(
        "--skip_test", help="skip testing", action="store_true"
    )
    parser.add_argument(
        "--skip_reassemble", help="skip reassemble", action="store_true"
    )

    args = parser.parse_args()
    disassemble_reassemble_test(
        **{k: v for k, v in args.__dict__.items() if v is not None}
    )
