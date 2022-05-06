#!/usr/bin/env python
import subprocess
import sys
import conanfile


def run_conan(args):
    cmd = ["conan"] + args
    print("running: %s" % " ".join(cmd))
    sys.stdout.flush()
    subprocess.check_call(cmd)


def build(argv):
    props = conanfile.Properties()
    run_conan(["create", "--keep-source", ".", props.conan_ref] + argv)
    run_conan(["upload", props.conan_recipe, "--all", "--remote", "gitlab"])


if __name__ == "__main__":
    if len(sys.argv) > 1:
        build(sys.argv[1:])
    else:
        build([])
