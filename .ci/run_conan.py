#!/usr/bin/env python
import subprocess
import conanfile
import sys


def run_conan(args):
    cmd = ["conan"] + args
    print("running: %s" % " ".join(cmd))
    sys.stdout.flush()
    subprocess.check_call(cmd)


def build(argv):
    props = conanfile.Properties()
    run_conan(["create", "--keep-source", ".", props.conan_ref] + argv)


def upload():
    props = conanfile.Properties()
    run_conan(["upload", props.conan_recipe, "--all", "--remote", "gitlab"])


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "upload":
            upload()
        elif sys.argv[1] == "build":
            build(sys.argv[2:])
        else:
            print("Unrecognized arguments")
            sys.exit(1)
