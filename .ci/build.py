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
    archived_channels = props.archived_channels
    if props.conan_channel in archived_channels:
        run_conan(
            ["upload", props.conan_recipe, "--all", "--remote", "gitlab"]
        )
    else:
        print(
            "Conan channel not archived. Update archived_branches in "
            "conanfile.py to get archival."
        )
        print("archived channels: ")
        print(*archived_channels, sep=", ")
        print("channel built: " + props.conan_channel)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        build(sys.argv[1:])
    else:
        build([])
