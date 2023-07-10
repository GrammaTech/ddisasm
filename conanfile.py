from conans import ConanFile, CMake, tools
from conans.errors import ConanInvalidConfiguration
import os
import re


def get_version():
    if re.match(r"^release-.*", os.getenv("CI_COMMIT_REF_NAME", "")):
        try:
            with open("version.txt") as f:
                s = f.read()
                match = re.search(
                    r"VERSION_MAJOR(\s+)(\S+)(\s+)"
                    r"VERSION_MINOR(\s+)(\S+)(\s+)"
                    r"VERSION_PATCH(\s+)(\S+)(\s+)",
                    s,
                )
                if match:
                    major = match.group(2)
                    minor = match.group(5)
                    patch = match.group(8)
                    return major + "." + minor + "." + patch
                else:
                    return "<ERROR: no version found>"
        except Exception:
            return None
    else:
        return "dev"


def branch_to_channel(branch):
    if re.match(r"^release-.*", branch):
        return "stable"
    else:
        return branch.replace("/", "+")


class Properties:
    name = "ddisasm"
    version = get_version()
    rel_url = "rewriting/ddisasm"
    exports_sources = "*", "!.conan/*", "!ccache/*"

    @property
    def description(self):
        return (
            "DDisasm is a *fast* disassembler which is accurate enough for the"
            " resulting assembly code to be reassembled."
        )

    @property
    def url(self):
        return "https://git.grammatech.com/%s" % self.rel_url

    @property
    def conan_channel(self):
        channel = "local"
        if "CI_COMMIT_REF_NAME" in os.environ:
            branch = os.environ["CI_COMMIT_REF_NAME"]
            channel = branch_to_channel(branch)
        return channel

    @property
    def conan_ref(self):
        return "%s/%s" % (self.rel_url.replace("/", "+"), self.conan_channel)

    @property
    def conan_recipe(self):
        return "%s/%s@%s" % (self.name, self.version, self.conan_ref)


class DdisasmConan(Properties, ConanFile):
    author = "GrammaTech Inc."
    generators = "cmake"
    settings = ("os", "compiler", "build_type", "arch")
    options = {"run_tests": [True, False, None]}

    lief_version = "0.13.0"
    libehp_version = "0.1.1-gt3"
    souffle_version = "2.4"
    build_requires = (
        "libehp/%s@rewriting+extra-packages/stable" % (libehp_version),
        "lief/%s@rewriting+extra-packages/stable" % (lief_version),
        "souffle/%s@rewriting+extra-packages/stable" % (souffle_version),
    )

    def build_requirements(self):
        if self.settings.os == "Windows":
            self.build_requires("ninja/1.10.2")

    boost_version = "1.69.0"
    gtirb_version = "dev"
    gtirb_pprinter_version = "dev"
    capstone_version = "dev"
    requires = (
        "boost/%s" % (boost_version),
        "gtirb/%s@rewriting+gtirb/master" % (gtirb_version),
        "gtirb-pprinter/%s@rewriting+gtirb-pprinter/master"
        % (gtirb_pprinter_version),
        "capstone/%s@rewriting+extra-packages/next" % (capstone_version),
    )

    def imports(self):
        self.copy("*.dll", "bin", "bin")

    def validate(self):
        if (
            self.settings.compiler == "gcc"
            and self.settings.compiler.libcxx != "libstdc++11"
        ):
            raise ConanInvalidConfiguration(
                (
                    "ddisasm requires libstdc++11 ABI, update your "
                    "conan profile"
                )
            )

    def build(self):
        if self.settings.os == "Windows":
            with tools.vcvars(
                self.settings, force=True, filter_known_paths=False
            ):
                self.build_cmake()
        else:
            self.build_cmake()

    # Puts a dependency's bin path on PATH
    def add_dep_bin_path(self, *deps):
        bin_dirs = sum([self.deps_cpp_info[dep].bin_paths for dep in deps], [])
        new_path = [os.environ.get("PATH", "")] + bin_dirs
        os.environ["PATH"] = os.pathsep.join(new_path)

    # Puts a dependency's lib path on LD_LIBRARY_PATH (for Linux) or PATH (for
    # Windows)
    def add_dep_lib_path(self, *deps):
        lib_dirs = sum([self.deps_cpp_info[dep].lib_paths for dep in deps], [])
        env_var_name = (
            "PATH" if self.settings.os == "Windows" else "LD_LIBRARY_PATH"
        )
        new_value = [os.environ.get(env_var_name, "")] + lib_dirs
        os.environ[env_var_name] = os.pathsep.join(new_value)

    def build_cmake(self):
        defs = {"CMAKE_VERBOSE_MAKEFILE:BOOL": "ON", "ENABLE_CONAN:BOOL": "ON"}
        if self.settings.os == "Windows":
            cmake = CMake(self, generator="Ninja", parallel=False)
            defs.update(
                {
                    k: os.environ.get(k)
                    for k in [
                        "CMAKE_PREFIX_PATH",
                        "PYTHON",
                    ]
                }
            )
            defs["Boost_USE_STATIC_LIBS"] = "ON"
            defs[
                "CMAKE_CXX_FLAGS"
            ] = "/DBOOST_ALL_NO_LIB /DBOOST_UUID_FORCE_AUTO_LINK"
            self.add_dep_lib_path("libffi")
        else:
            cmake = CMake(self, generator=None, parallel=True)
            defs.update(
                {
                    "GTIRB_PPRINTER_STRIP_DEBUG_SYMBOLS:BOOL": "ON",
                    "DDISASM_GENERATE_MANY": "ON",
                }
            )
        revision = os.environ.get("CI_COMMIT_SHORT_SHA")
        if revision:
            defs["DDISASM_BUILD_REVISION"] = revision

        self.add_dep_bin_path("gtirb-pprinter", "mcpp")
        self.add_dep_lib_path("gtirb-pprinter", "gtirb", "capstone")
        bin_dir = os.path.join(os.getcwd(), "bin")
        os.environ["PATH"] = os.pathsep.join([os.environ["PATH"], bin_dir])

        cmake.configure(source_folder=".", defs=defs)
        cmake.build()

        run_tests = (
            self.options.run_tests or self.options.run_tests == None
        )  # noqa: E711

        # Using the CMAKE_CTEST_ARGUMENTS environment variable to pass args to
        # ctest would allow us to use `cmake.test()` and `--verbose`, but it
        # is new in CMake 3.17 (newer than what is available in our Windows
        # test runner). As a workaround, we run ctest directly.
        # https://cmake.org/cmake/help/latest/variable/CMAKE_CTEST_ARGUMENTS.html#cmake-ctest-arguments
        if run_tests:
            with tools.vcvars(self.settings, arch="x86_64"):
                self.run(["ctest", "--verbose"], cwd=cmake.build_folder)
            # FIXME: https://github.com/conan-io/conan/issues/3673
            # Remove environment variable to force vcvars configuration.
            os.environ.pop("VisualStudioVersion", None)
            with tools.vcvars(self.settings, arch="x86"):
                self.run(["ctest", "--verbose"], cwd=cmake.build_folder)

    def package(self):
        self.copy("*", src="bin", dst="bin", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = [self.name]
