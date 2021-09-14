from conans import ConanFile, CMake, tools
from conans.errors import ConanInvalidConfiguration
import os
import re


def get_version():
    if os.getenv("CI_COMMIT_REF_NAME", "") == "master":
        return "dev"
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


def branch_to_channel(branch):
    if re.match(r"^release-.*", branch):
        return "stable"
    else:
        return branch.replace("/", "+")


class Properties:
    name = "ddisasm"
    version = get_version()
    rel_url = "rewriting/ddisasm"
    exports_sources = "*"

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
    def archived_channels(self):
        # Add to this list branch names to have conan packages for
        # branches archived in gitlab.
        archived_branches = ["master", "windows-support"]
        # Also, archive the 'stable' channel, where all stable versions
        # will be uploaded
        archived_channels = ["stable"]
        return archived_channels + list(
            map(branch_to_channel, archived_branches)
        )

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

    lief_version = "0.11.5"
    libehp_version = "dev"
    souffle_version = "2.1"
    build_requires = (
        "libehp/%s@rewriting+extra-packages/stable" % (libehp_version),
        "lief/%s" % (lief_version),
    )

    def build_requirements(self):
        if self.settings.os == "Windows":
            self.build_requires("ninja/1.10.2")
        else:
            self.build_requires(
                "souffle/%s@rewriting+extra-packages/stable"
                % (self.souffle_version)
            )

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

    def configure(self):
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
    def add_dep_bin_path(self, dep):
        bin_dirs = self.deps_cpp_info[dep].bin_paths
        new_path = [os.environ.get("PATH", "")] + bin_dirs
        os.environ["PATH"] = os.pathsep.join(new_path)

    # Puts a dependency's lib path on LD_LIBRARY_PATH
    def add_dep_lib_path(self, *deps):
        lib_dirs = sum([self.deps_cpp_info[dep].lib_paths for dep in deps], [])
        new_ld_lib_path = [os.environ.get("LD_LIBRARY_PATH", "")] + lib_dirs
        os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(new_ld_lib_path)

    def build_cmake(self):
        defs = {"CMAKE_VERBOSE_MAKEFILE:BOOL": "ON", "ENABLE_CONAN:BOOL": "ON"}
        if self.settings.os == "Windows":
            cmake = CMake(self, generator="Ninja")
            defs.update(
                {
                    k: os.environ.get(k)
                    for k in [
                        "CMAKE_PREFIX_PATH",
                        "SOUFFLE_INCLUDE_DIR",
                        "PYTHON",
                    ]
                }
            )
            defs["Boost_USE_STATIC_LIBS"] = "ON"
            defs[
                "CMAKE_CXX_FLAGS"
            ] = "/DBOOST_ALL_NO_LIB /DBOOST_UUID_FORCE_AUTO_LINK"
        else:
            cmake = CMake(self, generator=None)
            defs.update({"GTIRB_PPRINTER_STRIP_DEBUG_SYMBOLS:BOOL": "ON"})
            self.add_dep_bin_path("mcpp")

        if self.settings.build_type == "Release":
            cmake.build_type = "RelWithDebInfo"
        self.add_dep_bin_path("gtirb-pprinter")
        self.add_dep_lib_path("gtirb-pprinter", "gtirb", "capstone")
        bin_dir = os.path.join(os.getcwd(), "bin")
        os.environ["PATH"] = os.pathsep.join([os.environ["PATH"], bin_dir])

        cmake.configure(source_folder=".", defs=defs)
        cmake.build()
        if self.settings.build_type == "Release":
            with tools.vcvars(self.settings, arch="x86"):
                cmake.test(output_on_failure=True)
            with tools.vcvars(self.settings, arch="x86_64"):
                cmake.test(output_on_failure=True)
        cmake.install()

    def package(self):
        self.copy("*.h", dst="include", src=self.name)
        self.copy("*%s.lib" % (self.name), dst="lib", keep_path=False)
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = [self.name]
