from conans import ConanFile, CMake, tools
from conans.errors import ConanInvalidConfiguration
import os
import re


def get_version():
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
    if branch == "master":
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
            "A pretty printer from the GTIRB intermediate representation "
            "for binary analysis and reverse engineering to gas-syntax "
            "assembly code."
        )

    @property
    def url(self):
        return "https://git.grammatech.com/%s" % self.rel_url

    @property
    def conan_channel(self):
        channel = "local"
        if "CI_COMMIT_BRANCH" in os.environ:
            branch = os.environ["CI_COMMIT_BRANCH"]
            channel = branch_to_channel(branch)
        return channel

    # Add to this list branch names to have conan packages for
    # branches archived in gitlab.
    @property
    def archived_channels(self):
        archived_branches = ["master", "windows-support"]
        return list(map(branch_to_channel, archived_branches))

    @property
    def conan_ref(self):
        return "%s/%s" % (self.rel_url.replace("/", "+"), self.conan_channel)

    @property
    def conan_recipe(self):
        return "%s/%s@%s" % (self.name, self.version, self.conan_ref)


class GtirbPprinterConan(Properties, ConanFile):
    boost_version = "1.69.0"
    gtirb_version = "1.10.1"
    gtirb_pprinter_version = "1.5.1"
    capstone_version = "4.0.1"
    requires = (
        "boost/%s@conan/stable" % (boost_version),
        "gtirb/%s@rewriting+gtirb/stable" % (gtirb_version),
        "gtirb-pprinter/%s@rewriting+gtirb-pprinter/stable" % (gtirb_pprinter_version),
        "capstone/%s@rewriting+extra-packages/next" % (capstone_version),
    )
    lief_version = "0.10.1"
    libehp_version = "0.1.1"
    build_requires = (
        "libehp/%s@rewriting+extra-packages/stable" % (libehp_version),
        "lief/%s" % (lief_version)
    )
    author = "GrammaTech Inc."
    generators = "cmake"
    settings = ("os", "compiler", "build_type", "arch")

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

    def build_cmake(self):
        defs = {"CMAKE_VERBOSE_MAKEFILE:BOOL": "ON", "ENABLE_CONAN:BOOL": "ON"}
        if self.settings.os == "Windows":
            cmake = CMake(self, generator="Ninja")
            defs.update({k: os.environ.get(k) for k in ["CMAKE_PREFIX_PATH"]})
            defs["Boost_USE_STATIC_LIBS"] = "ON"
        else:
            cmake = CMake(self, generator=None)
            defs.update(
                {
                    "CMAKE_CXX_COMPILER": "g++-7",
                    "GTIRB_PPRINTER_STRIP_DEBUG_SYMBOLS:BOOL": "ON",
                }
            )

        cmake.configure(source_folder=".", defs=defs)
        cmake.build()
        cmake.test(output_on_failure=True)
        cmake.install()
        # The patch_config_paths() function will change absolute paths in the
        # exported cmake config files to use the appropriate conan variables
        # instead.
        # It is an experimental feature of conan, however, so if you're having
        # trouble with paths in the cmake of the conan package, it could that
        # this function is no longer doing what we want.
        cmake.patch_config_paths()

    def build_requirements(self):
        if self.settings.os == "Windows":
            self.build_requires("ninja_installer/1.9.0@bincrafters/stable")

    def package(self):
        self.copy("*.h", dst="include", src=self.name)
        self.copy("*%s.lib" % (self.name), dst="lib", keep_path=False)
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = [self.name]
