## Installation

There are a number of options to install a pre-built copy of ddisasm:

* Docker image published to Docker Hub
* Ubuntu apt packages published to the GTIRB apt repository
* .zip archives of the Windows build published to the GrammaTech fileserver

These options offer `stable` and `unstable` variants. It is critical to
install a consistent set of tools, using tools that are all `stable` or all
`unstable`; a mix of `stable` and `unstable` tools will likely not work. The
`stable` versions are recommended for most users. The `unstable` versions
reflect the latest state of the development branch, and may include bugs and
unannounced breaking changes.

Note that installing the `gtirb` Python package from pip yields a `stable`
package, which will only work with corresponding `stable` versions of ddisasm;
see the [GTIRB README](https://github.com/GrammaTech/gtirb/#python-api) for
more details.

### Docker

The Docker image is the easiest way to download and try ddisasm quickly.

* `grammatech/ddisasm:latest` - the latest stable version
* `grammatech/ddisasm:unstable` - the latest unstable version
* `grammatech/ddisasm:1.5.7` - a specific release of ddisasm

Explore the available docker tags [here](https://hub.docker.com/r/grammatech/ddisasm)

### Ubuntu

Packages for Ubuntu 20 are available in the GTIRB apt repository and may
be installed per the following instructions.

First, add GrammaTech's APT key.
```sh
wget -O - https://download.grammatech.com/gtirb/files/apt-repo/conf/apt.gpg.key | apt-key add -
```

Next update your sources.list file.
```sh
echo "deb https://download.grammatech.com/gtirb/files/apt-repo [distribution] [component]"| sudo tee -a /etc/apt/sources.list
```
Where:
- `[distribution]` is `focal` (currently, only Ubuntu 20 packages are available)
- `[component]` is either `stable`, which holds the last versioned release, or
`unstable`, which holds the HEAD of the repository.

Finally update your package database and install the core GTIRB tools:
```sh
sudo apt-get update
sudo apt-get install gtirb-pprinter ddisasm
```
**Warning**:  There is a problem with the packages in the stable repository
that will cause conflicts if you try `apt-get upgrade`.  In this case,
uninstall and reinstall the packages you got from the GTIRB repository.  You
may need to use `dpkg --remove` to remove the metapackages (e.g. `ddisasm`)
before removing the concrete versioned packages (e.g. `ddisasm-1.5.1`).

### Windows

Windows releases are packaged as .zip files and are available
[here](https://download.grammatech.com/gtirb/files/windows-release/).
