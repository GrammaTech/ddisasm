FROM archlinux/base as souffle
RUN sed -i 's/#\[multilib\]/\[multilib\]/; /^\[multilib\]/,/^$/ s/^#//' /etc/pacman.conf
RUN pacman --noconfirm -Syu archlinux-keyring
RUN pacman -Syu --noconfirm git autoconf automake bison doxygen flex fakeroot sqlite \
    libtool make pkg-config zlib mcpp gcc gcc-multilib lib32-fakeroot lib32-gcc-libs lib32-libltdl
# Enable makepkg as root.
RUN sed -i "s/^\(OPT_LONG=(\)/\1'asroot' /;s/EUID == 0/1 == 0/" /usr/bin/makepkg
RUN mkdir -p /aur/souffle
COPY .ci/PKGBUILD /aur/souffle
RUN cd /aur/souffle && makepkg --asroot --noconfirm -si

FROM archlinux/base

ARG CMAKE_VERSION=3.9
ARG CXX_COMPILER=g++

RUN sed -i 's/#\[multilib\]/\[multilib\]/; /^\[multilib\]/,/^$/ s/^#//' /etc/pacman.conf
RUN pacman --noconfirm -Syu archlinux-keyring
RUN pacman -Syu --noconfirm git autoconf automake bison doxygen flex fakeroot sqlite libtool \
    make pkg-config zlib mcpp gcc gcc-multilib lib32-fakeroot lib32-gcc-libs lib32-libltdl \
    clang gdb ed cmake wget which

COPY --from=souffle /usr/bin/souffle-compile /usr/bin/souffle-compile
COPY --from=souffle /usr/bin/souffle-config /usr/bin/souffle-config
COPY --from=souffle /usr/bin/souffle /usr/bin/souffle
COPY --from=souffle /usr/bin/souffle-profile /usr/bin/souffle-profile
COPY --from=souffle /usr/include/souffle/ /usr/include/souffle

# Install capstone
RUN cd /usr/local/src \
#   && git clone https://github.com/aquynh/capstone \
#   && cd capstone \
    && wget https://github.com/aquynh/capstone/archive/4.0.1.tar.gz \
    && tar xf 4.0.1.tar.gz \
    && cd capstone-4.0.1 \
    && CAPSTONE_ARCHS=x86 ./make.sh \
    && CAPSTONE_ARCHS=x86 ./make.sh install

COPY . /ddisasm

# Build GTIRB
RUN rm -rf /ddisasm/gtirb/build /ddisasm/gtirb/CMakeCache.txt /ddisasm/gtirb/CMakeFiles /ddisasm/gtirb/CMakeScripts
RUN cd /ddisasm/gtirb/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} && cd build &&  make

# Build gtirb-pprinter
RUN rm -rf /ddisasm/gtirb-pprinter/build /ddisasm/gtirb-pprinter/CMakeCache.txt /ddisasm/gtirb-pprinter/CMakeFiles /ddisasm/gtirb-pprinter/CMakeScripts
RUN cd /ddisasm/gtirb-pprinter/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER}  && cd build &&  make

# Build ddisasm
ENV TERM xterm
RUN rm -rf /ddisasm/build /ddisasm/CMakeCache.txt /ddisasm/CMakeFiles /ddisasm/CMakeScripts
WORKDIR /ddisasm
RUN cmake ./  -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} -DCORES=8 && cd build && make
ENV PATH=/ddisasm/build/bin:$PATH
