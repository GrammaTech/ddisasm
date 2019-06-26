FROM ubuntu:16.04 as souffle
RUN apt-get -y update && apt-get -y install automake bison build-essential \
    doxygen flex g++ gcc gcc-multilib g++-multilib git libtool make mcpp \
    pkg-config  sqlite3 libsqlite3-dev zlib1g-dev libffi-dev
RUN git clone -b 1.5.1 https://github.com/souffle-lang/souffle
RUN cd souffle && sh ./bootstrap
RUN cd souffle && ./configure --prefix=/usr --enable-64bit-domain --disable-provenance
RUN cd souffle && make -j4 install
RUN cd souffle && cp include/souffle/RamTypes.h /usr/include/souffle/

FROM ubuntu:16.04

ARG CMAKE_VERSION=3.9
ARG CXX_COMPILER=g++-7

# Copy souffle
RUN apt-get -y update && \
    apt-get -y install software-properties-common && \
    add-apt-repository ppa:jonathonf/gcc-7.1 && \
    apt-get -y update
RUN apt-get -y update && apt-get -y install autoconf automake bison build-essential clang \
    doxygen flex g++ gcc gcc-multilib g++-multilib git libtool make mcpp pkg-config \
    sqlite3 libsqlite3-dev zlib1g-dev clang ed libpcre3-dev libncurses5-dev wget \
    curl libc++1 libc++abi1 gcc-7 g++-7

COPY --from=souffle /usr/bin/souffle-compile /usr/bin/souffle-compile
COPY --from=souffle /usr/bin/souffle-config /usr/bin/souffle-config
COPY --from=souffle /usr/bin/souffle /usr/bin/souffle
COPY --from=souffle /usr/bin/souffle-profile /usr/bin/souffle-profile
COPY --from=souffle /usr/include/souffle/ /usr/include/souffle

# Fix symlinks for libc++/libc++abi.
RUN ln -s libc++.so.1 /usr/lib/x86_64-linux-gnu/libc++.so
RUN ln -s libc++abi.so.1 /usr/lib/x86_64-linux-gnu/libc++abi.so

# We use clang to build examples during testing. But clang 3.8 is not
# compatible with the gcc-7 headers. So we need to work around this
RUN mv /usr/bin/clang++ /usr/bin/clang++.real
RUN printf "#\!/bin/sh\nclang++.real --gcc-toolchain=/usr/lib/gcc/x86_64-linux-gnu/5.4.0 -L/usr/lib/gcc/x86_64-linux-gnu/5.4.0/ -I/usr/include/c++/5/ -I/usr/include/x86_64-linux-gnu/c++/5/ \$*\n" > /usr/bin/clang++
RUN chmod a+x /usr/bin/clang++
RUN ln -s /usr/lib/gcc/x86_64-linux-gnu/5/crtbegin.o /usr/lib/x86_64-linux-gnu/
RUN ln -s /usr/lib/gcc/x86_64-linux-gnu/5/crtend.o /usr/lib/x86_64-linux-gnu/


# Install CMake
RUN curl -SL https://cmake.org/files/v$CMAKE_VERSION/cmake-$CMAKE_VERSION.0-Linux-x86_64.tar.gz \
    |tar -xz --strip-components=1 -C /usr/local

RUN ldconfig

# Install capstone
RUN cd /usr/local/src \
    && wget https://github.com/aquynh/capstone/archive/4.0.1.tar.gz \
    && tar xf 4.0.1.tar.gz \
    && cd capstone-4.0.1 \
    && CAPSTONE_ARCHS=x86 ./make.sh \
    && CAPSTONE_ARCHS=x86 ./make.sh install

COPY . /ddisasm

# Build GTIRB
RUN rm -rf /ddisasm/gtirb/build /ddisasm/gtirb/CMakeCache.txt /ddisasm/gtirb/CMakeFiles /ddisasm/gtirb/CMakeScripts
RUN cd /ddisasm/gtirb/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER}  && cd build &&  make

# Build gtirb-pprinter
RUN rm -rf /ddisasm/gtirb-pprinter/build /ddisasm/gtirb-pprinter/CMakeCache.txt /ddisasm/gtirb-pprinter/CMakeFiles /ddisasm/gtirb-pprinter/CMakeScripts
RUN cd /ddisasm/gtirb-pprinter/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} && cd build &&  make

# Build ddisasm
ENV TERM xterm
RUN rm -rf /ddisasm/build /ddisasm/CMakeCache.txt /ddisasm/CMakeFiles /ddisasm/CMakeScripts
WORKDIR /ddisasm
RUN cmake ./  -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} -DCORES=8 && cd build && make
ENV PATH=/ddisasm/build/bin:$PATH
