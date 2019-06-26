FROM ubuntu:18.04 as souffle
RUN apt-get -y update && apt-get -y install automake bison build-essential \
    doxygen flex git libtool make mcpp pkg-config sqlite3 libsqlite3-dev \
    zlib1g-dev libffi-dev
RUN git clone -b 1.5.1 https://github.com/souffle-lang/souffle
RUN cd souffle && sh ./bootstrap
RUN cd souffle && ./configure --prefix=/usr --enable-64bit-domain --disable-provenance
RUN cd souffle && make -j4 install
RUN cd souffle && cp include/souffle/RamTypes.h /usr/include/souffle/

FROM ubuntu:18.04

ARG CMAKE_VERSION=3.9
ARG CXX_COMPILER=g++-7

RUN apt-get -y update && apt-get -y install autoconf automake bison build-essential clang \
    doxygen flex git libtool make mcpp pkg-config python sqlite3 libsqlite3-dev zlib1g-dev \
    ed libpcre3-dev libncurses5-dev wget curl cmake

COPY --from=souffle /usr/bin/souffle-compile /usr/bin/souffle-compile
COPY --from=souffle /usr/bin/souffle-config /usr/bin/souffle-config
COPY --from=souffle /usr/bin/souffle /usr/bin/souffle
COPY --from=souffle /usr/bin/souffle-profile /usr/bin/souffle-profile
COPY --from=souffle /usr/include/souffle/ /usr/include/souffle

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
RUN cd /ddisasm/gtirb/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} && cd build &&  make

# Build gtirb-pprinter
RUN rm -rf /ddisasm/gtirb-pprinter/build /ddisasm/gtirb-pprinter/CMakeCache.txt /ddisasm/gtirb-pprinter/CMakeFiles /ddisasm/gtirb-pprinter/CMakeScripts
RUN cd /ddisasm/gtirb-pprinter/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} && cd build &&  make

# Build ddisasm
ENV TERM xterm
RUN rm -rf /ddisasm/build /ddisasm/CMakeCache.txt /ddisasm/CMakeFiles /ddisasm/CMakeScripts
WORKDIR /ddisasm
RUN cmake ./  -Bbuild -DCMAKE_CXX_COMPILER=${CXX_COMPILER} -DCORES=8 && cd build && make
ENV PATH=/ddisasm/build/bin:$PATH
