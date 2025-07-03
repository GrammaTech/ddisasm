# ------------------------------------------------------------------------------
# Install Souffle
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 AS souffle
RUN export DEBIAN_FRONTEND=noninteractive
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
RUN apt-get -y update \
 && apt-get -y install \
      automake \
      bison \
      build-essential \
      cmake \
      doxygen \
      flex \
      git \
      libffi-dev \
      libsqlite3-dev \
      libtool \
      lsb-release \
      mcpp \
      sqlite3 \
      zlib1g-dev

RUN git clone -b 2.4 https://github.com/souffle-lang/souffle && \
    cd souffle && \
    cmake . -Bbuild -DCMAKE_BUILD_TYPE=Release -DSOUFFLE_USE_CURSES=0 -DSOUFFLE_USE_SQLITE=0 -DSOUFFLE_DOMAIN_64BIT=1 && \
    cd build && \
    make install -j4

# ------------------------------------------------------------------------------
# Install LIEF
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 AS lief

RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime

RUN apt-get -y update && \
    apt-get -y install \
      build-essential \
      cmake \
      git \
      python3 \
      python3-pip \
      wget

# Install CMake 3.24.0 (needed by LIEF 0.16.6)
ENV CMAKE_VERSION=3.24.0
RUN wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz && \
    tar -xzf cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz && \
    mv cmake-${CMAKE_VERSION}-linux-x86_64 /opt/cmake && \
    rm /usr/bin/cmake && \
    ln -s /opt/cmake/bin/cmake /usr/bin/cmake && \
    rm cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz

RUN pip install conan==1.59 && \
    conan profile new default --detect && \
    conan remote add rewriting_remote https://git.grammatech.com/api/v4/packages/conan

ENV LIEF_VERSION="0.16.6"

RUN echo "[requires]\n\
lief/${LIEF_VERSION}@rewriting+extra-packages/stable\n\
\n\
[generators]\n\
CMakeDeps\n\
CMakeToolchain" > /tmp/conanfile.txt

RUN conan install /tmp/conanfile.txt \
    --build=missing \
    --remote=rewriting_remote \
    -pr:b=default -pr:h=default

RUN PKG_DIR=$(find /root/.conan/data/lief/${LIEF_VERSION}/rewriting+extra-packages/stable/package -mindepth 1 -maxdepth 1 -type d) && \
    mkdir -p /opt/lief-pkg && \
    cp -a $PKG_DIR/include /opt/lief-pkg/ && \
    cp -a $PKG_DIR/lib /opt/lief-pkg/ && \
    cp -a $PKG_DIR/lib/cmake /opt/lief-pkg/ && \
    cp -a $PKG_DIR/lib/pkgconfig /opt/lief-pkg/ || true

# ------------------------------------------------------------------------------
# Install libehp
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 AS libehp
RUN export DEBIAN_FRONTEND=noninteractive
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
RUN apt-get -y update \
 && apt-get -y install \
      build-essential \
      cmake \
      git

RUN git clone https://github.com/GrammaTech/libehp.git /usr/local/src/libehp
RUN git -C /usr/local/src/libehp reset --hard 5e41e26b88d415f3c7d3eb47f9f0d781cc519459
RUN cmake -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release -DEHP_BUILD_SHARED_LIBS=OFF /usr/local/src/libehp -B/usr/local/src/libehp/build
RUN cmake --build /usr/local/src/libehp/build -j4 --target all install

# ------------------------------------------------------------------------------
# Install GTIRB
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 AS gtirb
RUN export DEBIAN_FRONTEND=noninteractive
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
RUN apt-get -y update \
 && apt-get -y install \
      cmake \
      build-essential \
      protobuf-compiler \
      libboost-filesystem-dev \
      libboost-filesystem1.71.0 \
      python3 \
      git

ARG GTIRB_BRANCH=master
ARG GTIRB_CACHE_KEY
RUN git clone --depth=1 -b $GTIRB_BRANCH https://github.com/GrammaTech/gtirb /usr/local/src/gtirb
RUN cmake -DGTIRB_JAVA_API=OFF -DGTIRB_CL_API=OFF /usr/local/src/gtirb -B/usr/local/src/gtirb/build
RUN cmake --build /usr/local/src/gtirb/build -j4 --target all install

# ------------------------------------------------------------------------------
# Install gtirb-pprinter
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 AS gtirb-pprinter
RUN export DEBIAN_FRONTEND=noninteractive
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
RUN apt-get -y update \
 && apt-get -y install \
      cmake \
      build-essential \
      protobuf-compiler \
      libboost-filesystem-dev \
      libboost-filesystem1.71.0 \
      libboost-system-dev \
      libboost-system1.71.0 \
      libboost-program-options-dev \
      libboost-program-options1.71.0 \
      python3 \
      git \
      wget

RUN wget https://download.grammatech.com/gtirb/files/apt-repo/pool/unstable/libc/libcapstone-dev/libcapstone-dev_5.0.1_gtdev_amd64.deb \
  && dpkg -i libcapstone-dev_*_amd64.deb \
  && rm libcapstone-dev_*_amd64.deb

COPY --from=gtirb /usr/local/lib /usr/local/lib
COPY --from=gtirb /usr/local/include /usr/local/include

ARG GTIRB_PPRINTER_BRANCH=master
ARG GTIRB_PPRINTER_CACHE_KEY
RUN git clone --depth 1 -b $GTIRB_PPRINTER_BRANCH https://github.com/GrammaTech/gtirb-pprinter /usr/local/src/gtirb-pprinter
RUN cmake /usr/local/src/gtirb-pprinter -B/usr/local/src/gtirb-pprinter/build
RUN cmake --build /usr/local/src/gtirb-pprinter/build -j4 --target all install

# ------------------------------------------------------------------------------
# Install Ddisasm
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 AS ddisasm
RUN export DEBIAN_FRONTEND=noninteractive
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
RUN apt-get -y update \
 && apt-get -y install \
      build-essential \
      clang \
      cmake \
      g++ \
      git \
      lib32gcc-9-dev \
      lib32stdc++-9-dev \
      libboost-filesystem-dev \
      libboost-filesystem1.71.0 \
      libboost-program-options-dev \
      libboost-program-options1.71.0 \
      libboost-system-dev \
      libboost-system1.71.0 \
      libc-dev-i386-cross \
      mcpp \
      pandoc \
      protobuf-compiler \
      python3 \
      wget

RUN wget https://download.grammatech.com/gtirb/files/apt-repo/pool/unstable/libc/libcapstone-dev/libcapstone-dev_5.0.1_gtdev_amd64.deb \
  && dpkg -i libcapstone-dev_*_amd64.deb \
  && rm libcapstone-dev_*_amd64.deb

COPY --from=souffle /usr/local/bin/souffle* /usr/local/bin/
COPY --from=souffle /usr/local/include /usr/local/include
COPY --from=lief /opt/lief-pkg/lib/libLIEF.a /usr/lib/libLIEF.a
COPY --from=lief /opt/lief-pkg/lib/cmake/LIEF /usr/lib/cmake/LIEF
COPY --from=lief /opt/lief-pkg/include/LIEF /usr/include/LIEF
COPY --from=libehp /usr/local/lib /usr/local/lib
COPY --from=libehp /usr/local/include /usr/local/include
COPY --from=gtirb /usr/local/lib /usr/local/lib
COPY --from=gtirb /usr/local/include /usr/local/include
COPY --from=gtirb-pprinter /usr/local/bin/gtirb* /usr/local/bin/
COPY --from=gtirb-pprinter /usr/local/lib /usr/local/lib
COPY --from=gtirb-pprinter /usr/local/include /usr/local/include

# .git directory is needed to correctly generate version information
COPY .git/ /usr/local/src/ddisasm/.git
COPY doc/ /usr/local/src/ddisasm/doc/
COPY src/ /usr/local/src/ddisasm/src/
COPY CMakeLists.txt \
     CMakeLists.googletest \
     LICENSE.txt \
     README.md \
     version.txt \
     /usr/local/src/ddisasm/
RUN cmake -DCMAKE_BUILD_TYPE=Release -DDDISASM_GENERATE_MANY=ON /usr/local/src/ddisasm -B/usr/local/src/ddisasm/build
RUN cmake --build /usr/local/src/ddisasm/build -j$(nproc) --target all install

# ------------------------------------------------------------------------------
# Final image
# ------------------------------------------------------------------------------
FROM ubuntu:20.04

COPY --from=ddisasm /lib/x86_64-linux-gnu/libboost_filesystem.so.1.71.0 /lib/x86_64-linux-gnu/libboost_filesystem.so.1.71.0
COPY --from=ddisasm /lib/x86_64-linux-gnu/libboost_program_options.so.1.71.0 /lib/x86_64-linux-gnu/libboost_program_options.so.1.71.0
COPY --from=ddisasm /lib/libcapstone.so.5 /lib/libcapstone.so.5
COPY --from=ddisasm /lib/x86_64-linux-gnu/libgomp.so* /lib/x86_64-linux-gnu/
COPY --from=ddisasm /usr/local/lib/libgtirb.so* /usr/local/lib/
COPY --from=ddisasm /usr/local/lib/libgtirb_layout.so* /usr/local/lib/
COPY --from=ddisasm /usr/local/lib/libgtirb_pprinter.so* /usr/local/lib/
COPY --from=ddisasm /lib/x86_64-linux-gnu/libprotobuf.so* /lib/x86_64-linux-gnu/
COPY --from=ddisasm /usr/local/bin/ddisasm /usr/local/bin/
COPY --from=ddisasm /usr/local/bin/gtirb* /usr/local/bin/

# gcc is needed to rebuild binaries with gtirb-pprinter
RUN apt-get update -y && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev

ENV LD_LIBRARY_PATH=/usr/local/lib

# `grep -v 'UNKNOWN'`: return a failure code if the version string contains 'UNKNOWN'
RUN gtirb-pprinter --version | grep -v 'UNKNOWN'
RUN ddisasm --version | grep -v 'UNKNOWN'
