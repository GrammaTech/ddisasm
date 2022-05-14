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

RUN git clone -b 2.3 https://github.com/souffle-lang/souffle && \
    cd souffle && \
    cmake . -Bbuild -DCMAKE_BUILD_TYPE=Release -DSOUFFLE_USE_CURSES=0 -DSOUFFLE_USE_SQLITE=0 -DSOUFFLE_DOMAIN_64BIT=1 && \
    cd build && \
    make install -j4

# ------------------------------------------------------------------------------
# Install LIEF
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 AS LIEF
RUN export DEBIAN_FRONTEND=noninteractive
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
RUN apt-get -y update \
 && apt-get -y install \
      build-essential \
      cmake \
      git \
      python3

RUN git clone -b 0.12.1 --depth 1 https://github.com/lief-project/LIEF.git /usr/local/src/LIEF
RUN cmake -DLIEF_PYTHON_API=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF /usr/local/src/LIEF -B/usr/local/src/LIEF/build
RUN cmake --build /usr/local/src/LIEF/build -j4 --target all install

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

RUN git clone https://git.zephyr-software.com/opensrc/libehp.git /usr/local/src/libehp
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

RUN git clone --depth 1 https://github.com/GrammaTech/gtirb /usr/local/src/gtirb
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

RUN wget https://download.grammatech.com/gtirb/files/apt-repo/pool/unstable/libc/libcapstone-dev/libcapstone-dev_5.0.0-gtdev_amd64.deb \
  && dpkg -i libcapstone-dev_*_amd64.deb \
  && rm libcapstone-dev_*_amd64.deb

COPY --from=gtirb /usr/local/lib /usr/local/lib
COPY --from=gtirb /usr/local/include /usr/local/include

RUN git clone --depth 1 https://github.com/GrammaTech/gtirb-pprinter /usr/local/src/gtirb-pprinter
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

RUN wget https://download.grammatech.com/gtirb/files/apt-repo/pool/unstable/libc/libcapstone-dev/libcapstone-dev_5.0.0-gtdev_amd64.deb \
  && dpkg -i libcapstone-dev_*_amd64.deb \
  && rm libcapstone-dev_*_amd64.deb

COPY --from=souffle /usr/local/bin/souffle* /usr/local/bin/
COPY --from=souffle /usr/local/include /usr/local/include
COPY --from=LIEF /usr/lib/libLIEF.a /usr/lib/libLIEF.a
COPY --from=LIEF /usr/include/LIEF /usr/include/LIEF
COPY --from=LIEF /usr/share/LIEF /usr/share/LIEF
COPY --from=libehp /usr/local/lib /usr/local/lib
COPY --from=libehp /usr/local/include /usr/local/include
COPY --from=gtirb /usr/local/lib /usr/local/lib
COPY --from=gtirb /usr/local/include /usr/local/include
COPY --from=gtirb-pprinter /usr/local/bin/gtirb* /usr/local/bin/
COPY --from=gtirb-pprinter /usr/local/lib /usr/local/lib
COPY --from=gtirb-pprinter /usr/local/include /usr/local/include

ARG DDISASM_URL=https://github.com/GrammaTech/ddisasm
ARG DDISASM_BRANCH=main
RUN git clone --depth 1 -b $DDISASM_BRANCH $DDISASM_URL /usr/local/src/ddisasm
RUN cmake -DCMAKE_BUILD_TYPE=Release /usr/local/src/ddisasm -B/usr/local/src/ddisasm/build
RUN cmake --build /usr/local/src/ddisasm/build -j4 --target all install

# ------------------------------------------------------------------------------
# Final image
# ------------------------------------------------------------------------------
FROM ubuntu:20.04

COPY --from=ddisasm /lib/x86_64-linux-gnu/libboost_filesystem.so.1.71.0 /lib/x86_64-linux-gnu/libboost_filesystem.so.1.71.0
COPY --from=ddisasm /lib/x86_64-linux-gnu/libboost_program_options.so.1.71.0 /lib/x86_64-linux-gnu/libboost_program_options.so.1.71.0
COPY --from=ddisasm /lib/libcapstone.so.5 /lib/libcapstone.so.5
COPY --from=ddisasm /lib/x86_64-linux-gnu/libgomp.so.1 /lib/x86_64-linux-gnu/libgomp.so.1
COPY --from=ddisasm /usr/local/lib/libgtirb.so.* /usr/local/lib/
COPY --from=ddisasm /usr/local/lib/libgtirb_layout.so.* /usr/local/lib/
COPY --from=ddisasm /usr/local/lib/libgtirb_pprinter.so.* /usr/local/lib/
COPY --from=ddisasm /lib/x86_64-linux-gnu/libprotobuf.so.17 /lib/x86_64-linux-gnu/libprotobuf.so.17
COPY --from=ddisasm /usr/local/bin/ddisasm /usr/local/bin/
COPY --from=ddisasm /usr/local/bin/gtirb* /usr/local/bin/

ENV LD_LIBRARY_PATH=/usr/local/lib

RUN gtirb-pprinter --version
RUN ddisasm --version
