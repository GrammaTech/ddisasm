# requires at least 13 GB of free RAM for the default ddisasm build

FROM ubuntu:21.04 as builder

RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y autoconf automake bison build-essential clang doxygen \
  flex g++ git libncurses5-dev libtool libsqlite3-dev make mcpp python sqlite zlib1g-dev cmake g++ python3-pip \
  libboost-dev libprotobuf-dev protobuf-compiler libboost-all-dev wget unzip pandoc openjdk-8-jdk

ENV CMAKE_BUILD_PARALLEL_LEVEL 4

WORKDIR /app

RUN git clone --depth 1 https://github.com/grammatech/gtirb

RUN cd gtirb && \
  cmake ./ -Bbuild && \
  cd build && \
  cmake --build . && \
  make install

RUN git clone --depth 1 -b next https://github.com/GrammaTech/capstone

RUN cd capstone && \
  MAKE_JOBS=${CMAKE_BUILD_PARALLEL_LEVEL} ./make.sh && \
  ./make.sh install

RUN git clone https://github.com/grammatech/gtirb-pprinter

RUN cd gtirb-pprinter && \
  cmake ./ && \
  make -j${CMAKE_BUILD_PARALLEL_LEVEL} && \
  make install

###
RUN git clone https://git.zephyr-software.com/opensrc/libehp

RUN cd libehp && \
  cmake . -Bbuild && \
  cd build && \
  cmake --build . && \
  make install

###
RUN git clone --depth 1 https://github.com/GrammaTech/ddisasm

RUN wget https://github.com/lief-project/LIEF/releases/download/0.10.0/LIEF-0.10.0-Linux.tar.gz -O lief.tar.gz
RUN tar zxvf lief.tar.gz

RUN git clone --depth 1 -b 2.0.2 https://github.com/souffle-lang/souffle

RUN cd souffle && \
  ./bootstrap && \
  ./configure --enable-64bit-domain && \
  make -j${CMAKE_BUILD_PARALLEL_LEVEL} && \
  make install

RUN cd ddisasm && \
  mkdir build && \
  cmake -Dgtirb_pprinter_DIR=/app/gtirb-pprinter/build -DLIEF_ROOT=/app/LIEF-0.10.0-Linux ./ -Bbuild && \
  cd build && \
  make -j${CMAKE_BUILD_PARALLEL_LEVEL} && \
  make install

RUN ldconfig
RUN ddisasm --version
RUN gtirb-pprinter --version

FROM ubuntu:21.04

RUN apt-get update && \
  apt-get install --no-install-recommends -y gcc && \
  rm -rf /var/cache/apt/*

WORKDIR /usr/lib/x86_64-linux-gnu/
COPY --from=builder /app/gtirb/build/java/gtirb_api-*.jar /libs/
COPY --from=builder /usr/local/bin/gtirb-* /usr/local/bin/ddisasm /usr/local/bin/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libgomp.* /usr/lib/x86_64-linux-gnu/libprotobuf.* \
  /usr/local/lib/libehp.so* \
  /usr/local/lib/libgtirb*.so* \
  /usr/lib/libcapstone.* \
  /usr/lib/x86_64-linux-gnu/libboost_filesystem.* \
  /usr/lib/x86_64-linux-gnu/libboost_program_options.* \
  ./

WORKDIR /app

ENTRYPOINT ["ddisasm"]
