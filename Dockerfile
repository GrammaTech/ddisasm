# requires at least 13 GB of free RAM for the default ddisasm build

FROM ubuntu:20.04 as builder

RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y autoconf automake bison build-essential clang doxygen flex g++ git libncurses5-dev libtool libsqlite3-dev make mcpp python sqlite zlib1g-dev cmake g++ python3-pip libboost-dev libprotobuf-dev protobuf-compiler libboost-all-dev wget unzip pandoc

ENV CMAKE_BUILD_PARALLEL_LEVEL 4

WORKDIR /app

RUN git clone --depth 1 https://github.com/grammatech/gtirb

WORKDIR gtirb

RUN cmake ./ -Bbuild

WORKDIR build
RUN cmake --build .
RUN make install

WORKDIR /app

RUN git clone https://github.com/GrammaTech/capstone

WORKDIR capstone

RUN git checkout origin/next

RUN MAKE_JOBS=${CMAKE_BUILD_PARALLEL_LEVEL} ./make.sh
RUN ./make.sh install

RUN git clone https://github.com/grammatech/gtirb-pprinter

WORKDIR gtirb-pprinter

RUN cmake ./ -Bbuild
WORKDIR build
RUN make -j${CMAKE_BUILD_PARALLEL_LEVEL}
RUN make install

RUN cmake ./ -Bbuild

WORKDIR build
RUN make -j${CMAKE_BUILD_PARALLEL_LEVEL}

###
RUN git clone https://git.zephyr-software.com/opensrc/libehp

WORKDIR libehp

RUN cmake . -Bbuild

WORKDIR build

RUN cmake --build .

RUN make install

RUN wget https://github.com/lief-project/LIEF/releases/download/0.11.0/lief-0.11.0.zip -O lief.zip

RUN unzip lief.zip

WORKDIR lief-0.11.0

RUN cmake . -Bbuild

WORKDIR build

RUN cmake --build .

###
RUN git clone --depth 1 https://github.com/GrammaTech/ddisasm

#WORKDIR /app/ddisasm
RUN ls -alh
WORKDIR ddisasm

RUN pip3 install lief

WORKDIR /app
RUN wget https://github.com/lief-project/LIEF/releases/download/0.11.4/LIEF-0.11.4-Linux-x86_64.tar.gz -O lief.tar.gz
RUN tar zxvf lief.tar.gz

WORKDIR /app/capstone/gtirb-pprinter/build/build/libehp/build/lief-0.11.0/build/ddisasm

RUN git clone --depth 1 -b 2.0.2 https://github.com/souffle-lang/souffle

WORKDIR souffle
RUN ./bootstrap && ./configure && make -j${CMAKE_BUILD_PARALLEL_LEVEL} && make install

WORKDIR ..

RUN cmake -Dgtirb_pprinter_DIR=/app/capstone/gtirb-pprinter/build -DLIEF_ROOT=/app/LIEF-0.11.4-Linux-x86_64 ./ -Bbuild
WORKDIR build
RUN make -j${CMAKE_BUILD_PARALLEL_LEVEL} && make install

RUN ldconfig
RUN ddisasm --version

FROM ubuntu:20.04

WORKDIR /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/local/bin/ddisasm /usr/local/bin/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libgomp.* /usr/lib/x86_64-linux-gnu/libprotobuf.* \
  /usr/local/lib/libehp.so* \
  /usr/local/lib/libgtirb_pprinter.so* \
  /usr/local/lib/libgtirb.so* \
  /usr/lib/libcapstone.* \
  /usr/lib/x86_64-linux-gnu/libboost_filesystem.* \
  /usr/lib/x86_64-linux-gnu/libboost_program_options.* \
  ./

WORKDIR /app

ENTRYPOINT ["ddisasm"]
