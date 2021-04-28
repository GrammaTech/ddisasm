FROM ubuntu:20.04

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
      lib32gcc-9-dev \
      lib32stdc++-9-dev \
      libboost-filesystem-dev \
      libboost-filesystem1.71.0 \
      libboost-program-options-dev \
      libboost-program-options1.71.0 \
      libboost-system-dev \
      libboost-system1.71.0 \
      libc-dev-i386-cross \
      libffi-dev \
      libsqlite3-dev \
      libtool \
      mcpp \
      protobuf-compiler \
      python3 \
      sqlite3 \
      wget \
      zlib1g-dev

WORKDIR /usr/local/src

# ------------------------------------------------------------------------------
# Install Souffle
# ------------------------------------------------------------------------------
RUN git clone -b 2.0.2 --depth 1 https://github.com/souffle-lang/souffle
WORKDIR souffle
RUN sh ./bootstrap
RUN ./configure --prefix=/usr --enable-64bit-domain --disable-ncurses
RUN make -j install
WORKDIR /usr/local/src

# ------------------------------------------------------------------------------
# Install LIEF
# ------------------------------------------------------------------------------
RUN git clone -b 0.10.0 --depth 1 https://github.com/lief-project/LIEF.git
RUN cmake -DLIEF_PYTHON_API=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF LIEF -BLIEF/build
RUN cmake --build LIEF/build -j --target all install

# ------------------------------------------------------------------------------
# Install Capstone
# ------------------------------------------------------------------------------
RUN wget https://grammatech.github.io/gtirb/pkgs/xenial/libcapstone-dev_4.0.1-gt3_amd64.deb
RUN dpkg -i libcapstone-dev_*_amd64.deb

# ------------------------------------------------------------------------------
# Install libehp
# ------------------------------------------------------------------------------
RUN git clone https://git.zephyr-software.com/opensrc/libehp.git
RUN git -C libehp reset --hard ddb106c4c1e521bf4b282d17e2a8abf0aa0fe721
RUN cmake -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release -DEHP_BUILD_SHARED_LIBS=OFF libehp -Blibehp/build
RUN cmake --build libehp/build -j --target all install

# ------------------------------------------------------------------------------
# Install GTIRB
# ------------------------------------------------------------------------------
RUN git clone --depth 1 https://github.com/GrammaTech/gtirb
RUN cmake -DGTIRB_JAVA_API=OFF -DGTIRB_CL_API=OFF gtirb -Bgtirb/build
RUN cmake --build gtirb/build -j --target all install

# ------------------------------------------------------------------------------
# Install gtirb-pprinter
# ------------------------------------------------------------------------------
# Dependencies:                                                  capstone, gtirb
RUN git clone --depth 1 https://github.com/GrammaTech/gtirb-pprinter
RUN cmake gtirb-pprinter -Bgtirb-pprinter/build
RUN cmake --build gtirb-pprinter/build -j --target all install

# ------------------------------------------------------------------------------
# Install Ddisasm
# ------------------------------------------------------------------------------
# Dependencies:                 souffle, libehp, capstone, gtirb, gtirb-pprinter
RUN git clone --depth 1 https://github.com/GrammaTech/ddisasm
RUN cmake -DLIEF_ROOT=/usr ddisasm -Bddisasm/build
RUN cmake --build ddisasm/build -j --target all install
