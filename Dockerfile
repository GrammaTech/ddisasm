FROM ubuntu:20.04

# ------------------------------------------------------------------------------
# Install Souffle
# ------------------------------------------------------------------------------
RUN apt-get -y update \
 && apt-get -y install \
      automake \
      bison \
      build-essential \
      doxygen \
      flex \
      git \
      libffi-dev \
      libsqlite3-dev \
      libtool \
      mcpp \
      sqlite3 \
      zlib1g-dev

RUN cd /usr/local/src \
 && git clone -b 2.0.2 --depth 1 https://github.com/souffle-lang/souffle \
 && cd souffle \
 && sh ./bootstrap \
 && ./configure --prefix=/usr --enable-64bit-domain --disable-ncurses \
 && make -j install

# ------------------------------------------------------------------------------
# Install Boost
# ------------------------------------------------------------------------------
RUN apt-get -y update \
 && apt-get -y install \
      libboost-filesystem-dev \
      libboost-filesystem1.71.0 \
      libboost-system-dev \
      libboost-system1.71.0 \
      libboost-program-options-dev \
      libboost-program-options1.71.0

# ------------------------------------------------------------------------------
# Install LIEF
# ------------------------------------------------------------------------------
RUN apt-get -y update \
 && apt-get -y install \
      build-essential \
      cmake \
      git \
      python3

RUN cd /usr/local/src \
 && git clone -b 0.10.0 --depth 1 https://github.com/lief-project/LIEF.git \
 && mkdir LIEF/build \
 && cd LIEF/build \
 && cmake -DLIEF_PYTHON_API=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF .. \
 && make -j \
 && make install

# ------------------------------------------------------------------------------
# Install Capstone
# ------------------------------------------------------------------------------
RUN apt-get -y update \
 && apt-get -y install git
COPY libcapstone-dev_*_amd64.deb ./
RUN dpkg -i libcapstone-dev_*_amd64.deb

# ------------------------------------------------------------------------------
# Install libehp
# ------------------------------------------------------------------------------
RUN apt-get -y update \
 && apt-get -y install \
      build-essential \
      cmake \
      git

RUN cd /usr/local/src \
 && git clone https://git.zephyr-software.com/opensrc/libehp.git \
 && cd libehp \
 && git reset --hard ddb106c4c1e521bf4b282d17e2a8abf0aa0fe721 \
 && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release -DEHP_BUILD_SHARED_LIBS=OFF \
 && cd build \
 && make -j \
 && make install

# ------------------------------------------------------------------------------
# Install GTIRB
# ------------------------------------------------------------------------------
# Dependencies:                                                            boost
RUN apt-get -y update \
 && apt-get -y install \
      cmake \
      build-essential \
      protobuf-compiler

RUN cd /usr/local/src \
 && git clone --depth 1 https://github.com/GrammaTech/gtirb \
 && mkdir gtirb/build \
 && cd gtirb/build \
 && cmake -DGTIRB_JAVA_API=OFF -DGTIRB_CL_API=OFF .. \
 && make -j \
 && make install

# ------------------------------------------------------------------------------
# Install gtirb-pprinter
# ------------------------------------------------------------------------------
# Dependencies:                                            boost, capstone, gtirb
RUN apt-get -y update \
 && apt-get -y install \
      cmake \
      build-essential \
      protobuf-compiler

RUN cd /usr/local/src \
 && git clone --depth 1 https://github.com/GrammaTech/gtirb-pprinter \
 && mkdir gtirb-pprinter/build \
 && cd gtirb-pprinter/build \
 && cmake .. \
 && make -j \
 && make install

# ------------------------------------------------------------------------------
# Install Ddisasm
# ------------------------------------------------------------------------------
# Dependencies:          souffle, boost, libehp, capstone, gtirb, gtirb-pprinter
RUN apt-get -y update \
 && apt-get -y install \
      cmake \
      build-essential \
      protobuf-compiler

RUN cd /usr/local/src \
 && git clone --depth 1 https://github.com/GrammaTech/ddisasm \
 && mkdir ddisasm/build \
 && cd ddisasm/build \
 && cmake -DLIEF_ROOT=/usr .. \
 && make -j \
 && make install

# ------------------------------------------------------------------------------
# Install x86_32 runtime
# ------------------------------------------------------------------------------
RUN apt-get -y update \
 && apt-get -y install \
      lib32gcc-9-dev \
      lib32stdc++-9-dev \
      libc-dev-i386-cross \
 && ln -s /usr/i686-linux-gnu/lib/ /usr/lib/i386-linux-gnu \
 && ln -s /usr/i686-linux-gnu/include /usr/include/i386-linux-gnu
