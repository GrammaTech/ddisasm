FROM ubuntu:20.04

RUN export DEBIAN_FRONTEND=noninteractive
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime

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
      libtool \
      make \
      mcpp \
      pkg-config \
      sqlite3 \
      libsqlite3-dev \
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
      unzip \
      libboost-filesystem-dev \
      libboost-filesystem1.71.0 \
      libboost-system-dev \
      libboost-system1.71.0 \
      libboost-program-options-dev \
      libboost-program-options1.71.0 \
      make \
      mcpp \
      pkg-config \
      protobuf-compiler \
      python3 \
      python3-pip \
      software-properties-common \
      wget \
      zlib1g-dev

# ------------------------------------------------------------------------------
# Install LIEF
# ------------------------------------------------------------------------------
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
COPY libcapstone-dev_*_amd64.deb ./
RUN dpkg -i libcapstone-dev_*_amd64.deb

# ------------------------------------------------------------------------------
# Install libehp
# ------------------------------------------------------------------------------
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
RUN cd /usr/local/src \
 && git clone https://github.com/GrammaTech/gtirb \
 && mkdir gtirb/build \
 && cd gtirb/build \
 && cmake -DGTIRB_JAVA_API=OFF -DGTIRB_CL_API=OFF .. \
 && make -j \
 && make install

# ------------------------------------------------------------------------------
# Install gtirb-pprinter
# ------------------------------------------------------------------------------
RUN cd /usr/local/src \
 && git clone https://github.com/GrammaTech/gtirb-printer \
 && mkdir gtirb-printer/build \
 && cd gtirb-printer/build \
 && cmake .. \
 && make -j \
 && make install

# ------------------------------------------------------------------------------
# Install Ddisasm
# ------------------------------------------------------------------------------
RUN cd /usr/local/src \
 && git clone https://github.com/GrammaTech/ddisasm \
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
