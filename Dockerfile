FROM ubuntu:22.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y wget python3.10-full python3.10-dev build-essential cmake gdbserver gdb tmux zsh git \
      cmake g++ doxygen git zlib1g-dev libunwind-dev libsnappy-dev liblz4-dev \
      build-essential gdb lcov pkg-config \
      curl && \
      rm -rf /var/lib/apt/lists/*

RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10
RUN echo '#!/bin/bash\npython3.10 -m pip "$@"' > /usr/local/bin/pip3 && \
    chmod +x /usr/local/bin/pip3

# Install pwndbg + pwntools
WORKDIR /tmp
RUN git clone https://github.com/pwndbg/pwndbg.git && \
    cd pwndbg && git checkout cada600b0f2be0e2873465f59cc9c4c31425951a && \
    sed -i 's/signal.signal/__import__("pls_no_signal").signal/' pwndbg/__init__.py && \
    pip3 install -e . && \
    pip3 install pwntools

ARG PYDA_DEBUG=0

# install dynamorio
COPY patches/dynamorio-11.2.patch /tmp
COPY patches/wine_tls_fix_11.2.patch /tmp
RUN git clone --recurse-submodules -j4 https://github.com/DynamoRIO/dynamorio.git /opt/dynamorio && cd /opt/dynamorio/ && git checkout release_11.2.0  && \
      cd /opt/dynamorio/ && \
      wget https://github.com/DynamoRIO/dynamorio/commit/f1b67a4b0cf0a13314d500dd3aaefe9869597021.patch && git apply f1b67a4b0cf0a13314d500dd3aaefe9869597021.patch && rm f1b67a4b0cf0a13314d500dd3aaefe9869597021.patch && git submodule update --init && \
      wget https://github.com/DynamoRIO/dynamorio/commit/c46d736f308e6e734bd0477f7b8a2dcbefb155d3.patch && git apply c46d736f308e6e734bd0477f7b8a2dcbefb155d3.patch && rm c46d736f308e6e734bd0477f7b8a2dcbefb155d3.patch && \
      wget https://github.com/DynamoRIO/dynamorio/commit/8c997f483b564f2408553b718a5707e28c9be820.patch && git apply 8c997f483b564f2408553b718a5707e28c9be820.patch && rm 8c997f483b564f2408553b718a5707e28c9be820.patch && \
      wget https://github.com/DynamoRIO/dynamorio/commit/572f3b1484fda1fbc502fad298939756cd72f3ae.patch && git apply 572f3b1484fda1fbc502fad298939756cd72f3ae.patch && rm 572f3b1484fda1fbc502fad298939756cd72f3ae.patch && \
      git apply /tmp/dynamorio-11.2.patch && \
      git apply /tmp/wine_tls_fix_11.2.patch && \
      rm /tmp/*.patch && \
      mkdir /opt/dynamorio-install/ && \
      mkdir build && cd build && bash -c 'cmake -DDEBUG=$([ "$PYDA_DEBUG" == "1" ] && echo "ON" || echo "OFF") -DCMAKE_INSTALL_PREFIX=/opt/dynamorio-install/ -DBUILD_TESTS=OFF -DBUILD_SAMPLES=OFF -DBUILD_CLIENTS=OFF -DBUILD_DOCS=OFF ..' && \
      make -j && make install && \
      rm -rf /opt/dynamorio/ && \
      touch /opt/dynamorio-install/CMakeCache.txt

ENV DYNAMORIO_HOME=/opt/dynamorio-install/
ENV PYTHONPATH=/opt/pyda/lib

COPY ./ /opt/pyda/
WORKDIR /opt/pyda
RUN mkdir build && cd build && \
      bash -c 'CMAKE_PREFIX_PATH=/opt/dynamorio/build/cmake cmake -DCMAKE_BUILD_TYPE=$([ "$PYDA_DEBUG" == "1" ] && echo "Debug" || echo "Release") -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake ..' && \
      make -j

ENV PATH=$PATH:/opt/pyda/bin
ENV PYDA_TOOL_PATH=/opt/pyda/build/pyda_core/libtool.so

WORKDIR /opt/pyda

ARG PYDA_GEF=0
RUN bash -c 'if [[ "$PYDA_GEF" = "1" ]]; then \
    apt update && apt install -y file; \
    PYTHONPATH= PYTHONHOME= bash -c "$(wget https://raw.githubusercontent.com/hugsy/gef/main/scripts/gef.sh -O -)"; \
    fi'

ARG EVAL=0
RUN bash -c 'if [[ "$EVAL" = "1" ]]; then \
    apt update && apt install -y python3 python3-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg; \
    pip3 install libdebug; \
    fi'

