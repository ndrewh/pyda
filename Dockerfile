FROM ubuntu:22.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y wget python3-pip python3-dev build-essential cmake gdbserver gdb tmux zsh git \
      cmake g++ doxygen git zlib1g-dev libunwind-dev libsnappy-dev liblz4-dev \
      build-essential gdb lcov pkg-config \
      libbz2-dev libffi-dev libgdbm-dev libgdbm-compat-dev liblzma-dev \
      libncurses5-dev libreadline6-dev libsqlite3-dev libssl-dev \
      lzma lzma-dev tk-dev uuid-dev zlib1g-dev && \
      rm -rf /var/lib/apt/lists/*

# install openssl to make python happy
RUN cd /usr/src/ && \
      wget https://www.openssl.org/source/openssl-1.1.1v.tar.gz && \
      tar xf openssl-1.1.1v.tar.gz && \
      rm openssl-1.1.1v.tar.gz && \
      cd openssl-1.1.1v/ && \
      ./config --prefix=/usr/local && \
      make -j && make install_sw && \
      rm -rf /usr/src/openssl-1.1.1v/

# install python
COPY patches/cpython-3.10.12.patch /tmp/cpython-3.10.12.patch
RUN mkdir /opt/custom-python/ && \
      mkdir /opt/custom-python-root/ && \
      cd /opt/custom-python/ && \
      wget https://github.com/python/cpython/archive/refs/tags/v3.10.12.tar.gz && \
      tar xf v3.10.12.tar.gz && rm v3.10.12.tar.gz && \
      mv /tmp/cpython-3.10.12.patch /opt/custom-python/cpython-3.10.12/ && \
      cd /opt/custom-python/cpython-3.10.12/ && git apply cpython-3.10.12.patch && \
      cd /opt/custom-python/cpython-3.10.12/ && \
      ./configure --prefix=/opt/custom-python-root/ --with-ensurepip=install --enable-shared --with-openssl=/usr/local/ --with-openssl-rpath=auto && \
      make install -j && \
      rm -rf /opt/custom-python/

ARG PYDA_DEBUG=0

# install dynamorio
COPY patches/dynamorio-10.0.patch /tmp
RUN git clone --recurse-submodules -j4 https://github.com/DynamoRIO/dynamorio.git /opt/dynamorio && cd /opt/dynamorio/ && git checkout release_10.0.0  && \
      cd /opt/dynamorio/ && \
      git apply /tmp/dynamorio-10.0.patch && \
      rm /tmp/dynamorio-10.0.patch && \
      mkdir /opt/dynamorio-install/ && \
      mkdir build && cd build && bash -c 'cmake -DDEBUG=$([ "$PYDA_DEBUG" == "1" ] && echo "ON" || echo "OFF") -DCMAKE_INSTALL_PREFIX=/opt/dynamorio-install/ ..' && \
      make -j && make install && \
      rm -rf /opt/dynamorio/ && \
      touch /opt/dynamorio-install/CMakeCache.txt

ENV DYNAMORIO_HOME=/opt/dynamorio-install/
ENV PYTHONHOME=/opt/custom-python-root/
ENV PYTHONPATH=/opt/custom-python-root/lib/python3.10/:/opt/pyda/lib

COPY ./ /opt/pyda/
WORKDIR /opt/pyda
RUN mkdir build && cd build && \
      bash -c 'CMAKE_PREFIX_PATH=/opt/dynamorio/build/cmake cmake -DCMAKE_BUILD_TYPE=$([ "$PYDA_DEBUG" == "1" ] && echo "Debug" || echo "Release") -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake -DPython3_EXECUTABLE=$PYTHONHOME/bin/python3 -DPython3_ROOT_DIR=/opt/custom-python-root/  ..' && \
      make -j

ENV PATH=$PATH:/opt/pyda/bin
WORKDIR /tmp

RUN git clone https://github.com/pwndbg/pwndbg.git && \
    cd pwndbg && git checkout cada600b0f2be0e2873465f59cc9c4c31425951a && \
    sed -i 's/signal.signal/__import__("pls_no_signal").signal/' pwndbg/__init__.py && \
    pip3 install -e .

WORKDIR /opt/pyda

ARG PYDA_GEF=0
RUN bash -c 'if [[ "$PYDA_GEF" = "1" ]]; then \
    apt update && apt install -y file; \
    PYTHONPATH= PYTHONHOME= bash -c "$(wget https://raw.githubusercontent.com/hugsy/gef/main/scripts/gef.sh -O -)"; \
    fi'

RUN pip3 install pwntools
