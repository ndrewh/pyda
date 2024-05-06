FROM ubuntu:22.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y wget python3-pip python3-dev build-essential cmake gdbserver gdb tmux zsh git \
      cmake g++ g++-multilib doxygen git zlib1g-dev libunwind-dev libsnappy-dev liblz4-dev \
      build-essential gdb lcov pkg-config \
      libbz2-dev libffi-dev libgdbm-dev libgdbm-compat-dev liblzma-dev \
      libncurses5-dev libreadline6-dev libsqlite3-dev libssl-dev \
      lzma lzma-dev tk-dev uuid-dev zlib1g-dev

# install openssl to make python happy
RUN cd /usr/src/
RUN wget https://www.openssl.org/source/openssl-1.1.1v.tar.gz
RUN tar xf openssl-1.1.1v.tar.gz && cd openssl-1.1.1v/ && ./config --prefix=/usr/local && make && make install

# install python
RUN mkdir /opt/custom-python/ && mkdir /opt/custom-python-root/ && cd /opt/custom-python/ && wget https://github.com/python/cpython/archive/refs/tags/v3.10.12.tar.gz && tar xf v3.10.12.tar.gz && rm v3.10.12.tar.gz
COPY patches/cpython-3.10.12.patch /opt/custom-python/cpython-3.10.12/
RUN cd /opt/custom-python/cpython-3.10.12/ && git apply cpython-3.10.12.patch
RUN cd /opt/custom-python/cpython-3.10.12/ && ./configure --prefix=/opt/custom-python-root/ --with-ensurepip=install --enable-shared --with-openssl=/usr/local/ --with-openssl-rpath=auto && \
      make install -

# install dynamorio
RUN git clone --recurse-submodules -j4 https://github.com/DynamoRIO/dynamorio.git /opt/dynamorio && cd /opt/dynamorio/ && git checkout release_10.0.0 
WORKDIR /opt/dynamorio/
COPY patches/dynamorio-10.0.patch /opt/dynamorio/
RUN git apply dynamorio-10.0.patch
RUN mkdir build && cd build && cmake .. && make -j

ENV DYNAMORIO_HOME=/opt/dynamorio/build/
ENV PYTHONHOME=/opt/custom-python-root/
ENV PYTHONPATH=/opt/custom-python-root/lib/python3.10/:/opt/pyda/lib

COPY ./ /opt/pyda/
WORKDIR /opt/pyda
RUN mkdir build && cd build && \
      CMAKE_PREFIX_PATH=/opt/dynamorio/build/cmake cmake -DCMAKE_BUILD_TYPE=Release -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake -DPython3_EXECUTABLE=$PYTHONHOME/bin/python3 -DPython3_ROOT_DIR=/opt/custom-python-root/  .. && \
      make -j

ENV PATH=$PATH:/opt/custom-python-root/bin

# RUN bash -c "$(wget https://gef.blah.cat/sh -O -)"
# RUN pip3 install pwntools