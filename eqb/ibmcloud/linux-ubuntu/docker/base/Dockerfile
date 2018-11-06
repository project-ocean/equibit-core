FROM ubuntu:16.04

MAINTAINER Harmeek Jhutty <hjhutty@coderise.io> (@coderiseio)

RUN useradd -r equibit

ENV GOSU_VERSION=1.10

RUN apt-get update -y \
  && apt-get install -y curl gnupg \
  && apt-get install -y autoconf \
  && apt-get install -y libtool \
  && apt-get install -y g++ \
  && apt-get install -y pkg-config \
  && apt-get install -y libboost-all-dev \
  && apt-get install -y libevent-dev \
  && apt-get install -y git \
  && apt-get install -y build-essential \
  && apt-get install -y wget \
  && apt-get install -y curl \
  && apt-get install -y vim \
  && apt-get install -y sudo

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN set -ex \
    && for key in \
      B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    ; do \
      gpg --keyserver pgp.mit.edu --recv-keys "$key" || \
      gpg --keyserver keyserver.pgp.com --recv-keys "$key" || \
      gpg --keyserver ha.pool.sks-keyservers.net --recv-keys "$key" || \
      gpg --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys "$key" ; \
    done

RUN curl -o /usr/local/bin/gosu -fSL https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-$(dpkg --print-architecture) \
  	&& curl -o /usr/local/bin/gosu.asc -fSL https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-$(dpkg --print-architecture).asc \
  	&& gpg --verify /usr/local/bin/gosu.asc \
  	&& rm /usr/local/bin/gosu.asc \
  	&& chmod +x /usr/local/bin/gosu

COPY ./equibit-core/edc/ /home/equibit/

RUN /home/equibit/linux-ubuntu/setup.build.environment/make.berkley.db.sh

RUN cd /opt && git clone https://github.com/openssl/openssl.git \
    && cd /opt/openssl && ./config \
    && make && make install \
    && cp /usr/local/lib/lib* /usr/lib/ \
    && rm -rf /opt/openssl
  