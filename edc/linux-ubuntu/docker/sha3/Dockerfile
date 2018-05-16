FROM registry.ng.bluemix.net/equibit/equibit-ubuntu:16.04

MAINTAINER Harmeek Jhutty <hjhutty@coderise.io> (@coderiseio)

ENV EQUIBIT_ENV=dev
ENV EQUIBIT_VERSION=0.1
ENV EQUIBIT_FOLDER_VERSION=0.1
ENV EQUIBIT_DATA=/home/equibit/.equibit \
    PATH=/opt/equibit-${EQUIBIT_FOLDER_VERSION}/:$PATH

WORKDIR /root/equibit/source

RUN git clone -b edc-sha3 https://Equibit:f41c78627c23717323d6dc2a83fe9193b09b13f7@github.com/Equibit/equibit-core.git

RUN cd /root/equibit/source/equibit-core/edc/linux-ubuntu/build.scripts/ && \
    ./build.core.sh && \
    ls -ltr /root/equibit/source/equibit-core/src/ && \
    mkdir -p /opt/equibit-${EQUIBIT_VERSION}/ && \
    mv /root/equibit/source/equibit-core/src/equibitd    /opt/equibit-${EQUIBIT_VERSION}/equibitd    && \
    mv /root/equibit/source/equibit-core/src/equibit-cli /opt/equibit-${EQUIBIT_VERSION}/equibit-cli && \
    chmod +x /opt/equibit-${EQUIBIT_VERSION}/equibit-cli && \
    chmod +x /opt/equibit-${EQUIBIT_VERSION}/equibitd    && \
    ls -ltr /opt/equibit-${EQUIBIT_VERSION}/
 
VOLUME ["/home/equibit/.equibit"]

COPY docker-entrypoint.sh /entrypoint.sh

RUN echo "Publishing Core Binaries"
   git clone https://Equibit:f41c78627c23717323d6dc2a83fe9193b09b13f7@github.com/Equibit/CoreBinaries.git && \
   cd CoreBinaries && \
   mkdir -p ${EQUIBIT_ENV}/${EQUIBIT_VERSION} && \
   cp /opt/equibit-${EQUIBIT_VERSION}/equibit-cli ${EQUIBIT_ENV}/${EQUIBIT_VERSION} && \
   cp /opt/equibit-${EQUIBIT_VERSION}/equibitd ${EQUIBIT_ENV}/${EQUIBIT_VERSION} && \
   git config --global user.name "Harmeek Jhutty" && \
   git config --global user.email "hjhutty@coderise.io" && \
   git add ${EQUIBIT_ENV}/${EQUIBIT_VERSION}/equibit-cli && \
   git add ${EQUIBIT_ENV}/${EQUIBIT_VERSION}/equibitd && \
   git commit -m "Committed Equibit Binaries ${EQUIBIT_ENV}/${EQUIBIT_VERSION}" && \
   git push origin master

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8332 8333 18332 18333 18444

CMD ["equibitd","-reindex"]
