FROM registry.ng.bluemix.net/equibit/equibit-ubuntu:16.04

MAINTAINER Harmeek Jhutty <hjhutty@coderise.io>

ENV EQUIBIT_VERSION=0.16.2.0
ENV EQUIBIT_FOLDER_VERSION=0.16.2.0
ENV EQUIBIT_DATA=/home/equibit/.equibit \
    PATH=/opt/equibit-${EQUIBIT_FOLDER_VERSION}/:$PATH

WORKDIR /root/equibit/source

RUN git clone -b issues/#219-stage https://Equibit:76e049c3fcb3d35440e82121898a9f6c60cc6a96@github.com/Equibit/equibit-core.git

RUN cd /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/ && \
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

RUN cd /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/ && \
    chmod +x /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/publish.sh && \
    /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/publish.sh

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8332 8333 18332 18333 18444

CMD ["equibitd","-reindex"]
#CMD ["equibitd"]
