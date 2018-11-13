FROM registry.ng.bluemix.net/equibit/equibit-ubuntu:16.04

MAINTAINER Harmeek Jhutty <hjhutty@coderise.io>

<<<<<<< HEAD
ENV EQUIBIT_VERSION=0.2
ENV EQUIBIT_FOLDER_VERSION=0.2
=======
ENV EQUIBIT_VERSION=0.16.2.0
ENV EQUIBIT_FOLDER_VERSION=0.16.2.0
>>>>>>> issues/#18-sha3
ENV EQUIBIT_DATA=/home/equibit/.equibit \
    PATH=/opt/equibit-${EQUIBIT_FOLDER_VERSION}/:$PATH

WORKDIR /root/equibit/source

<<<<<<< HEAD
RUN git clone -b issues/#203-ibm-could-build https://Equibit:f41c78627c23717323d6dc2a83fe9193b09b13f7@github.com/Equibit/equibit-core.git
=======
RUN git clone -b issues/#18-sha3 https://Equibit:f41c78627c23717323d6dc2a83fe9193b09b13f7@github.com/Equibit/equibit-core.git
>>>>>>> issues/#18-sha3

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

<<<<<<< HEAD
RUN cd /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/ && \
    chmod +x /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/publish.sh && \
    /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/publish.sh
=======
# RUN cd /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/ && \
#     chmod +x /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/publish.sh && \
#     /root/equibit/source/equibit-core/eqb/ibmcloud/linux-ubuntu/build.scripts/publish.sh
>>>>>>> issues/#18-sha3

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8332 8333 18332 18333 18444

#CMD ["equibitd", "-reindex"]
<<<<<<< HEAD
CMD ["equibitd", "-regtest"]
=======
CMD ["equibitd", "-regtest"]
>>>>>>> issues/#18-sha3
