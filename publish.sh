#!/bin/bash
# Upload Windows exe files to https://github.com/Equibit/CoreBinaries/dev/

EQUIBIT_VERSION=0.2.1
BUILD_TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "--------------------- Publishing Core Binaries ---------------------"
git clone https://$GH_USR:$GH_TKN@github.com/Equibit/CoreBinaries.git
cd CoreBinaries/dev && mkdir -p ${EQUIBIT_VERSION}/${BUILD_TIMESTAMP}/
cp /home/travis/build/Equibit/equibit-core/build/equibit-x86_64-w64-mingw32/src/*.exe ${EQUIBIT_VERSION}/${BUILD_TIMESTAMP}
git add *
git commit -m "Copy Equibit binaries to ${EQUIBIT_VERSION}/${BUILD_TIMESTAMP}"
git push origin master

