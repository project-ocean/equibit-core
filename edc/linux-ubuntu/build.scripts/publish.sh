#!/bin/bash

EQUIBIT_ENV=dev
EQUIBIT_VERSION=0.1
BUILD_TIMESTAMP=$(date +%Y%m%d%H%M%S)

echo -e "Checking for Equibit daemon"
if [ -f /opt/equibit-${EQUIBIT_VERSION}/equibitd ]; then
  echo "Equibit daemon found"
else
  echo "Equibit daemon not found. Exit!"
  exit 1
fi

echo -e "Checking for Equibit cli"
if [ -f /opt/equibit-${EQUIBIT_VERSION}/equibit-cli ]; then
  echo "Equibit cli found"
else
  echo "Equibit cli not found. Exit!"
  exit 1
fi

echo "Publishing Core Binaries"
git clone https://Equibit:f41c78627c23717323d6dc2a83fe9193b09b13f7@github.com/Equibit/CoreBinaries.git
cd CoreBinaries

mkdir -p ${EQUIBIT_ENV}/${EQUIBIT_VERSION}/${BUILD_TIMESTAMP}/
cp /opt/equibit-${EQUIBIT_VERSION}/equibit-cli ${EQUIBIT_ENV}/${EQUIBIT_VERSION}/${BUILD_TIMESTAMP}/
cp /opt/equibit-${EQUIBIT_VERSION}/equibitd ${EQUIBIT_ENV}/${EQUIBIT_VERSION}/${BUILD_TIMESTAMP}/

git config --global user.name "Harmeek Jhutty"
git config --global user.email "hjhutty@coderise.io"

git add ${EQUIBIT_ENV}/${EQUIBIT_VERSION}/${BUILD_TIMESTAMP}/
git commit -m "Committed Equibit Binaries ${EQUIBIT_ENV}/${EQUIBIT_VERSION}/${BUILD_TIMESTAMP}"
# git push origin master
