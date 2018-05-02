#!/bin/bash

SCRIPT=$(realpath $0)
PROJECT_SOURCE=$(dirname $(dirname $(dirname ${SCRIPT})))
PROJECT_BUILD=${PROJECT_SOURCE}/build/ubuntu

echo ""
echo "SCRIPT     = ${SCRIPT}"
echo "SOURCE     = ${PROJECT_SOURCE}"
echo "BUILD      = ${PROJECT_BUILD}"
echo ""

mkdir -p "${PROJECT_BUILD}" || exit 1

cd "${PROJECT_BUILD}" || exit 1

"${PROJECT_SOURCE}/autogen.sh" || exit 1

"${PROJECT_SOURCE}/configure" \
    --with-gui=no \
    --disable-tests \
    || exit 1

make || exit 1

strip src/bitcoind    || strip src/equibitd    || exit 1
strip src/bitcoin-cli || strip src/equibit-cli || exit 1

echo ""
echo "Build OK"
echo ""
