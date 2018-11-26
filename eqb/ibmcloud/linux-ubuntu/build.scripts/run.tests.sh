#!/bin/bash

source ./set.environment.sh

cd $source_folder

echo "*** Run tests ***"
src/test/test_bitcoin
echo ""

echo "Done"
echo ""
