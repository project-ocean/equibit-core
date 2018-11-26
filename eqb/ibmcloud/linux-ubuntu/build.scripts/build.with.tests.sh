#!/bin/bash

source ./set.environment.sh

cd $source_folder

echo "*** Run autogen.sh ***"
./autogen.sh
echo ""

echo "*** Confugure using --with-gui=no ***"
./configure CPPFLAGS="-I${berkley_folder}/include/" LDFLAGS="-L${berkley_folder}/lib/ -L/usr/local/lib" --with-gui=no
echo ""


echo "*** Build the source code ***"
make
echo ""

echo "Done"
echo ""
