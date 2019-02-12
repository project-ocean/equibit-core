#!/bin/bash
# deploying win exe files to https://github.com/Equibit/CoreBinaries/dev/

BUILD_TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "--------------------- Publishing Core Binaries ---------------------"
echo $BUILD_TIMESTAMP

# ls -laR /home/travis/build/Equibit/equibit-core/build/equibit-x86_64-w64-mingw32

git clone https://$GH_USR:$GH_TKN@github.com/Equibit/CoreBinaries.git
cd CoreBinaries/dev && mkdir -p 0.2.1/${BUILD_TIMESTAMP}/
cp /home/travis/build/Equibit/equibit-core/build/equibit-x86_64-w64-mingw32/src/*.exe 0.2.1/${BUILD_TIMESTAMP}
git add *
git commit -m "Copy Equibit binaries to 0.2.1/${BUILD_TIMESTAMP}"
git push origin master

