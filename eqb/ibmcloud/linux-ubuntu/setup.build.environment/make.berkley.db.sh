# Build Berkley DB required for BitCoin

cd ~
mkdir -p ~/temp/berkley-db
cd       ~/temp/berkley-db

wget 'http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz'
tar  -xzvf  db-4.8.30.NC.tar.gz
sudo rm -rf db-4.8.30.NC.tar.gz
cd          db-4.8.30.NC/build_unix/

../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$HOME/equibit/source/thirdparty/db4/

make install

cd ~

sudo rm -rf ~/temp/berkley-db
