# Build and install OpenSSL

cd ~
mkdir -p ~/temp
cd       ~/temp

sudo apt-get install git
git  clone https://github.com/openssl/openssl.git

sudo DEBIAN_FRONTEND=noninteractive apt-get --yes --force-yes install checkinstall
sudo DEBIAN_FRONTEND=noninteractive apt-get --yes --force-yes install build-essential

# NOTE: we might need SU to run all OpenSSL tests or installation
#sudo su                    

cd   openssl
sudo ./config
sudo make
sudo make test             # NOTE: Not all of the tests pass. I did not investigate why. We only use ECC.
sudo checkinstall          # NOTE: Enter any description. No other input required. Say yes to removing temporary installation files

sudo ln -s /usr/local/bin/openssl /usr/bin/openssl
sudo ldconfig

sudo rm -rf ~/temp/openssl # to uninstall it in future use $ dpkg -r openssl

cd ~
