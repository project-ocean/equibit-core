@ECHO OFF

call project.bat

set bitcoin_dat=%PROJECT_BLOCKCHAIN%/
set bitcoin_bin=%PROJECT_SOLUTION%/build/Debug/

set regtest1=-datadir="%bitcoin_dat%btc-1" -rpcuser=equibit -rpcpassword=equibit -regtest -relaypriority=false -rpcport=18443 -port=18444 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex
set testnet1=-datadir="%bitcoin_dat%btc-1" -rpcuser=equibit -rpcpassword=equibit -testnet -relaypriority=false -rpcport=18332 -port=18333 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex
set mainnet1=-datadir="%bitcoin_dat%btc-1" -rpcuser=equibit -rpcpassword=equibit          -relaypriority=false  -rpcport=8332  -port=8333 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex

set regtest2=-datadir="%bitcoin_dat%btc-2" -rpcuser=equibit -rpcpassword=equibit -regtest -relaypriority=false -rpcport=28443 -port=28444 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex
set testnet2=-datadir="%bitcoin_dat%btc-2" -rpcuser=equibit -rpcpassword=equibit -testnet -relaypriority=false -rpcport=28332 -port=28333 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex

set cli1=%bitcoin_bin%bitcoin_client.exe %regtest1%
set cli2=%bitcoin_bin%bitcoin_client.exe %regtest2%
set cli1t=%bitcoin_bin%bitcoin_client.exe %testnet1%
set cli2t=%bitcoin_bin%bitcoin_client.exe %testnet2%
set cli1m=%bitcoin_bin%bitcoin_client.exe %mainnet1%

set btc1=%bitcoin_bin%bitcoin_server.exe %regtest1%
set btc2=%bitcoin_bin%bitcoin_server.exe %regtest2%
set btc1t=%bitcoin_bin%bitcoin_server.exe %testnet1%
set btc2t=%bitcoin_bin%bitcoin_server.exe %testnet2%
set btc1m=%bitcoin_bin%bitcoin_server.exe %mainnet1%

doskey cli1=%cli1% $*
doskey cli2=%cli2% $*
doskey cli1t=%cli1t% $*
doskey cli2t=%cli2t% $*
doskey cli1m=%cli1m% $*

doskey btc1=%btc1% $*
doskey btc2=%btc2% $*
doskey btc1t=%btc1t% $*
doskey btc2t=%btc2t% $*
doskey btc1m=%btc1m% $*
