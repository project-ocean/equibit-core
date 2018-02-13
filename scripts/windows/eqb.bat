@ECHO OFF

set folder=%~dp0

set equibit_dat=%folder%blockchain/
set equibit_bin=%folder%

set regtest1=-datadir="%equibit_dat%eqb-1" -rpcuser=equibit -rpcpassword=equibit -regtest -relaypriority=false -rpcport=18441 -port=18440 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex
set testnet1=-datadir="%equibit_dat%eqb-1" -rpcuser=equibit -rpcpassword=equibit -testnet -relaypriority=false -rpcport=18331 -port=18330 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex
set mainnet1=-datadir="%equibit_dat%eqb-1" -rpcuser=equibit -rpcpassword=equibit          -relaypriority=false  -rpcport=8331  -port=8330 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex

set regtest2=-datadir="%equibit_dat%eqb-2" -rpcuser=equibit -rpcpassword=equibit -regtest -relaypriority=false -rpcport=28441 -port=28440 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex
set testnet2=-datadir="%equibit_dat%eqb-2" -rpcuser=equibit -rpcpassword=equibit -testnet -relaypriority=false -rpcport=28331 -port=28330 -rpcallowip=127.0.0.1 -rpcallowanyip -printtoconsole -txindex

set cli1=%equibit_bin%equibit_client.exe %regtest1%
set cli2=%equibit_bin%equibit_client.exe %regtest2%
set cli1t=%equibit_bin%equibit_client.exe %testnet1%
set cli2t=%equibit_bin%equibit_client.exe %testnet2%
set cli1m=%equibit_bin%equibit_client.exe %mainnet1%

set eqb1=%equibit_bin%equibit_server.exe %regtest1%
set eqb2=%equibit_bin%equibit_server.exe %regtest2%
set eqb1t=%equibit_bin%equibit_server.exe %testnet1%
set eqb2t=%equibit_bin%equibit_server.exe %testnet2%
set eqb1m=%equibit_bin%equibit_server.exe %mainnet1%

doskey cli1=%cli1% $*
doskey cli2=%cli2% $*
doskey cli1t=%cli1t% $*
doskey cli2t=%cli2t% $*
doskey cli1m=%cli1m% $*

doskey eqb1=%eqb1% $*
doskey eqb2=%eqb2% $*
doskey eqb1t=%eqb1t% $*
doskey eqb2t=%eqb2t% $*
doskey eqb1m=%eqb1m% $*
