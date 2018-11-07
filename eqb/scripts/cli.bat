@echo off

rem -------------------------------------------------------
rem A batch script to simplify the execution of Equibit-CLI 
rem Usage: cli getblockchaininfo 
rem Setup: Specify your own parameters, including data directory below 
rem -------------------------------------------------------

echo using parameters %*
set port=18331
set net=regtest
set user=equibit
set pass=equibit
set dir=C:\Users\RezaSoltani\Projects\equibit\data\node0
echo using directory %dir%, port %port% and net %net%
echo executing CLI..
equibit-cli -datadir=%dir% -rpcport=%port% -%net% -rpcuser=%user% -rpcpassword=%pass% %*
