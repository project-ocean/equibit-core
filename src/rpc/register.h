// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPCREGISTER_H
#define BITCOIN_RPCREGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

/** Register block chain RPC commands */
void RegisterBlockchainRPCCommands(CRPCTable &tableRPC);
/** Register P2P networking RPC commands */
void RegisterNetRPCCommands(CRPCTable &tableRPC);
/** Register miscellaneous RPC commands */
void RegisterMiscRPCCommands(CRPCTable &tableRPC);
/** Register mining RPC commands */
void RegisterMiningRPCCommands(CRPCTable &tableRPC);
/** Register raw transaction RPC commands */
void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC);

/** Register Issuer related RPC commands */
void RegisterIssuerRPCCommands(CRPCTable & tableRPC);
/** Register messaging related RPC commands */
void RegisterMessagingRPCCommands(CRPCTable & tableRPC);
/** Register web-of-trust related RPC commands */
void RegisterWoTRPCCommands(CRPCTable & tableRPC);
/** Register polling related RPC commands */
void RegisterPollingRPCCommands(CRPCTable & tableRPC);
/** Register proxy related RPC commands */
void RegisterProxyRPCCommands(CRPCTable & tableRPC);
static inline void RegisterAllCoreRPCCommands(CRPCTable &t)
{
    RegisterBlockchainRPCCommands(t);
    RegisterNetRPCCommands(t);
    RegisterMiscRPCCommands(t);
    RegisterMiningRPCCommands(t);
    RegisterRawTransactionRPCCommands(t);
    RegisterIssuerRPCCommands(t);
    RegisterMessagingRPCCommands(t);
    RegisterWoTRPCCommands(t);
    RegisterPollingRPCCommands(t);
    RegisterProxyRPCCommands(t);
}

#endif
