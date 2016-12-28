// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once


/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

/** Register block chain RPC commands */
void edcRegisterBlockchainRPCCommands( CEDCRPCTable & edcTableRPC);

/** Register P2P networking RPC commands */
void edcRegisterNetRPCCommands(CEDCRPCTable & edcTableRPC);

/** Register miscellaneous RPC commands */
void edcRegisterMiscRPCCommands(CEDCRPCTable & edcTableRPC);

/** Register mining RPC commands */
void edcRegisterMiningRPCCommands(CEDCRPCTable & edcTableRPC);

/** Register raw transaction RPC commands */
void edcRegisterRawTransactionRPCCommands(CEDCRPCTable & edcTableRPC);

/** Register Issuer related RPC commands */
void edcRegisterIssuerRPCCommands(CEDCRPCTable & edcTableRPC);

/** Register messaging related RPC commands */
void edcRegisterMessagingRPCCommands(CEDCRPCTable & edcTableRPC);

/** Register web-of-trust related RPC commands */
void edcRegisterWoTRPCCommands(CEDCRPCTable & edcTableRPC);

/** Register polling related RPC commands */
void edcRegisterPollingRPCCommands(CEDCRPCTable & edcTableRPC);

/** Register proxy related RPC commands */
void edcRegisterProxyRPCCommands(CEDCRPCTable & edcTableRPC);

inline void edcRegisterAllCoreRPCCommands(CEDCRPCTable & t)
{
    edcRegisterBlockchainRPCCommands(t);
    edcRegisterNetRPCCommands(t);
    edcRegisterMiscRPCCommands(t);
    edcRegisterMiningRPCCommands(t);
    edcRegisterRawTransactionRPCCommands(t);
	edcRegisterIssuerRPCCommands(t);
	edcRegisterMessagingRPCCommands(t);
	edcRegisterWoTRPCCommands(t);
	edcRegisterPollingRPCCommands(t);
	edcRegisterProxyRPCCommands(t);
}

