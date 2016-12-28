// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once 

#include <string>
#include <map>

class EDCHTTPRequest;

/** Start Equibit HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been started.
 */
bool edcStartHTTPRPC();

/** Interrupt Equibit HTTP RPC subsystem.
 */
void edcInterruptHTTPRPC();

/** Stop Equibit HTTP RPC subsystem.
 * Precondition; Equibit HTTP and RPC has been stopped.
 */
void edcStopHTTPRPC();

/** Start Equibit HTTP REST subsystem.
 * Precondition; Equibit HTTP and RPC has been started.
 */
bool edcStartREST();

/** Interrupt RPC REST subsystem.
 */
void edcInterruptREST();

/** Stop Equibit HTTP REST subsystem.
 * Precondition; Equibit HTTP and RPC has been stopped.
 */
void edcStopREST();
