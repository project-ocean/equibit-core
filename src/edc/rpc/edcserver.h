// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "rpc/server.h"

class CRPCCommand;

namespace EDCRPCServer
{
    void OnStarted(boost::function<void ()> slot);
    void OnStopped(boost::function<void ()> slot);
    void OnPreCommand(boost::function<void (const CRPCCommand&)> slot);
    void OnPostCommand(boost::function<void (const CRPCCommand&)> slot);
}

/** Query whether RPC is running */
bool edcIsRPCRunning();

/**
 * Set the RPC warmup status.  When this is done, all RPC calls will error out
 * immediately with RPC_IN_WARMUP.
 */
void edcSetRPCWarmupStatus(const std::string& newStatus);

/* Mark warmup as done.  RPC calls will be processed from now on.  */
void edcSetRPCWarmupFinished();

/* returns the current warmup state.  */
bool edcRPCIsInWarmup(std::string *statusOut);

/** Set the factory function for timers */
void edcRPCSetTimerInterface(RPCTimerInterface *iface);

/** Set the factory function for timer, but only, if unset */
void edcRPCSetTimerInterfaceIfUnset(RPCTimerInterface *iface);

/** Unset factory function for timers */
void edcRPCUnsetTimerInterface(RPCTimerInterface *iface);

/**
 * Run func nSeconds from now.
 * Overrides previous timer <name> (if any).
 */
void edcRPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds);

/**
 * Equibit RPC command dispatcher.
 */
class CEDCRPCTable
{
private:
    std::map<std::string, const CRPCCommand*> mapCommands;
public:
    CEDCRPCTable();
    const CRPCCommand* operator[](const std::string& name) const;
    std::string help(const std::string& name) const;

    /**
     * Execute a method.
     * @param method   Method to execute
     * @param params   UniValue Array of arguments (JSON objects)
     * @returns Result of the call.
     * @throws an exception (UniValue) when an error happens.
     */
    UniValue execute(const std::string &method, const UniValue &params) const;

    /**
    * Returns a list of registered commands
    * @returns List of registered commands.
    */
    std::vector<std::string> listCommands() const;


    /**
     * Appends a CRPCCommand to the dispatch table.
     * Returns false if RPC server is already running (dump concurrency protection).
     * Commands cannot be overwritten (returns false).
     */
    bool appendCommand(const std::string& name, const CRPCCommand* pcmd);
};

extern CEDCRPCTable edcTableRPC;

double edcGetDifficulty(const CBlockIndex* blockindex = NULL);

void edcEnsureWalletIsUnlocked();

bool edcStartRPC();
void edcInterruptRPC();
void edcStopRPC();
void edcRPCNotifyBlockChange(bool ibd, const CBlockIndex *);
