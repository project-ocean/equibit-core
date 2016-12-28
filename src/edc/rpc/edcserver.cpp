// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/rpc/edcserver.h"

#include "edc/edcbase58.h"
#include "edc/edcinit.h"
#include "random.h"
#include "sync.h"
#include "edc/edcui_interface.h"
#include "edc/edcutil.h"
#include "utilstrencodings.h"

#include <univalue.h>

#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_upper()

#include <memory> // for unique_ptr

using namespace RPCServer;
using namespace std;

namespace
{

bool fRPCRunning = false;
bool fRPCInWarmup = true;
std::string rpcWarmupStatus("Equibit RPC server started");
CCriticalSection cs_rpcWarmup;

/* Timer-creating functions */
RPCTimerInterface* timerInterface = NULL;

/* Map of name to timer. */
static std::map<std::string, std::unique_ptr<RPCTimerBase> > deadlineTimers;

struct CRPCSignals
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CRPCCommand&)> PreCommand;
    boost::signals2::signal<void (const CRPCCommand&)> PostCommand;
} g_rpcSignals;

};


void EDCRPCServer::OnStarted(boost::function<void ()> slot)
{
    g_rpcSignals.Started.connect(slot);
}

void EDCRPCServer::OnStopped(boost::function<void ()> slot)
{
    g_rpcSignals.Stopped.connect(slot);
}

void EDCRPCServer::OnPreCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PreCommand.connect(boost::bind(slot, _1));
}

void EDCRPCServer::OnPostCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PostCommand.connect(boost::bind(slot, _1));
}

bool edcStartRPC()
{
    edcLogPrint("rpc", "Starting Equibit RPC\n");
    fRPCRunning = true;
    g_rpcSignals.Started();
    return true;
}

void edcInterruptRPC()
{
    edcLogPrint("rpc", "Interrupting Equibit RPC\n");
    // Interrupt e.g. running longpolls
    fRPCRunning = false;
}

void edcStopRPC()
{
    edcLogPrint("rpc", "Stopping Equibit RPC\n");
    deadlineTimers.clear();
    g_rpcSignals.Stopped();
}

bool edcIsRPCRunning()
{
    return fRPCRunning;
}

void edcSetRPCWarmupStatus(const std::string& newStatus)
{
    LOCK(cs_rpcWarmup);
    rpcWarmupStatus = newStatus;
}

void edcSetRPCWarmupFinished()
{
    LOCK(cs_rpcWarmup);
    assert(fRPCInWarmup);
    fRPCInWarmup = false;
}

bool edcRPCIsInWarmup(std::string *outStatus)
{
    LOCK(cs_rpcWarmup);
    if (outStatus)
        *outStatus = rpcWarmupStatus;
    return fRPCInWarmup;
}

void edcRPCSetTimerInterfaceIfUnset(RPCTimerInterface *iface)
{
    if (!timerInterface)
        timerInterface = iface;
}

void edcRPCSetTimerInterface(RPCTimerInterface *iface)
{
    timerInterface = iface;
}

void edcRPCUnsetTimerInterface(RPCTimerInterface *iface)
{
    if (timerInterface == iface)
        timerInterface = NULL;
}

void edcRPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds)
{
    if (!timerInterface)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No timer handler registered for RPC");
    deadlineTimers.erase(name);

    edcLogPrint("rpc", "queue run of timer %s in %i seconds (using %s)\n", name, nSeconds, timerInterface->Name());

	deadlineTimers.emplace(name, std::unique_ptr<RPCTimerBase>(timerInterface->NewTimer(func, nSeconds*1000)));
}

/**
 * Note: This interface may still be subject to change.
 */

std::string CEDCRPCTable::help(const std::string& strCommand) const
{
    string strRet;
    string category;
    set<rpcfn_type> setDone;
    vector<pair<string, const CRPCCommand*> > vCommands;

    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
        vCommands.push_back(make_pair(mi->second->category + mi->first, mi->second));
    sort(vCommands.begin(), vCommands.end());

    BOOST_FOREACH(const PAIRTYPE(string, const CRPCCommand*)& command, vCommands)
    {
        const CRPCCommand *pcmd = command.second;
        string strMethod = pcmd->name;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;

        if ((strCommand != "" || pcmd->category == "hidden") && strMethod != strCommand)
            continue;

        try
        {
            UniValue params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        }
        catch (const std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
            {
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));

                if (category != pcmd->category)
                {
                    if (!category.empty())
                        strRet += "\n";
                    category = pcmd->category;
                    string firstLetter = category.substr(0,1);
                    boost::to_upper(firstLetter);
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n";
                }
            }
            strRet += strHelp + "\n";
        }
    }

    if (strRet == "")
        strRet = strprintf("eb_help: unknown command: %s\n", strCommand);

    strRet = strRet.substr(0,strRet.size()-1);

    return strRet;
}

UniValue edchelp(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_help ( \"command\" )\n"
            "\nList all commands, or get help for a specified command.\n"
            "\nArguments:\n"
            "1. \"command\"     (string, optional) The command to get help on\n"
            "\nResult:\n"
            "\"text\"     (string) The help text\n"
        );

    string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    return edcTableRPC.help(strCommand);
}

void StartShutdown();

UniValue edcstop(const UniValue& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_stop\n"
            "\nStop Equibit server.");
    // Event loop will exit after current HTTP requests have been handled, so
    // this reply will get back to the client.
    StartShutdown();
    return "Bitcoin/Equibit server stopping";
}

/**
 * Call Table
 */
static const CRPCCommand vRPCCommands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    /* Overall control/query calls */
    { "control",            "eb_help",                &edchelp,                   true  },
    { "control",            "eb_stop",                &edcstop,                   true  },
};

CEDCRPCTable::CEDCRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CEDCRPCTable::operator[](const std::string &name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

bool CEDCRPCTable::appendCommand(const std::string& name, const CRPCCommand* pcmd)
{
    if (edcIsRPCRunning())
        return false;

    // don't allow overwriting for now
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it != mapCommands.end())
        return false;

    mapCommands[name] = pcmd;
    return true;
}

UniValue CEDCRPCTable::execute(const std::string &strMethod, const UniValue &params) const
{
    // Return immediately if in warmup
    {
        LOCK(cs_rpcWarmup);
        if (fRPCInWarmup)
            throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus);
    }

    // Find method
    const CRPCCommand *pcmd = edcTableRPC[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    g_rpcSignals.PreCommand(*pcmd);

    try
    {
        // Execute
        return pcmd->actor(params, false);
    }
    catch (const std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }

    g_rpcSignals.PostCommand(*pcmd);
}

std::vector<std::string> CEDCRPCTable::listCommands() const
{
    std::vector<std::string> commandList;
    typedef std::map<std::string, const CRPCCommand*> commandMap;

    std::transform( mapCommands.begin(), mapCommands.end(),
                   std::back_inserter(commandList),
                   boost::bind(&commandMap::value_type::first,_1) );
    return commandList;
}

CEDCRPCTable	edcTableRPC;
