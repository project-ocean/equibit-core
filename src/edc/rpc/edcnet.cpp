// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/rpc/edcserver.h"

#include "edc/edcchainparams.h"
#include "clientversion.h"
#include "edc/edcmain.h"
#include "edc/edcnet.h"
#include "edc/edcnetbase.h"
#include "protocol.h"
#include "sync.h"
#include "timedata.h"
#include "edc/edcui_interface.h"
#include "edc/edcutil.h"
#include "utilstrencodings.h"
#include "version.h"
#include "edc/edcapp.h"
#include "edc/edcparams.h"


#include <boost/foreach.hpp>

#include <univalue.h>

using namespace std;

UniValue edcgetconnectioncount(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getconnectioncount\n"
            "\nReturns the number of connections to other nodes.\n"
            "\nResult:\n"
            "n          (numeric) The connection count\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getconnectioncount", "")
            + HelpExampleRpc("eb_getconnectioncount", "")
        );

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
 
    return (int)theApp.connman()->GetNodeCount(CEDCConnman::CONNECTIONS_ALL);
}

UniValue edcping(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_ping\n"
            "\nRequests that a ping be sent to all other nodes, to measure ping time.\n"
            "Results provided in eb_getpeerinfo, pingtime and pingwait fields are decimal seconds.\n"
            "Ping command is handled in queue with all other commands, so it measures processing backlog, not just network ping.\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_ping", "")
            + HelpExampleRpc("eb_ping", "")
        );

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
 
    // Request that each node send a ping during next message processing pass
    theApp.connman()->ForEachNode([](CEDCNode* pnode) 
	{
        pnode->fPingQueued = true;
    });

    return NullUniValue;
}

UniValue edcgetpeerinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getpeerinfo\n"
            "\nReturns data about each connected network node as a json array of objects.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"id\": n,                   (numeric) Peer index\n"
            "    \"addr\":\"host:port\",      (string) The ip address and port of the peer\n"
            "    \"addrlocal\":\"ip:port\",   (string) local address\n"
            "    \"services\":\"xxxxxxxxxxxxxxxx\",   (string) The services offered\n"
            "    \"relaytxes\":true|false,    (boolean) Whether peer has asked us to relay transactions to it\n"
            "    \"lastsend\": ttt,           (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last send\n"
            "    \"lastrecv\": ttt,           (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last receive\n"
            "    \"bytessent\": n,            (numeric) The total bytes sent\n"
            "    \"bytesrecv\": n,            (numeric) The total bytes received\n"
            "    \"conntime\": ttt,           (numeric) The connection time in seconds since epoch (Jan 1 1970 GMT)\n"
            "    \"timeoffset\": ttt,         (numeric) The time offset in seconds\n"
            "    \"pingtime\": n,             (numeric) ping time (if available)\n"
            "    \"minping\": n,              (numeric) minimum observed ping time (if any at all)\n"
            "    \"pingwait\": n,             (numeric) ping wait (if non-zero)\n"
            "    \"version\": v,              (numeric) The peer version, such as 7001\n"
            "    \"subver\": \"/Satoshi:0.8.5/\",  (string) The string version\n"
            "    \"inbound\": true|false,     (boolean) Inbound (true) or Outbound (false)\n"
            "    \"startingheight\": n,       (numeric) The starting height (block) of the peer\n"
            "    \"banscore\": n,             (numeric) The ban score\n"
            "    \"synced_headers\": n,       (numeric) The last header we have in common with this peer\n"
            "    \"synced_blocks\": n,        (numeric) The last block we have in common with this peer\n"
            "    \"inflight\": [\n"
            "       n,                        (numeric) The heights of blocks we're currently asking from this peer\n"
            "       ...\n"
            "    ]\n"
            "    \"bytessent_per_msg\": {\n"
            "       \"addr\": n,             (numeric) The total bytes sent aggregated by message type\n"
            "       ...\n"
            "    }\n"
            "    \"bytesrecv_per_msg\": {\n"
            "       \"addr\": n,             (numeric) The total bytes received aggregated by message type\n"
            "       ...\n"
            "    }\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getpeerinfo", "")
            + HelpExampleRpc("eb_getpeerinfo", "")
        );

	EDCapp & theApp = EDCapp::singleton();

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    vector<CNodeStats> vstats;
    theApp.connman()->GetNodeStats(vstats);

    UniValue ret(UniValue::VARR);

    BOOST_FOREACH(const CNodeStats& stats, vstats) 
	{
        UniValue obj(UniValue::VOBJ);
        CNodeStateStats statestats;
        bool fStateStats = edcGetNodeStateStats(stats.nodeid, statestats);

        obj.push_back(Pair("id", stats.nodeid));
        obj.push_back(Pair("addr", stats.addrName));
        if (!(stats.addrLocal.empty()))
            obj.push_back(Pair("addrlocal", stats.addrLocal));

        obj.push_back(Pair("services", strprintf("%016x", stats.nServices)));
        obj.push_back(Pair("relaytxes", stats.fRelayTxes));
        obj.push_back(Pair("lastsend", stats.nLastSend));
        obj.push_back(Pair("lastrecv", stats.nLastRecv));
        obj.push_back(Pair("bytessent", stats.nSendBytes));
        obj.push_back(Pair("bytesrecv", stats.nRecvBytes));
        obj.push_back(Pair("conntime", stats.nTimeConnected));
        obj.push_back(Pair("timeoffset", stats.nTimeOffset));
        if (stats.dPingTime > 0.0)
            obj.push_back(Pair("pingtime", stats.dPingTime));
        if (stats.dPingMin < std::numeric_limits<int64_t>::max()/1e6)
            obj.push_back(Pair("minping", stats.dPingMin));
        if (stats.dPingWait > 0.0)
            obj.push_back(Pair("pingwait", stats.dPingWait));
        obj.push_back(Pair("version", stats.nVersion));

        // Use the sanitized form of subver here, to avoid tricksy remote peers from
        // corrupting or modifiying the JSON output by putting special characters in
        // their ver message.
        obj.push_back(Pair("subver", stats.cleanSubVer));
        obj.push_back(Pair("inbound", stats.fInbound));
        obj.push_back(Pair("startingheight", stats.nStartingHeight));
        if (fStateStats) 
		{
            obj.push_back(Pair("banscore", statestats.nMisbehavior));
            obj.push_back(Pair("synced_headers", statestats.nSyncHeight));
            obj.push_back(Pair("synced_blocks", statestats.nCommonHeight));
            UniValue heights(UniValue::VARR);
            BOOST_FOREACH(int height, statestats.vHeightInFlight) 
			{
                heights.push_back(height);
            }
            obj.push_back(Pair("inflight", heights));
        }
        obj.push_back(Pair("whitelisted", stats.fWhitelisted));

        UniValue sendPerMsgCmd(UniValue::VOBJ);
        BOOST_FOREACH(const mapMsgCmdSize::value_type &i, stats.mapSendBytesPerMsgCmd) 
		{
            if (i.second > 0)
                sendPerMsgCmd.push_back(Pair(i.first, i.second));
        }
        obj.push_back(Pair("bytessent_per_msg", sendPerMsgCmd));

        UniValue recvPerMsgCmd(UniValue::VOBJ);
        BOOST_FOREACH(const mapMsgCmdSize::value_type &i, stats.mapRecvBytesPerMsgCmd) 
		{
            if (i.second > 0)
                recvPerMsgCmd.push_back(Pair(i.first, i.second));
        }
        obj.push_back(Pair("bytesrecv_per_msg", recvPerMsgCmd));

        ret.push_back(obj);
    }

    return ret;
}

UniValue edcaddnode(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    string strCommand;
    if (params.size() == 2)
        strCommand = params[1].get_str();
    if (fHelp || params.size() != 2 ||
        (strCommand != "onetry" && strCommand != "add" && strCommand != "remove"))
        throw runtime_error(
            "eb_addnode \"node\" \"add|remove|onetry\"\n"
            "\nAttempts add or remove a node from the addnode list.\n"
            "Or try a connection to a node once.\n"
            "\nArguments:\n"
            "1. \"node\"     (string, required) The node (see eb_getpeerinfo for nodes)\n"
            "2. \"command\"  (string, required) 'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_addnode", "\"192.168.0.6:8333\" \"onetry\"")
            + HelpExampleRpc("eb_addnode", "\"192.168.0.6:8333\", \"onetry\"")
        );

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    string strNode = params[0].get_str();

    if (strCommand == "onetry")
    {
        CAddress addr;
        theApp.connman()->OpenNetworkConnection(addr, false, NULL, NULL, strNode.c_str());
        return NullUniValue;
    }

    if (strCommand == "add")
    {
        if (theApp.connman()->AddNode(strNode))
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Node already added");
    }
    else if(strCommand == "remove")
    {
        if (theApp.connman()->RemoveAddedNode(strNode))
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
    }

    return NullUniValue;
}

UniValue edcdisconnectnode(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_disconnectnode \"node\" \n"
            "\nImmediately disconnects from the specified node.\n"
            "\nArguments:\n"
            "1. \"node\"     (string, required) The node (see eb_getpeerinfo for nodes)\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_disconnectnode", "\"192.168.0.6:8333\"")
            + HelpExampleRpc("eb_disconnectnode", "\"192.168.0.6:8333\"")
        );

	EDCapp & theApp = EDCapp::singleton();

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

	// Disconnect secure node as well
    bool ret = theApp.connman()->DisconnectNode(params[0].get_str());
    if (!ret)
        throw JSONRPCError(RPC_CLIENT_NODE_NOT_CONNECTED, "Node not found in connected nodes");

    return NullUniValue;
}

UniValue edcgetaddednodeinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_getaddednodeinfo ( \"node\" )\n"
            "\nReturns information about the given added node, or all added nodes\n"
            "(note that onetry addnodes are not listed here)\n"
            "\nArguments:\n"
            "1. \"node\"   (string, optional) If provided, return information about this specific node, otherwise all nodes are returned.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
			"    \"addednode\" : \"192.168.0.201\",   (string) The node ip address or name (as provided to addnode)\n"
            "    \"connected\" : true|false,          (boolean) If connected\n"
            "    \"addresses\" : [\n"
            "       {\n"
			"         \"address\" : \"192.168.0.201:8333\",  (string) The bitcoin server IP and port we're connected to\n"

            "         \"connected\" : \"outbound\"           (string) connection, inbound or outbound\n"
            "       }\n"
            "     ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getaddednodeinfo", "true")
            + HelpExampleCli("eb_getaddednodeinfo", "true \"192.168.0.201\"")
            + HelpExampleRpc("eb_getaddednodeinfo", "true, \"192.168.0.201\"")
        );

	EDCapp & theApp = EDCapp::singleton();

	if(theApp.connman())
		throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<AddedNodeInfo> vInfo = theApp.connman()->GetAddedNodeInfo();

    if (params.size() == 1) 
	{
        bool found = false;
        for (const AddedNodeInfo& info : vInfo) 
		{
            if (info.strAddedNode == params[0].get_str()) 
			{
                vInfo.assign(1, info);
                found = true;
                break;
            }
        }
        if (!found)
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
    }

    UniValue ret(UniValue::VARR);

	for (const AddedNodeInfo& info : vInfo) 
	{
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("addednode", info.strAddedNode));
        obj.push_back(Pair("connected", info.fConnected));

        UniValue addresses(UniValue::VARR);
        if (info.fConnected) 
		{
            UniValue address(UniValue::VOBJ);
            address.push_back(Pair("address", info.resolvedAddress.ToString()));
            address.push_back(Pair("connected", info.fInbound ? "inbound" : "outbound"));
            addresses.push_back(address);
        }
        obj.push_back(Pair("addresses", addresses));
        ret.push_back(obj);
    }

    return ret;
}

UniValue edcgetnettotals(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "eb_getnettotals\n"
            "\nReturns information about network traffic, including bytes in, bytes out,\n"
            "and current time.\n"
            "\nResult:\n"
            "{\n"
            "  \"totalbytesrecv\": n,   (numeric) Total bytes received\n"
            "  \"totalbytessent\": n,   (numeric) Total bytes sent\n"
            "  \"timemillis\": t,       (numeric) Total cpu time\n"
            "  \"uploadtarget\":\n"
            "  {\n"
            "    \"timeframe\": n,                         (numeric) Length of the measuring timeframe in seconds\n"
            "    \"target\": n,                            (numeric) Target in bytes\n"
            "    \"target_reached\": true|false,           (boolean) True if target is reached\n"
            "    \"serve_historical_blocks\": true|false,  (boolean) True if serving historical blocks\n"
            "    \"bytes_left_in_cycle\": t,               (numeric) Bytes left in current time cycle\n"
            "    \"time_left_in_cycle\": t                 (numeric) Seconds left in current time cycle\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getnettotals", "")
            + HelpExampleRpc("eb_getnettotals", "")
       );

	EDCapp & theApp = EDCapp::singleton();
	CEDCConnman * connman = theApp.connman().get();

    if(!connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("totalbytesrecv", connman->GetTotalBytesRecv()));
    obj.push_back(Pair("totalbytessent", connman->GetTotalBytesSent()));
    obj.push_back(Pair("timemillis", GetTimeMillis()));

    UniValue outboundLimit(UniValue::VOBJ);
    outboundLimit.push_back(Pair("timeframe", connman->GetMaxOutboundTimeframe()));
    outboundLimit.push_back(Pair("target", connman->GetMaxOutboundTarget()));
    outboundLimit.push_back(Pair("target_reached", connman->OutboundTargetReached(false)));
    outboundLimit.push_back(Pair("serve_historical_blocks", !connman->OutboundTargetReached(true)));
    outboundLimit.push_back(Pair("bytes_left_in_cycle", connman->GetOutboundTargetBytesLeft()));
    outboundLimit.push_back(Pair("time_left_in_cycle", connman->GetMaxOutboundTimeLeftInCycle()));
    obj.push_back(Pair("uploadtarget", outboundLimit));
    return obj;
}

static UniValue GetNetworksInfo()
{
    UniValue networks(UniValue::VARR);
    for(int n=0; n<NET_MAX; ++n)
    {
        enum Network network = static_cast<enum Network>(n);
        if(network == NET_UNROUTABLE)
            continue;

        proxyType proxy;
        UniValue obj(UniValue::VOBJ);
        edcGetProxy(network, proxy);

        obj.push_back(Pair("name", GetNetworkName(network)));
        obj.push_back(Pair("limited", edcIsLimited(network)));
        obj.push_back(Pair("reachable", edcIsReachable(network)));
        obj.push_back(Pair("proxy", proxy.IsValid() ? proxy.proxy.ToStringIPPort() : string()));
        obj.push_back(Pair("proxy_randomize_credentials", proxy.randomize_credentials));
        networks.push_back(obj);
    }
    return networks;
}

int64_t edcGetTimeOffset();

UniValue edcgetnetworkinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getnetworkinfo\n"
            "Returns an object containing various state info regarding P2P networking.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,                      (numeric) the server version\n"
            "  \"subversion\": \"/Satoshi:x.x.x/\",     (string) the server subversion string\n"
            "  \"protocolversion\": xxxxx,              (numeric) the protocol version\n"
            "  \"localservices\": \"xxxxxxxxxxxxxxxx\", (string) the services we offer to the network\n"
            "  \"localrelay\": true|false,              (bool) true if transaction relay is requested from peers\n"

            "  \"timeoffset\": xxxxx,                   (numeric) the time offset\n"
            "  \"connections\": xxxxx,                  (numeric) the number of connections\n"
            "  \"networks\": [                          (array) information per network\n"
            "  {\n"
            "    \"name\": \"xxx\",                     (string) network (ipv4, ipv6 or onion)\n"
            "    \"limited\": true|false,               (boolean) is the network limited using -eb_onlynet?\n"
            "    \"reachable\": true|false,             (boolean) is the network reachable?\n"
            "    \"proxy\": \"host:port\"               (string) the proxy that is used for this network, or empty if none\n"
            "  }\n"
            "  ,...\n"
            "  ],\n"
            "  \"relayfee\": x.xxxxxxxx,                (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"localaddresses\": [                    (array) list of local addresses\n"
            "  {\n"
            "    \"address\": \"xxxx\",                 (string) network address\n"
            "    \"port\": xxx,                         (numeric) network port\n"
            "    \"score\": xxx                         (numeric) relative score\n"
            "  }\n"
            "  ,...\n"
            "  ]\n"
            "  \"warnings\": \"...\"                    (string) any network warnings (such as alert messages) \n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getnetworkinfo", "")
            + HelpExampleRpc("eb_getnetworkinfo", "")
        );

    LOCK(EDC_cs_main);

	EDCapp & theApp = EDCapp::singleton();
	EDCparams & theParams = EDCparams::singleton();

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version",       CLIENT_VERSION));
    obj.push_back(Pair("subversion",    theApp.strSubVersion() ));
    obj.push_back(Pair("protocolversion",PROTOCOL_VERSION));
	if(theApp.connman())
		obj.push_back(Pair("localservices", strprintf("%016x", theApp.connman()->GetLocalServices())));
	obj.push_back(Pair("localreply",    theParams.blocksonly));
    obj.push_back(Pair("timeoffset",    edcGetTimeOffset()));
    if(theApp.connman())
        obj.push_back(Pair("connections",   (int)theApp.connman()->GetNodeCount(CEDCConnman::CONNECTIONS_ALL)));
    obj.push_back(Pair("networks",      GetNetworksInfo()));
    obj.push_back(Pair("relayfee",      ValueFromAmount(theApp.minRelayTxFee().GetFeePerK())));
    UniValue localAddresses(UniValue::VARR);
    {
        LOCK(theApp.mapLocalHostCS());
        BOOST_FOREACH(const PAIRTYPE(CNetAddr, LocalServiceInfo) &item, theApp.mapLocalHost())
        {
            UniValue rec(UniValue::VOBJ);
            rec.push_back(Pair("address", item.first.ToString()));
            rec.push_back(Pair("port", item.second.nPort));
            rec.push_back(Pair("score", item.second.nScore));
            localAddresses.push_back(rec);
        }
    }
    obj.push_back(Pair("localaddresses", localAddresses));
    obj.push_back(Pair("warnings",       edcGetWarnings("statusbar")));
    return obj;
}

UniValue edcsetban(const UniValue& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 2)
        strCommand = params[1].get_str();
    if (fHelp || params.size() < 2 ||
        (strCommand != "add" && strCommand != "remove"))
        throw runtime_error(
                            "eb_setban \"ip(/netmask)\" \"add|remove\" (bantime) (absolute)\n"
                            "\nAttempts add or remove a IP/Subnet from the banned list.\n"
                            "\nArguments:\n"
                            "1. \"ip(/netmask)\" (string, required) The IP/Subnet (see eb_getpeerinfo for nodes ip) with a optional netmask (default is /32 = single ip)\n"
                            "2. \"command\"      (string, required) 'add' to add a IP/Subnet to the list, 'remove' to remove a IP/Subnet from the list\n"
                            "3. \"bantime\"      (numeric, optional) time in seconds how long (or until when if [absolute] is set) the ip is banned (0 or empty means using the default time of 24h which can also be overwritten by the -eb_bantime startup argument)\n"
                            "4. \"absolute\"     (boolean, optional) If set, the bantime must be a absolute timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("eb_setban", "\"192.168.0.6\" \"add\" 86400")
                            + HelpExampleCli("eb_setban", "\"192.168.0.0/24\" \"add\"")
                            + HelpExampleRpc("eb_setban", "\"192.168.0.6\", \"add\", 86400")
                            );

	EDCapp & theApp = EDCapp::singleton();

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    CSubNet subNet;
    CNetAddr netAddr;
    bool isSubnet = false;

    if (params[0].get_str().find("/") != string::npos)
        isSubnet = true;

    if (!isSubnet) 
	{
        CNetAddr resolved;
        LookupHost(params[0].get_str().c_str(), resolved, false);
        netAddr = resolved;
    }
    else
		LookupSubNet(params[0].get_str().c_str(), subNet);

    if (! (isSubnet ? subNet.IsValid() : netAddr.IsValid()) )
        throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Invalid IP/Subnet");

    if (strCommand == "add")
    {
        if (isSubnet ? theApp.connman()->IsBanned(subNet) : theApp.connman()->IsBanned(netAddr))
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: IP/Subnet already banned");

        int64_t banTime = 0; //use standard bantime if not specified
        if (params.size() >= 3 && !params[2].isNull())
            banTime = params[2].get_int64();

        bool absolute = false;
        if (params.size() == 4 && params[3].isTrue())
            absolute = true;

        isSubnet ? theApp.connman()->Ban(subNet, BanReasonManuallyAdded, banTime, absolute) : theApp.connman()->Ban(netAddr, BanReasonManuallyAdded, banTime, absolute);
    }
    else if(strCommand == "remove")
    {
        if (!( isSubnet ? theApp.connman()->Unban(subNet) : theApp.connman()->Unban(netAddr) ))
            throw JSONRPCError(RPC_MISC_ERROR, "Error: Unban failed");
    }

    return NullUniValue;
}

UniValue edclistbanned(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                            "eb_listbanned\n"
                            "\nList all banned IPs/Subnets.\n"
                            "\nExamples:\n"
                            + HelpExampleCli("eb_listbanned", "")
                            + HelpExampleRpc("eb_listbanned", "")
                            );

	EDCapp & theApp = EDCapp::singleton();

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    banmap_t banMap;
    theApp.connman()->GetBanned(banMap);

    UniValue bannedAddresses(UniValue::VARR);
    for (banmap_t::iterator it = banMap.begin(); it != banMap.end(); it++)
    {
        CBanEntry banEntry = (*it).second;
        UniValue rec(UniValue::VOBJ);
        rec.push_back(Pair("address", (*it).first.ToString()));
        rec.push_back(Pair("banned_until", banEntry.nBanUntil));
        rec.push_back(Pair("ban_created", banEntry.nCreateTime));
        rec.push_back(Pair("ban_reason", banEntry.banReasonToString()));

        bannedAddresses.push_back(rec);
    }

    return bannedAddresses;
}

UniValue edcclearbanned(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                            "eb_clearbanned\n"
                            "\nClear all banned IPs.\n"
                            "\nExamples:\n"
                            + HelpExampleCli("eb_clearbanned", "")
                            + HelpExampleRpc("eb_clearbanned", "")
                            );

	EDCapp & theApp = EDCapp::singleton();

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    theApp.connman()->ClearBanned();

    return NullUniValue;
}

static const CRPCCommand edcCommands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "network",            "eb_getconnectioncount",     &edcgetconnectioncount,     true  },
    { "network",            "eb_ping",                   &edcping,                   true  },
    { "network",            "eb_getpeerinfo",            &edcgetpeerinfo,            true  },
    { "network",            "eb_addnode",                &edcaddnode,                true  },
    { "network",            "eb_disconnectnode",         &edcdisconnectnode,         true  },
    { "network",            "eb_getaddednodeinfo",       &edcgetaddednodeinfo,       true  },
    { "network",            "eb_getnettotals",           &edcgetnettotals,           true  },
    { "network",            "eb_getnetworkinfo",         &edcgetnetworkinfo,         true  },
    { "network",            "eb_setban",                 &edcsetban,                 true  },
    { "network",            "eb_listbanned",             &edclistbanned,             true  },
    { "network",            "eb_clearbanned",            &edcclearbanned,            true  },
};

void edcRegisterNetRPCCommands(CEDCRPCTable & t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        t.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
