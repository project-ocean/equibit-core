// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "edcnet.h"
#include "edcparams.h"
#include "edcutil.h"
#include "edcapp.h"
#include "edcparams.h"

#include "addrman.h"
#include "edcchainparams.h"
#include "clientversion.h"
#include "edc/consensus/edcconsensus.h"
#include "crypto/common.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "edc/primitives/edctransaction.h"
#include "scheduler.h"
#include "edcui_interface.h"
#include "utilstrencodings.h"
#include "edc/message/edcmessage.h"
#include "edc/wallet/edcwallet.h"

#ifdef WIN32
#include <string.h>
#else
#include <fcntl.h>
#endif

#ifdef USE_UPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <math.h>

// Dump addresses to peers.dat and banlist.dat every 15 minutes (900s)
#define DUMP_ADDRESSES_INTERVAL 900

// We add a random period time (0 to 1 seconds) to feeler connections to prevent synchronization.
#define FEELER_SLEEP_WINDOW 1

#if !defined(HAVE_MSG_NOSIGNAL) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

// Fix for ancient MinGW versions, that don't have defined these in ws2tcpip.h.
// Todo: Can be removed when our pull-tester is upgraded to a modern MinGW version.
#ifdef WIN32
#ifndef PROTECTION_LEVEL_UNRESTRICTED
#define PROTECTION_LEVEL_UNRESTRICTED 10
#endif
#ifndef IPV6_PROTECTION_LEVEL
#define IPV6_PROTECTION_LEVEL 23
#endif
#endif


namespace 
{

const std::string NET_MESSAGE_COMMAND_OTHER = "*other*";

const uint64_t RANDOMIZER_ID_NETGROUP = 0x6c0edd8036ef4036ULL; // SHA256("netgroup")[0:8]

bool vfLimited[NET_MAX] = {};
CEDCNode* pnodeLocalHost = NULL;
}

// Signals for message handling
static CEDCNodeSignals g_edcsignals;
CEDCNodeSignals & edcGetNodeSignals() { return g_edcsignals; }

void CEDCConnman::AddOneShot(const std::string& strDest)
{
    LOCK(cs_vOneShots);
    vOneShots.push_back(strDest);
}

unsigned short edcGetListenPort()
{
	EDCparams & params = EDCparams::singleton();
    return static_cast<unsigned short>(params.port);
}

unsigned short edcGetListenSecurePort()
{
	EDCparams & params = EDCparams::singleton();
    return static_cast<unsigned short>(params.sport);
}

// find 'best' local address for a particular peer
bool edcGetLocal(CService& addr, const CNetAddr *paddrPeer)
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    if (!params.listen)
        return false;

    int nBestScore = -1;
    int nBestReachability = -1;
    {
        LOCK(theApp.mapLocalHostCS());
        for (std::map<CNetAddr, LocalServiceInfo>::iterator it = theApp.mapLocalHost().begin(); it != theApp.mapLocalHost().end(); it++)
        {
            int nScore = (*it).second.nScore;
            int nReachability = (*it).first.GetReachabilityFrom(paddrPeer);
            if (nReachability > nBestReachability || (nReachability == nBestReachability && nScore > nBestScore))
            {
                addr = CService((*it).first, (*it).second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    return nBestScore >= 0;
}

//! Convert the pnSeeds6 array into usable address objects.
static std::vector<CAddress> convertSeed6(const std::vector<SeedSpec6> &vSeedsIn)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    std::vector<CAddress> vSeedsOut;
    vSeedsOut.reserve(vSeedsIn.size());
    for (std::vector<SeedSpec6>::const_iterator i(vSeedsIn.begin()); i != vSeedsIn.end(); ++i)
    {
        struct in6_addr ip;
        memcpy(&ip, i->addr, sizeof(ip));
        CAddress addr(CService(ip, i->port), NODE_NETWORK );
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
    return vSeedsOut;
}

int64_t edcGetAdjustedTime();

// get best local address for a particular peer as a CAddress
// Otherwise, return the unroutable 0.0.0.0 but filled in with
// the normal parameters, since the IP may be changed to a useful
// one by discovery.
CAddress edcGetLocalAddress(const CNetAddr *paddrPeer, ServiceFlags nLocalServices)
{
    CAddress ret(CService(CNetAddr(), edcGetListenPort()), NODE_NONE);
    CService addr;
    if (edcGetLocal(addr, paddrPeer))
    {
        ret = CAddress(addr, nLocalServices );
    }
    ret.nTime = edcGetAdjustedTime();
    return ret;
}

int edcGetnScore(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    if (theApp.mapLocalHost().count(addr) == LOCAL_NONE)
        return 0;
    return theApp.mapLocalHost()[addr].nScore;
}

// Is our peer's addrLocal potentially useful as an external IP source?
bool IsPeerAddrLocalGood(CEDCNode *pnode)
{
	EDCparams & params = EDCparams::singleton();
    return params.discover && pnode->addr.IsRoutable() && pnode->addrLocal.IsRoutable() &&
           !edcIsLimited(pnode->addrLocal.GetNetwork());
}

// pushes our own address to a peer
void AdvertiseLocal(CEDCNode *pnode)
{
	EDCparams & params = EDCparams::singleton();

    if (params.listen && pnode->fSuccessfullyConnected)
    {
        CAddress addrLocal = edcGetLocalAddress(&pnode->addr, pnode->GetLocalServices());
        // If discovery is enabled, sometimes give our peer the address it
        // tells us that it sees us as in case it has a better idea of our
        // address than we do.
        if (IsPeerAddrLocalGood(pnode) && (!addrLocal.IsRoutable() ||
             GetRand((edcGetnScore(addrLocal) > LOCAL_MANUAL) ? 8:2) == 0))
        {
            addrLocal.SetIP(pnode->addrLocal);
        }
        if (addrLocal.IsRoutable())
        {
            edcLogPrint("net", "AdvertiseLocal: advertising address %s\n", addrLocal.ToString());
            pnode->PushAddress(addrLocal);
        }
    }
}

bool edcRemoveLocal(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    edcLogPrintf("edcRemoveLocal(%s)\n", addr.ToString());
    theApp.mapLocalHost().erase(addr);
    return true;
}

/** Make a particular network entirely off-limits (no automatic connects to it) */
void edcSetLimited(enum Network net, bool fLimited)
{
	EDCapp & theApp = EDCapp::singleton();
    if (net == NET_UNROUTABLE)
        return;
    LOCK(theApp.mapLocalHostCS());
    vfLimited[net] = fLimited;
}

bool edcIsLimited(enum Network net)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    return vfLimited[net];
}

bool edcIsLimited(const CNetAddr &addr)
{
    return edcIsLimited(addr.GetNetwork());
}

/** vote for a local address */
bool edcSeenLocal(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    {
        LOCK(theApp.mapLocalHostCS());
        if (theApp.mapLocalHost().count(addr) == 0)
            return false;
        theApp.mapLocalHost()[addr].nScore++;
    }
    return true;
}


/** check whether a given address is potentially local */
bool edcIsLocal(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    return theApp.mapLocalHost().count(addr) > 0;
}

/** check whether a given network is one we can probably connect to */
bool edcIsReachable(enum Network net)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    return !vfLimited[net];
}

/** check whether a given address is in a network we can probably connect to */
bool edcIsReachable(const CNetAddr& addr)
{
    enum Network net = addr.GetNetwork();
    return edcIsReachable(net);
}

CEDCNode* CEDCConnman::FindNode(const CNetAddr& ip, bool secure )
{
    LOCK(cs_vNodes);
	if(!secure)
	{
    	BOOST_FOREACH(CEDCNode* pnode, vNodes)
        	if ((CNetAddr)pnode->addr == ip)
            	return (pnode);
	}
	else
	{
    	BOOST_FOREACH(CEDCSSLNode* pnode, vSSLNodes)
        	if ((CNetAddr)pnode->addr == ip)
            	return (pnode);
	}
    return NULL;
}

CEDCNode* CEDCConnman::FindNode(const CSubNet& subNet, bool secure )
{
    LOCK(cs_vNodes);
	if(!secure)
	{
	    BOOST_FOREACH(CEDCNode* pnode, vNodes)
    	if (subNet.Match((CNetAddr)pnode->addr))
        	return (pnode);
	}
	else
	{
	    BOOST_FOREACH(CEDCSSLNode* pnode, vSSLNodes)
    	if (subNet.Match((CNetAddr)pnode->addr))
        	return (pnode);
	}
    return NULL;
}

CEDCNode* CEDCConnman::FindNode(const std::string& addrName, bool secure )
{	
    LOCK(cs_vNodes);
	if(!secure)
	{
    	BOOST_FOREACH(CEDCNode* pnode, vNodes)
       		if (pnode->addrName == addrName)
       	     	return (pnode);
	}
	else
	{
    	BOOST_FOREACH(CEDCSSLNode* pnode, vSSLNodes)
       		if (pnode->addrName == addrName)
       	     	return (pnode);
	}
    return NULL;
}

CEDCNode* CEDCConnman::FindNode(const CService& addr, bool secure )
{
    LOCK(cs_vNodes);
	if(!secure)
	{
	    BOOST_FOREACH(CEDCNode* pnode, vNodes)
   	     	if ((CService)pnode->addr == addr)
            	return (pnode);
	}
	else
	{
	    BOOST_FOREACH(CEDCSSLNode* pnode, vSSLNodes)
   	     	if ((CService)pnode->addr == addr)
            	return (pnode);
	}
    return NULL;
}

void CEDCNode::CloseSocketDisconnect()
{
    fDisconnect = true;

    if (!invalidSocket())
    {
        edcLogPrint("net", "disconnecting peer=%d\n", id);
        closeSocket();
    }

    // in case this fails, we'll empty the recv buffer when the CEDCNode is deleted
    TRY_LOCK(cs_vRecvMsg, lockRecv);
    if (lockRecv)
        vRecvMsg.clear();
}

void CEDCNode::PushVersion()
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    int64_t nTime = (fInbound ? edcGetAdjustedTime() : GetTime());

	CAddress addrYou = (addr.IsRoutable() && !edcIsProxy(addr) ? addr : 
		CAddress(CService(), addr.nServices));

    CAddress addrMe = CAddress(CService(), nLocalServices);

    if (params.logips)
        edcLogPrint("net", "send version message: version %d, blocks=%d, us=%s, them=%s, peer=%d\n", PROTOCOL_VERSION, nMyStartingHeight, addrMe.ToString(), addrYou.ToString(), id);
    else
        edcLogPrint("net", "send version message: version %d, blocks=%d, us=%s, peer=%d\n", PROTOCOL_VERSION, nMyStartingHeight, addrMe.ToString(), id);

    PushMessage(
		NetMsgType::VERSION, 
		PROTOCOL_VERSION, 
		(uint64_t)nLocalServices, 
		nTime, 
		addrYou, 
		addrMe,
        nLocalHostNonce, 
		theApp.strSubVersion(), 
		nMyStartingHeight, 
		!params.blocksonly);
}

void CEDCConnman::DumpBanlist()
{
    SweepBanned(); // clean unused entries (if bantime has expired)

    if (!BannedSetIsDirty())
        return;

    int64_t nStart = GetTimeMillis();

    CEDCBanDB bandb;
    banmap_t banmap;
    SetBannedSetDirty(false);
    GetBanned(banmap);
    if (!bandb.Write(banmap))
        SetBannedSetDirty(true);

    edcLogPrint("net", "Flushed %d banned node ips/subnets to banlist.dat  %dms\n",
        banmap.size(), GetTimeMillis() - nStart);
}

void CEDCConnman::ClearBanned()
{
    {
        LOCK(cs_setBanned);
        setBanned.clear();
        setBannedIsDirty = true;
    }
    DumpBanlist(); //store banlist to disk
	if(clientInterface)
		clientInterface->BannedListChanged();
}

bool CEDCConnman::IsBanned(CNetAddr ip)
{
    bool fResult = false;
    {
        LOCK(cs_setBanned);
        for (banmap_t::iterator it = setBanned.begin(); it != setBanned.end(); it++)
        {
            CSubNet subNet = (*it).first;
            CBanEntry banEntry = (*it).second;

            if(subNet.Match(ip) && GetTime() < banEntry.nBanUntil)
                fResult = true;
        }
    }
    return fResult;
}

bool CEDCConnman::IsBanned(CSubNet subnet)
{
    bool fResult = false;
    {
        LOCK(cs_setBanned);
        banmap_t::iterator i = setBanned.find(subnet);
        if (i != setBanned.end())
        {
            CBanEntry banEntry = (*i).second;
            if (GetTime() < banEntry.nBanUntil)
                fResult = true;
        }
    }
    return fResult;
}

void CEDCConnman::Ban(
	 const CNetAddr & addr, 
	const BanReason & banReason, 
			  int64_t bantimeoffset, 
				 bool sinceUnixEpoch) 
{
    CSubNet subNet(addr);
    Ban(subNet, banReason, bantimeoffset, sinceUnixEpoch);
}

void CEDCConnman::Ban(
	  const CSubNet & subNet, 
	const BanReason & banReason, 
			  int64_t bantimeoffset, 
				 bool sinceUnixEpoch) 
{
    CBanEntry banEntry(GetTime());
    banEntry.banReason = banReason;
    if (bantimeoffset <= 0)
    {
		EDCparams & params = EDCparams::singleton();
        bantimeoffset = params.bantime;
        sinceUnixEpoch = false;
    }
    banEntry.nBanUntil = (sinceUnixEpoch ? 0 : GetTime() )+bantimeoffset;

    {
        LOCK(cs_setBanned);
        if (setBanned[subNet].nBanUntil < banEntry.nBanUntil) 
		{
            setBanned[subNet] = banEntry;
            setBannedIsDirty = true;
        }
        else
            return;
    }
    if(clientInterface)
		clientInterface->BannedListChanged();
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CEDCNode* pnode, vNodes) 
		{
            if (subNet.Match((CNetAddr)pnode->addr))
                pnode->fDisconnect = true;
        }
    }
    if(banReason == BanReasonManuallyAdded)
        DumpBanlist(); //store banlist to disk immediately if user requested ban
}

bool CEDCConnman::Unban(const CNetAddr &addr) 
{
    CSubNet subNet(addr);
    return Unban(subNet);
}

bool CEDCConnman::Unban(const CSubNet &subNet) 
{
    {
        LOCK(cs_setBanned);
        if (!setBanned.erase(subNet))
            return false;
        setBannedIsDirty = true;
    }
	if(clientInterface)
		clientInterface->BannedListChanged();
    DumpBanlist(); //store banlist to disk immediately
    return true;
}

void CEDCConnman::GetBanned(banmap_t &banMap)
{
    LOCK(cs_setBanned);
    banMap = setBanned; //create a thread safe copy
}

void CEDCConnman::SetBanned(const banmap_t &banMap)
{
    LOCK(cs_setBanned);
    setBanned = banMap;
    setBannedIsDirty = true;
}

void CEDCConnman::SweepBanned()
{
    int64_t now = GetTime();

    LOCK(cs_setBanned);
    banmap_t::iterator it = setBanned.begin();
    while(it != setBanned.end())
    {
        CSubNet subNet = (*it).first;
        CBanEntry banEntry = (*it).second;
        if(now > banEntry.nBanUntil)
        {
            setBanned.erase(it++);
            setBannedIsDirty = true;
            edcLogPrint("net", "%s: Removed banned node ip/subnet from banlist.dat: %s\n", __func__, subNet.ToString());
        }
        else
            ++it;
    }
}

bool CEDCConnman::BannedSetIsDirty()
{
    LOCK(cs_setBanned);
    return setBannedIsDirty;
}

void CEDCConnman::SetBannedSetDirty(bool dirty)
{
    LOCK(cs_setBanned); //reuse setBanned lock for the isDirty flag
    setBannedIsDirty = dirty;
}

bool CEDCConnman::IsWhitelistedRange(const CNetAddr &addr) 
{
    LOCK(cs_vWhitelistedRange);
    BOOST_FOREACH(const CSubNet& subnet, vWhitelistedRange) 
	{
        if (subnet.Match(addr))
            return true;
    }
    return false;
}

void CEDCConnman::AddWhitelistedRange(const CSubNet &subnet) 
{
    LOCK(cs_vWhitelistedRange);
    vWhitelistedRange.push_back(subnet);
}

#undef X
#define X(name) stats.name = name
void CEDCNode::copyStats(CNodeStats &stats)
{
    stats.nodeid = this->GetId();
    X(nServices);
    X(fRelayTxes);
    X(nLastSend);
    X(nLastRecv);
    X(nTimeConnected);
    X(nTimeOffset);
    X(addrName);
    X(nVersion);
    X(cleanSubVer);
    X(fInbound);
    X(nStartingHeight);
    X(nSendBytes);
    X(mapSendBytesPerMsgCmd);
    X(nRecvBytes);
    X(mapRecvBytesPerMsgCmd);
    X(fWhitelisted);

    // It is common for nodes with good ping times to suddenly become lagged,
    // due to a new block arriving or other large transfer.
    // Merely reporting pingtime might fool the caller into thinking the node was still responsive,
    // since pingtime does not update until the ping is complete, which might take a while.
    // So, if a ping is taking an unusually long time in flight,
    // the caller can immediately detect that this is happening.
    int64_t nPingUsecWait = 0;
    if ((0 != nPingNonceSent) && (0 != nPingUsecStart)) 
	{
        nPingUsecWait = GetTimeMicros() - nPingUsecStart;
    }

    // Raw ping time is in microseconds, but show it to user as whole seconds (Equibit users should be well used to small numbers with many decimal places by now :)
    stats.dPingTime = (((double)nPingUsecTime) / 1e6);
    stats.dPingMin  = (((double)nMinPingUsecTime) / 1e6);
    stats.dPingWait = (((double)nPingUsecWait) / 1e6);

    // Leave string empty if addrLocal invalid (not filled in yet)
    stats.addrLocal = addrLocal.IsValid() ? addrLocal.ToString() : "";
}
#undef X

// requires LOCK(cs_vRecvMsg)
bool CEDCNode::ReceiveMsgBytes(const char *pch, unsigned int nBytes, bool & complete)
{
	complete = false;
    while (nBytes > 0) 
	{
        // get current incomplete message, or create a new one
        if (vRecvMsg.empty() ||
            vRecvMsg.back().complete())
            vRecvMsg.push_back(CNetMessage(edcParams().MessageStart(), SER_NETWORK, nRecvVersion));

        CNetMessage& msg = vRecvMsg.back();

        // absorb network data
        int handled;
        if (!msg.in_data)
            handled = msg.readHeader(pch, nBytes);
        else
            handled = msg.readData(pch, nBytes);

        if (handled < 0)
			return false;

        if (msg.in_data && msg.hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) 
		{
            edcLogPrint("net", "Oversized message from peer=%i, disconnecting\n", GetId());
            return false;
        }

        pch += handled;
        nBytes -= handled;

        if (msg.complete()) 
		{

            //store received bytes per message command
            //to prevent a memory DOS, only allow valid commands
            mapMsgCmdSize::iterator i = mapRecvBytesPerMsgCmd.find(msg.hdr.pchCommand);
            if (i == mapRecvBytesPerMsgCmd.end())
                i = mapRecvBytesPerMsgCmd.find(NET_MESSAGE_COMMAND_OTHER);
            assert(i != mapRecvBytesPerMsgCmd.end());
            i->second += msg.hdr.nMessageSize + CMessageHeader::HEADER_SIZE;

            msg.nTime = GetTimeMicros();
			complete = true;
        }
    }

    return true;
}

// requires LOCK(cs_vSend)
size_t SocketSendData(CEDCNode *pnode)
{
    std::deque<CSerializeData>::iterator it = pnode->vSendMsg.begin();
	size_t nSendSize = 0;

    while (it != pnode->vSendMsg.end()) 
	{
        const CSerializeData &data = *it;
        assert(data.size() > pnode->nSendOffset);
        int nBytes = pnode->send( &data[pnode->nSendOffset], data.size() - pnode->nSendOffset, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (nBytes > 0) 
		{
            pnode->nLastSend = GetTime();
            pnode->nSendBytes += nBytes;
            pnode->nSendOffset += nBytes;
			nSendSize += nBytes;

            if (pnode->nSendOffset == data.size()) 
			{
                pnode->nSendOffset = 0;
                pnode->nSendSize -= data.size();
                it++;
            } 
			else 
			{
                // could not send full message; stop sending more
                break;
            }
        } 
		else 
		{
            if (nBytes < 0) 
			{
                // error
                int nErr = WSAGetLastError();
                if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                {
                    edcLogPrintf("socket send error %s\n", NetworkErrorString(nErr));
                    pnode->CloseSocketDisconnect();
                }
            }
            // couldn't send anything at all
            break;
        }
    }

    if (it == pnode->vSendMsg.end()) 
	{
        assert(pnode->nSendOffset == 0);
        assert(pnode->nSendSize == 0);
    }
    pnode->vSendMsg.erase(pnode->vSendMsg.begin(), it);
	return nSendSize;
}

struct NodeEvictionCandidate
{
    NodeId id;
    int64_t nTimeConnected;
    int64_t nMinPingUsecTime;
    int64_t nLastBlockTime;
    int64_t nLastTXTime;
    bool fNetworkNode;
    bool fRelayTxes;
    bool fBloomFilter;
    CAddress addr;
	uint64_t nKeyedNetGroup;
};

static bool ReverseCompareNodeMinPingTime(
	const NodeEvictionCandidate &a, 
	const NodeEvictionCandidate &b)
{
    return a.nMinPingUsecTime > b.nMinPingUsecTime;
}

static bool ReverseCompareNodeTimeConnected(
	const NodeEvictionCandidate &a, 
	const NodeEvictionCandidate &b)
{
    return a.nTimeConnected > b.nTimeConnected;
}

static bool CompareNetGroupKeyed(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b) 
{
    return a.nKeyedNetGroup < b.nKeyedNetGroup;
}

static bool CompareNodeBlockTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    // There is a fall-through here because it is common for a node to have many peers which have not yet relayed a block.
    if (a.nLastBlockTime != b.nLastBlockTime) return a.nLastBlockTime < b.nLastBlockTime;
    if (a.fNetworkNode != b.fNetworkNode) return b.fNetworkNode;
    return a.nTimeConnected > b.nTimeConnected;
}

static bool CompareNodeTXTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    // There is a fall-through here because it is common for a node to have more than a few peers that have not yet relayed txn.
    if (a.nLastTXTime != b.nLastTXTime) return a.nLastTXTime < b.nLastTXTime;
    if (a.fRelayTxes != b.fRelayTxes) return b.fRelayTxes;
    if (a.fBloomFilter != b.fBloomFilter) return a.fBloomFilter;
    return a.nTimeConnected > b.nTimeConnected;
}

/** Try to find a connection to evict when the node is full.
  *  Extreme care must be taken to avoid opening the node to attacker
  *   triggered network partitioning.
  *  The strategy used here is to protect a small number of peers
  *   for each of several distinct characteristics which are difficult
  *   to forge.  In order to partition a node the attacker must be
  *   simultaneously better at all of them than honest peers.
  */
bool CEDCConnman::AttemptToEvictConnection() 
{
    std::vector<NodeEvictionCandidate> vEvictionCandidates;
    {
        LOCK(cs_vNodes);

        BOOST_FOREACH(CEDCNode *node, vNodes) 
		{
            if (node->fWhitelisted)
                continue;
            if (!node->fInbound)
                continue;
            if (node->fDisconnect)
                continue;
			NodeEvictionCandidate candidate = {
				node->id, node->nTimeConnected, node->nMinPingUsecTime,
                node->nLastBlockTime, node->nLastTXTime, node->fNetworkNode,
                node->fRelayTxes, node->pfilter != NULL, node->addr, node->nKeyedNetGroup};
            vEvictionCandidates.push_back(candidate);
        }
    }

    if (vEvictionCandidates.empty()) return false;

    // Protect 4 nodes that most recently sent us transactions.
    // An attacker cannot manipulate this metric without performing useful work.
    std::sort(vEvictionCandidates.begin(), vEvictionCandidates.end(), CompareNodeTXTime);
    vEvictionCandidates.erase(vEvictionCandidates.end() - std::min(4, static_cast<int>(vEvictionCandidates.size())), vEvictionCandidates.end());

    if (vEvictionCandidates.empty()) return false;

    // Protect 4 nodes that most recently sent us blocks.
    // An attacker cannot manipulate this metric without performing useful work.
    std::sort(vEvictionCandidates.begin(), vEvictionCandidates.end(), CompareNodeBlockTime);
    vEvictionCandidates.erase(vEvictionCandidates.end() - std::min(4, static_cast<int>(vEvictionCandidates.size())), vEvictionCandidates.end());

    if (vEvictionCandidates.empty()) return false;

    // Protect connections with certain characteristics

    // Deterministically select 4 peers to protect by netgroup.
    // An attacker cannot predict which netgroups will be protected
    std::sort(vEvictionCandidates.begin(), vEvictionCandidates.end(), CompareNetGroupKeyed);
    vEvictionCandidates.erase(vEvictionCandidates.end() - std::min(4, static_cast<int>(vEvictionCandidates.size())), vEvictionCandidates.end());

    if (vEvictionCandidates.empty()) return false;

    // Protect the 8 nodes with the lowest minimum ping time.
    // An attacker cannot manipulate this metric without physically moving nodes closer to the target.
    std::sort(vEvictionCandidates.begin(), vEvictionCandidates.end(), ReverseCompareNodeMinPingTime);
    vEvictionCandidates.erase(vEvictionCandidates.end() - std::min(8, static_cast<int>(vEvictionCandidates.size())), vEvictionCandidates.end());

    if (vEvictionCandidates.empty()) return false;

    // Protect the half of the remaining nodes which have been connected the longest.
    // This replicates the non-eviction implicit behavior, and precludes attacks that start later.
    std::sort(vEvictionCandidates.begin(), vEvictionCandidates.end(), ReverseCompareNodeTimeConnected);
    vEvictionCandidates.erase(vEvictionCandidates.end() - static_cast<int>(vEvictionCandidates.size() / 2), vEvictionCandidates.end());

    if (vEvictionCandidates.empty()) return false;

    // Identify the network group with the most connections and youngest member.
    // (vEvictionCandidates is already sorted by reverse connect time)
	uint64_t naMostConnections;
    unsigned int nMostConnections = 0;
    int64_t nMostConnectionsTime = 0;
	std::map<uint64_t, std::vector<NodeEvictionCandidate> > mapNetGroupNodes;
    BOOST_FOREACH(const NodeEvictionCandidate &node, vEvictionCandidates) 
	{
        mapNetGroupNodes[node.nKeyedNetGroup].push_back(node);
        int64_t grouptime = mapNetGroupNodes[node.nKeyedNetGroup][0].nTimeConnected;
        size_t groupsize = mapNetGroupNodes[node.nKeyedNetGroup].size();

        if (groupsize > nMostConnections || (groupsize == nMostConnections && grouptime > nMostConnectionsTime)) 
		{
            nMostConnections = groupsize;
            nMostConnectionsTime = grouptime;
            naMostConnections = node.nKeyedNetGroup;
        }
    }

    // Reduce to the network group with the most connections
	vEvictionCandidates = std::move(mapNetGroupNodes[naMostConnections]);

	// Disconnect from the network group with the most connections
    NodeId evicted = vEvictionCandidates.front().id;
    LOCK(cs_vNodes);
    for(std::vector<CEDCNode*>::const_iterator it(vNodes.begin()); 
	it != vNodes.end(); ++it) 
	{
        if ((*it)->GetId() == evicted) 
		{
            (*it)->fDisconnect = true;
            return true;
        }
    }
    return false;
}

void CEDCConnman::AcceptConnection(const ListenSocket& hListenSocket) 
{
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    SOCKET hSocket = accept(hListenSocket.socket, (struct sockaddr*)&sockaddr, &len);
    CAddress addr;
    int nInbound = 0;
	int nMaxInbound = nMaxConnections - (nMaxOutbound + nMaxFeeler);
    assert(nMaxInbound > 0);

    if (hSocket != INVALID_SOCKET)
        if (!addr.SetSockAddr((const struct sockaddr*)&sockaddr))
            edcLogPrintf("Warning: Unknown socket family\n");

    bool whitelisted = hListenSocket.whitelisted || IsWhitelistedRange(addr);
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CEDCNode* pnode, vNodes)
            if (pnode->fInbound)
                nInbound++;
    }

    if (hSocket == INVALID_SOCKET)
    {
        int nErr = WSAGetLastError();
        if (nErr != WSAEWOULDBLOCK)
            edcLogPrintf("socket error accept failed: %s\n", NetworkErrorString(nErr));
        return;
    }

    if (!IsSelectableSocket(hSocket))
    {
        edcLogPrintf("connection from %s dropped: non-selectable socket\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    // According to the internet TCP_NODELAY is not carried into accepted sockets
    // on all platforms.  Set it again here just to be sure.
    int set = 1;
#ifdef WIN32
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
#else
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&set, sizeof(int));
#endif

    if (IsBanned(addr) && !whitelisted)
    {
        edcLogPrintf("connection from %s dropped (banned)\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    if (nInbound >= nMaxInbound)
    {
        if (!AttemptToEvictConnection()) 
		{
            // No connection to evict, disconnect the new connection
            edcLogPrint("net","failed to find an eviction candidate - connection dropped (full)\n");
            CloseSocket(hSocket);
            return;
        }
    }

	// If socket is on secure port, then 
	bool isSecure;

	len = sizeof(sockaddr);
	if(0 == getsockname( hSocket, (struct sockaddr*)&sockaddr, &len))
	{
		if( sockaddr.ss_family == AF_INET )
		{
			struct sockaddr_in * p = (struct sockaddr_in *)&sockaddr;
			isSecure = (ntohs(p->sin_port) == edcGetListenSecurePort());
		}
		else if( sockaddr.ss_family == AF_INET6 )
		{
			struct sockaddr_in6 * p = (struct sockaddr_in6 *)&sockaddr;
			isSecure = (ntohs(p->sin6_port) == edcGetListenSecurePort());
		}
		else
		{
        	edcLogPrint("net", "ERROR: unsupported family type loaded\n");
			return;
		}
	}
	else
	{
        edcLogPrint("net", "ERROR: failed to get socket information: %s\n",
			strerror(errno) );
		return;
	}

    CEDCNode * pnode;
	if( isSecure )
	{
		if( SSL * ssl = CEDCSSLNode::sslAccept(hSocket) )
		{
			pnode = new CEDCSSLNode( GetNewNodeId(), nLocalServices, GetBestHeight(), hSocket, 
				addr, CalculateKeyedNetGroup(addr), "", true, ssl );
		}
		else
		{
			edcLogPrint( "net", "ERROR:SSL accept failed. No connection established to %s\n", 
				addr.ToString());
			return;
		}
	}
	else
	{
		pnode = new CEDCNode( GetNewNodeId(), nLocalServices, GetBestHeight(), hSocket, addr, 
								CalculateKeyedNetGroup(addr), "", true );
	}

	edcGetNodeSignals().InitializeNode(pnode->GetId(), pnode);
    pnode->AddRef();
    pnode->fWhitelisted = whitelisted;

    edcLogPrint("net", "connection from %s accepted\n", addr.ToString());

    {
        LOCK(cs_vNodes);
		if(isSecure)
            vSSLNodes.push_back(static_cast<CEDCSSLNode *>(pnode));
		else
	        vNodes.push_back(pnode);
    }
}

void CEDCConnman::ThreadSocketHandler()
{
    unsigned int nPrevNodeCount = 0;
    while (true)
    {
        //
        // Disconnect nodes
        //
        {
            LOCK(cs_vNodes);
            // Disconnect unused nodes
            std::vector<CEDCNode*> vNodesCopy = vNodes;
			vNodesCopy.insert( vNodesCopy.end(), vSSLNodes.begin(), vSSLNodes.end());
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
            {
                if (pnode->fDisconnect ||
                    (pnode->GetRefCount() <= 0 && pnode->vRecvMsg.empty() && pnode->nSendSize == 0 && pnode->ssSend.empty()))
                {
                    // remove from vNodes
                    vNodes.erase(
						remove(	vNodes.begin(), 
								vNodes.end(), 
								pnode), 
						vNodes.end());

                    // remove from vSSLNodes
                    vSSLNodes.erase(
						remove(	vSSLNodes.begin(), 
								vSSLNodes.end(), 
								pnode), 
						vSSLNodes.end());

                    // release outbound grant (if any)
                    pnode->grantOutbound.Release();

                    // close socket and cleanup
                    pnode->CloseSocketDisconnect();

                    // hold in disconnected pool until all refs are released
                    if (pnode->fNetworkNode || pnode->fInbound)
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            }
        }
        {
            // Delete disconnected nodes
            std::list<CEDCNode*> vNodesDisconnectedCopy = vNodesDisconnected;
            BOOST_FOREACH(CEDCNode* pnode, vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    {
                        TRY_LOCK(pnode->cs_vSend, lockSend);
                        if (lockSend)
                        {
                            TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                            if (lockRecv)
                            {
                                TRY_LOCK(pnode->cs_inventory, lockInv);
                                if (lockInv)
                                    fDelete = true;
                            }
                        }
                    }
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        DeleteNode(pnode);
                    }
                }
            }
        }
        if(vNodes.size() != nPrevNodeCount) 
		{
            nPrevNodeCount = vNodes.size();
			if(clientInterface)
				clientInterface->NotifyNumConnectionsChanged(nPrevNodeCount);
        }

        //
        // Find which sockets have data to receive
        //
        struct timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 50000; // frequency to poll pnode->vSend

        fd_set fdsetRecv;
        fd_set fdsetSend;
        fd_set fdsetError;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);
        SOCKET hSocketMax = 0;
        bool have_fds = false;

        BOOST_FOREACH(const ListenSocket& hListenSocket, vhListenSocket) 
		{
            FD_SET(hListenSocket.socket, &fdsetRecv);
            hSocketMax = std::max(hSocketMax, hListenSocket.socket);
            have_fds = true;
        }

        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CEDCNode* pnode, vNodes)
            {
                if (pnode->invalidSocket())
                    continue;
                FD_SET(pnode->socket(), &fdsetError);
                hSocketMax = std::max(hSocketMax, pnode->socket());
                have_fds = true;

                // Implement the following logic:
                // * If there is data to send, select() for sending data. As this only
                //   happens when optimistic write failed, we choose to first drain the
                //   write buffer in this case before receiving more. This avoids
                //   needlessly queueing received data, if the remote peer is not themselves
                //   receiving data. This means properly utilizing TCP flow control signalling.
                // * Otherwise, if there is no (complete) message in the receive buffer,
                //   or there is space left in the buffer, select() for receiving data.
                // * (if neither of the above applies, there is certainly one message
                //   in the receiver buffer ready to be processed).
                // Together, that means that at least one of the following is always possible,
                // so we don't deadlock:
                // * We send some data.
                // * We wait for data to be received (and disconnect after timeout).
                // * We process a message in the buffer (message handler thread).
                {
                    TRY_LOCK(pnode->cs_vSend, lockSend);
                    if (lockSend) 
					{
                        if (pnode->nOptimisticBytesWritten) 
						{
                            RecordBytesSent(pnode->nOptimisticBytesWritten);
                            pnode->nOptimisticBytesWritten = 0;
                        }
                        if (!pnode->vSendMsg.empty()) 
						{
                            FD_SET(pnode->hSocket, &fdsetSend);
                            continue;
                        }
                    }
                }
                {
                    TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                    if (lockRecv && (
                        pnode->vRecvMsg.empty() || !pnode->vRecvMsg.front().complete() ||
                        pnode->GetTotalRecvSize() <= GetReceiveFloodSize()))
                        FD_SET(pnode->socket(), &fdsetRecv);
                }
			}
            BOOST_FOREACH(CEDCSSLNode* pnode, vSSLNodes)
            {
                if (pnode->invalidSocket())
                    continue;
                FD_SET(pnode->socket(), &fdsetError);
                hSocketMax = std::max(hSocketMax, pnode->socket());
                have_fds = true;

                // Implement the following logic:
                // * If there is data to send, select() for sending data. As this only
                //   happens when optimistic write failed, we choose to first drain the
                //   write buffer in this case before receiving more. This avoids
                //   needlessly queueing received data, if the remote peer is not themselves
                //   receiving data. This means properly utilizing TCP flow control signalling.
                // * Otherwise, if there is no (complete) message in the receive buffer,
                //   or there is space left in the buffer, select() for receiving data.
                // * (if neither of the above applies, there is certainly one message
                //   in the receiver buffer ready to be processed).
                // Together, that means that at least one of the following is always possible,
                // so we don't deadlock:
                // * We send some data.
                // * We wait for data to be received (and disconnect after timeout).
                // * We process a message in the buffer (message handler thread).
                {
                    TRY_LOCK(pnode->cs_vSend, lockSend);
                    if (lockSend && !pnode->vSendMsg.empty()) 
					{
                        FD_SET(pnode->socket(), &fdsetSend);
                        continue;
                    }
                }
                {
                    TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                    if (lockRecv && (
                        pnode->vRecvMsg.empty() || !pnode->vRecvMsg.front().complete() ||
                        pnode->GetTotalRecvSize() <= GetReceiveFloodSize()))
                        FD_SET(pnode->socket(), &fdsetRecv);
                }
            }
        }

        int nSelect = select(have_fds ? hSocketMax + 1 : 0,
                             &fdsetRecv, &fdsetSend, &fdsetError, &timeout);
        boost::this_thread::interruption_point();

        if (nSelect == SOCKET_ERROR)
        {
            if (have_fds)
            {
                int nErr = WSAGetLastError();
                edcLogPrintf("socket select error %s\n", NetworkErrorString(nErr));
                for (unsigned int i = 0; i <= hSocketMax; i++)
                    FD_SET(i, &fdsetRecv);
            }
            FD_ZERO(&fdsetSend);
            FD_ZERO(&fdsetError);
            MilliSleep(timeout.tv_usec/1000);
        }

        //
        // Accept new connections
        //
        BOOST_FOREACH(const ListenSocket& hListenSocket, vhListenSocket)
        {
            if (hListenSocket.socket != INVALID_SOCKET && FD_ISSET(hListenSocket.socket, &fdsetRecv))
            {
                AcceptConnection(hListenSocket);
            }
        }

        //
        // Service each socket
        //
        std::vector<CEDCNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
			vNodesCopy.insert( vNodesCopy.end(), 
				vSSLNodes.begin(), vSSLNodes.end());
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
                pnode->AddRef();
        }
        BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
        {
            boost::this_thread::interruption_point();

            //
            // Receive
            //
            if (pnode->invalidSocket())
                continue;
            if (FD_ISSET(pnode->socket(), &fdsetRecv) || FD_ISSET(pnode->socket(), &fdsetError))
            {
                TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                if (lockRecv)
                {
                    {
                        // typical socket buffer is 8K-64K
                        char pchBuf[0x10000];
                        int nBytes = pnode->recv( pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
                        if (nBytes > 0)
                        {
                            bool notify = false;
                            if (!pnode->ReceiveMsgBytes(pchBuf, nBytes, notify))
                                 pnode->CloseSocketDisconnect();
                            if(notify)
                                messageHandlerCondition.notify_one();

                            pnode->nLastRecv = GetTime();
                            pnode->nRecvBytes += nBytes;
                            RecordBytesRecv(nBytes);
                        }
                        else if (nBytes == 0)
                        {
                            // socket closed gracefully
                            if (!pnode->fDisconnect)
                                edcLogPrint("net", "socket closed\n");
                            pnode->CloseSocketDisconnect();
                        }
                        else if (nBytes < 0)
                        {
                            // error
                            int nErr = WSAGetLastError();
                            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                            {
                                if (!pnode->fDisconnect)
                                    edcLogPrintf("socket recv error %s\n", NetworkErrorString(nErr));
                                pnode->CloseSocketDisconnect();
                            }
                        }
                    }
                }
            }

            //
            // Send
            //
            if (pnode->invalidSocket())
                continue;
            if (FD_ISSET(pnode->socket(), &fdsetSend))
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend) 
				{
                    size_t nBytes = SocketSendData(pnode);
                    if (nBytes)
                        RecordBytesSent(nBytes);
                }
            }

            //
            // Inactivity checking
            //
            int64_t nTime = GetTime();
            if (!pnode->isSecure() && ( nTime - pnode->nTimeConnected > 60) )
            {
                if (pnode->nLastRecv == 0 || pnode->nLastSend == 0)
                {
                    edcLogPrint("net", "socket no message in first 60 seconds, %d %d from %d\n", pnode->nLastRecv != 0, pnode->nLastSend != 0, pnode->id);
                    pnode->fDisconnect = true;
                }
                else if (nTime - pnode->nLastSend > TIMEOUT_INTERVAL)
                {
                    edcLogPrintf("socket sending timeout: %is\n", nTime - pnode->nLastSend);
                    pnode->fDisconnect = true;
                }
                else if (nTime - pnode->nLastRecv > (pnode->nVersion > BIP0031_VERSION ? TIMEOUT_INTERVAL : 90*60))
                {
                    edcLogPrintf("socket receive timeout: %is\n", nTime - pnode->nLastRecv);
                    pnode->fDisconnect = true;
                }
                else if (pnode->nPingNonceSent && pnode->nPingUsecStart + TIMEOUT_INTERVAL * 1000000 < GetTimeMicros())
                {
                    edcLogPrintf("ping timeout: %fs\n", 0.000001 * (GetTimeMicros() - pnode->nPingUsecStart));
                    pnode->fDisconnect = true;
                }
            }
        }
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
                pnode->Release();
        }
    }
}

#ifdef USE_UPNP
void ThreadMapPort()
{
    std::string port = strprintf("%u", edcGetListenPort());
    const char * multicastif = 0;
    const char * minissdpdpath = 0;
    struct UPNPDev * devlist = 0;
    char lanaddr[64];

#ifndef UPNPDISCOVER_SUCCESS
    /* miniupnpc 1.5 */
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0);
#elif MINIUPNPC_API_VERSION < 14
    /* miniupnpc 1.6 */
    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, &error);
#else
    /* miniupnpc 1.9.20150730 */
    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, 2, &error);
#endif

    struct UPNPUrls urls;
    struct IGDdatas data;
    int r;

    r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    if (r == 1)
    {
		EDCparams & params = EDCparams::singleton();
        if (params.discover) 
		{
            char externalIPAddress[40];
            r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);
            if(r != UPNPCOMMAND_SUCCESS)
                edcLogPrintf("UPnP: GetExternalIPAddress() returned %d\n", r);
            else
            {
                if(externalIPAddress[0])
                {
                    CNetAddr resolved;
                    if(LookupHost(externalIPAddress, resolved, false)) 
					{
                        edcLogPrintf("UPnP: ExternalIPAddress = %s\n", resolved.ToString().c_str());
                        edcAddLocal(resolved, LOCAL_UPNP);
                    }
                }
                else
                    edcLogPrintf("UPnP: GetExternalIPAddress failed.\n");
            }
        }

        std::string strDesc = "Equibit " + FormatFullVersion();

        try 
		{
            while (true) 
			{
#ifndef UPNPDISCOVER_SUCCESS
                /* miniupnpc 1.5 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0);
#else
                /* miniupnpc 1.6 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0, "0");
#endif

                if(r!=UPNPCOMMAND_SUCCESS)
                    edcLogPrintf("AddPortMapping(%s, %s, %s) failed with code %d (%s)\n",
                        port, port, lanaddr, r, strupnperror(r));
                else
                    edcLogPrintf("UPnP Port Mapping successful.\n");

                MilliSleep(20*60*1000); // Refresh every 20 minutes
            }
        }
        catch (const boost::thread_interrupted&)
        {
            r = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port.c_str(), "TCP", 0);
            edcLogPrintf("UPNP_DeletePortMapping() returned: %d\n", r);
            freeUPNPDevlist(devlist); devlist = 0;
            FreeUPNPUrls(&urls);
            throw;
        }
    } 
	else 
	{
        edcLogPrintf("No valid UPnP IGDs found\n");
        freeUPNPDevlist(devlist); devlist = 0;
        if (r != 0)
            FreeUPNPUrls(&urls);
    }
}

void edcMapPort(bool fUseUPnP)
{
    static boost::thread* upnp_thread = NULL;

    if (fUseUPnP)
    {
        if (upnp_thread) 
		{
            upnp_thread->interrupt();
            upnp_thread->join();
            delete upnp_thread;
        }
        upnp_thread = new boost::thread(boost::bind(&edcTraceThread<void (*)()>, "upnp", &ThreadMapPort));
    }
    else if (upnp_thread) 
	{
        upnp_thread->interrupt();
        upnp_thread->join();
        delete upnp_thread;
        upnp_thread = NULL;
    }
}

#else
void edcMapPort(bool)
{
    // Intentionally left blank.
}
#endif

namespace
{

std::string edcGetDNSHost(const CDNSSeedData& data, ServiceFlags * requiredServiceBits)
{
    // use default host for non-filter-capable seeds or if we use the default 
	// service bits (NODE_NETWORK)
    if (!data.supportsServiceBitsFiltering || *requiredServiceBits == NODE_NETWORK) 
	{
        *requiredServiceBits = NODE_NETWORK;
        return data.host;
    }

    return strprintf("x%x.%s", *requiredServiceBits, data.host);
}

}

void CEDCConnman::ThreadDNSAddressSeed()
{
	EDCparams & params = EDCparams::singleton();

    // goal: only query DNS seeds if address need is acute
    if ((addrman.size() > 0) && !params.forcednsseed ) 
	{
        MilliSleep(11 * 1000);

        LOCK(cs_vNodes);
        if (vNodes.size() >= 2) 
		{
            edcLogPrintf("P2P peers available. Skipped DNS seeding.\n");
            return;
        }
    }

    const std::vector<CDNSSeedData> &vSeeds = edcParams().DNSSeeds();
    int found = 0;

    edcLogPrintf("Loading addresses from DNS seeds (could take a while)\n");

    BOOST_FOREACH(const CDNSSeedData &seed, vSeeds) 
	{
        if (edcHaveNameProxy()) 
		{
            AddOneShot(seed.host);
        } 
		else 
		{
            std::vector<CNetAddr> vIPs;
            std::vector<CAddress> vAdd;

            ServiceFlags requiredServiceBits = nRelevantServices;
			if (LookupHost(edcGetDNSHost(seed, &requiredServiceBits).c_str(), vIPs, 0, true))
            {
                BOOST_FOREACH(const CNetAddr& ip, vIPs)
                {
                    int nOneDay = 24*3600;
					CAddress addr = CAddress(CService(ip, edcParams().GetDefaultPort()), requiredServiceBits);
                    addr.nTime = GetTime() - 3*nOneDay - GetRand(4*nOneDay); // use a random age between 3 and 7 days old
                    vAdd.push_back(addr);
                    found++;
                }
            }
            // TODO: The seed name resolve may fail, yielding an IP of [::], 
			// which results in theApp.addrman() assigning the same source to 
			// results from different seeds. This should switch to a hard-coded
			// stable dummy IP for each seed name, so that the
            // resolve is not required at all.
            if (!vIPs.empty()) 
			{
                CService seedSource;
                Lookup(seed.name.c_str(), seedSource, 0, true);
                addrman.Add(vAdd, seedSource);
            }
        }
    }

    edcLogPrintf("%d addresses found from DNS seeds\n", found);
}

void CEDCConnman::DumpAddresses()
{
    int64_t nStart = GetTimeMillis();

    CEDCAddrDB adb;
    adb.Write(addrman);

    edcLogPrint("net", "Flushed %d addresses to peers.dat  %dms\n",
           addrman.size(), GetTimeMillis() - nStart);
}

void CEDCConnman::DumpData()
{
    DumpAddresses();
    DumpBanlist();
}

bool CEDCConnman::CheckIncomingNonce(uint64_t nonce)
{
    LOCK(cs_vNodes);
    BOOST_FOREACH(CEDCNode* pnode, vNodes) 
	{
        if (!pnode->fSuccessfullyConnected && !pnode->fInbound && pnode->GetLocalNonce() == nonce)
            return false;
    }
    return true;
}

CEDCNode * CEDCConnman::ConnectNode(
	CAddress addrConnect, 
	const char *pszDest, 
	bool fCountFailure,
	bool secure )
{
    if (pszDest == NULL) 
	{
        if (edcIsLocal(addrConnect))
            return NULL;

        // Look for an existing connection
        CEDCNode* pnode = FindNode((CService)addrConnect, fCountFailure );
        if (pnode)
        {
            pnode->AddRef();
            return pnode;
        }
    }

    /// debug print
    edcLogPrint("net", "trying %sconnection %s lastseen=%.1fhrs\n",
		secure ? "secure ":"",
        pszDest ? pszDest : addrConnect.ToString(),
        pszDest ? 0.0 : (double)(edcGetAdjustedTime() - addrConnect.nTime)/3600.0);

    // Connect
    SOCKET hSocket;
    bool proxyConnectionFailed = false;
	EDCapp & theApp = EDCapp::singleton();

    if (pszDest ? 
		edcConnectSocketByName(
			addrConnect, 
			hSocket, 
			pszDest, 
			secure ? edcParams().GetDefaultSecurePort() : edcParams().GetDefaultPort(), 
			theApp.connectTimeout(), &proxyConnectionFailed) :
        edcConnectSocket(
			addrConnect, 
			hSocket, 
			theApp.connectTimeout(), &proxyConnectionFailed) 
	)
    {
        if (!IsSelectableSocket(hSocket)) 
		{
            edcLogPrintf("Cannot create connection: non-selectable socket created (fd >= FD_SETSIZE ?)\n");
            CloseSocket(hSocket);
            return NULL;
        }

        if (pszDest && addrConnect.IsValid()) 
		{
            // It is possible that we already have a connection to the IP/port pszDest resolved to.
            // In that case, drop the connection that was just created, and return the existing 
			// CEDCNode instead. Also store the name we used to connect in that CNode, so that 
			// future edcFindNode() calls to that name catch this early.
            CEDCNode * pnode = FindNode((CService)addrConnect, false );

            if (pnode)
            {
                pnode->AddRef();
                {
                    LOCK(cs_vNodes);
                    if (pnode->addrName.empty()) 
					{
                        pnode->addrName = std::string(pszDest);
                    }
                }
                CloseSocket(hSocket);
                return pnode;
            }
        }

        addrman.Attempt(addrConnect, fCountFailure );

		// If this is a secure connection, then do the SSL handshake first
       	CEDCNode * pnode;
		if(secure)
		{
			if( SSL * ssl = CEDCSSLNode::sslConnect(hSocket))
			{
       			pnode = new CEDCSSLNode( GetNewNodeId(), nLocalServices, GetBestHeight(), hSocket, addrConnect, CalculateKeyedNetGroup(addrConnect), pszDest ? pszDest : "", false, ssl );
				edcGetNodeSignals().InitializeNode(pnode->GetId(), pnode);
			}
			else
			{
				edcLogPrintf( "ERROR: SSL connect failed. Secure messaging to node disabled\n" );
				return NULL;
			}
		}
		else
		{
			pnode = new CEDCNode( GetNewNodeId(), nLocalServices, GetBestHeight(), hSocket, addrConnect, CalculateKeyedNetGroup(addrConnect), pszDest ? pszDest : "", false);
			edcGetNodeSignals().InitializeNode(pnode->GetId(), pnode);
		}
        pnode->AddRef();

        {
            LOCK(cs_vNodes);
			if(secure)
	            vSSLNodes.push_back(static_cast<CEDCSSLNode *>(pnode));
			else
	            vNodes.push_back(pnode);
        }

		pnode->nServicesExpected = ServiceFlags( addrConnect.nServices & nRelevantServices);
        pnode->nTimeConnected = GetTime();

        return pnode;
    } 
	else if (!proxyConnectionFailed) 
	{
        // If connecting to the node failed, and failure is not caused by a problem connecting to
        // the proxy, mark this as an attempt.
        addrman.Attempt(addrConnect, fCountFailure );
    }

    edcLogPrint("net", "WARNING:FAILED to connect %s\n", pszDest ? pszDest : addrConnect.ToString());

    return NULL;
}

// if successful, this moves the passed grant to the constructed node
bool CEDCConnman::OpenNetworkConnection(
	 const CAddress & addrConnect, 
                 bool fCountFailure,
	CSemaphoreGrant * grantOutbound, 
	CSemaphoreGrant * sgrantOutbound, 
	     const char * pszDest, 
	             bool fOneShot,
				 bool fFeeler )
{
    //
    // Initiate outbound network connection
    //
    boost::this_thread::interruption_point();
    if (!pszDest) 
	{
        if (edcIsLocal(addrConnect) ||
            FindNode((CNetAddr)addrConnect, false ) || 
			IsBanned(addrConnect) ||
            FindNode(addrConnect.ToStringIPPort(), false ))
            return false;
    } 
	else if (FindNode(std::string(pszDest), false ))
        return false;

    CEDCNode* pnode = ConnectNode(addrConnect, pszDest, fCountFailure, false );
    boost::this_thread::interruption_point();

    if (!pnode)
        return false;
    if (grantOutbound)
        grantOutbound->MoveTo(pnode->grantOutbound);
    pnode->fNetworkNode = true;
    if (fOneShot)
        pnode->fOneShot = true;
    if (fFeeler)
        pnode->fFeeler = true;

	EDCapp & theApp = EDCapp::singleton();
	if( theApp.sslEnabled() )
	{
    	CEDCSSLNode* pSSLnode = static_cast<CEDCSSLNode *>(
			ConnectNode(addrConnect, pszDest, fCountFailure, true ));
	    boost::this_thread::interruption_point();

   		if (pSSLnode)
		{
    		if (sgrantOutbound)
        		sgrantOutbound->MoveTo(pSSLnode->grantOutbound);
    		pSSLnode->fNetworkNode = true;
    		if (fOneShot)
        		pSSLnode->fOneShot = true;
    		if (fFeeler)
        		pSSLnode->fFeeler = true;
		}
	}

    return true;
}

void CEDCConnman::ProcessOneShot()
{
    std::string strDest;
    {
        LOCK(cs_vOneShots);
        if (vOneShots.empty())
            return;
        strDest = vOneShots.front();
        vOneShots.pop_front();
    }
    CAddress addr;
    CSemaphoreGrant grant(*semOutbound, true);
    CSemaphoreGrant sgrant(*semOutbound, true);
    if (grant) 
	{
        if (!OpenNetworkConnection(addr, false, &grant, &sgrant, strDest.c_str(), true))
            AddOneShot(strDest);
    }
}

std::vector<AddedNodeInfo> CEDCConnman::GetAddedNodeInfo()
{
	EDCapp & theApp = EDCapp::singleton();
    std::vector<AddedNodeInfo> ret;

    std::list<std::string> lAddresses(0);
    {
        LOCK(theApp.addedNodesCS());
        ret.reserve(theApp.addedNodes().size());
        BOOST_FOREACH(const std::string& strAddNode, theApp.addedNodes())
            lAddresses.push_back(strAddNode);
    }


    // Build a map of all already connected addresses (by IP:port and by name) to 
	// inbound/outbound and resolved CService
    std::map<CService, bool> mapConnected;
    std::map<std::string, std::pair<bool, CService>> mapConnectedByName;
    {
        LOCK(cs_vNodes);
        for (const CEDCNode* pnode : vNodes) 
		{
            if (pnode->addr.IsValid()) 
			{
                mapConnected[pnode->addr] = pnode->fInbound;
            }
            if (!pnode->addrName.empty()) 
			{
                mapConnectedByName[pnode->addrName] = 
					std::make_pair(pnode->fInbound, static_cast<const CService&>(pnode->addr));
            }
        }
    }

    BOOST_FOREACH(const std::string& strAddNode, lAddresses) 
	{
        CService service(LookupNumeric(strAddNode.c_str(), edcParams().GetDefaultPort()));

        if (service.IsValid()) 
		{
            // strAddNode is an IP:port
            auto it = mapConnected.find(service);

            if (it != mapConnected.end()) 
			{
                ret.push_back(AddedNodeInfo{strAddNode, service, true, it->second});
            } 
			else 
			{
                ret.push_back(AddedNodeInfo{strAddNode, CService(), false, false});
            }
        } 
		else 
		{
            // strAddNode is a name
            auto it = mapConnectedByName.find(strAddNode);

            if (it != mapConnectedByName.end()) 
			{
                ret.push_back(AddedNodeInfo{strAddNode, it->second.second, true, it->second.first});
            } 
			else 
			{
                ret.push_back(AddedNodeInfo{strAddNode, CService(), false, false});
            }
        }
    }

    return ret;
}

void CEDCConnman::ThreadOpenConnections()
{
	EDCparams & params = EDCparams::singleton();
    // Connect to specific addresses
    if ( params.connect.size() > 0)
    {
        for (int64_t nLoop = 0;; nLoop++)
        {
            ProcessOneShot();
            BOOST_FOREACH(const std::string& strAddr, params.connect)
            {
                CAddress addr(CService(), NODE_NONE);
                OpenNetworkConnection(addr, false, NULL, NULL, strAddr.c_str());
                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    MilliSleep(500);
                }
            }
            MilliSleep(500);
        }
    }

    // Initiate network connections
    int64_t nStart = GetTime();

    // Minimum time before next feeler connection (in microseconds).
    int64_t nNextFeeler = edcPoissonNextSend(nStart*1000*1000, FEELER_INTERVAL);
    while (true)
    {
        ProcessOneShot();

        MilliSleep(500);

        boost::this_thread::interruption_point();

        // Add seed nodes if DNS seeds are all down (an infrastructure attack?).
        if (addrman.size() == 0 && (GetTime() - nStart > 60)) 
		{
            static bool done = false;
            if (!done) 
			{
                edcLogPrintf("Adding fixed seed nodes as DNS doesn't seem to be available.\n");
                CNetAddr local;
                LookupHost("127.0.0.1", local, false);
                addrman.Add(convertSeed6(edcParams().FixedSeeds()), local);
                done = true;
            }
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per network group (/16 for IPv4).
        // Do this here so we don't have to critsect theApp.vNodes() inside mapAddresses critsect.
        int nOutbound = 0;
        std::set<std::vector<unsigned char> > setConnected;
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CEDCNode* pnode, vNodes) 
			{
                if (!pnode->fInbound) 
				{
                    setConnected.insert(pnode->addr.GetGroup());
                    nOutbound++;
                }
            }
        }
		assert(nOutbound <= (nMaxOutbound + nMaxFeeler));
 
        // Feeler Connections
        //
        // Design goals:
        //  * Increase the number of connectable addresses in the tried table.
        //
        // Method:
        //  * Choose a random address from new and attempt to connect to it if we can connect 
        //    successfully it is added to tried.
        //  * Start attempting feeler connections only after node finishes making outbound 
        //    connections.
        //  * Only make a feeler connection once every few minutes.
        //
        bool fFeeler = false;
		if (nOutbound >= nMaxOutbound)
		{
            int64_t nTime = GetTimeMicros(); // The current time right now (in microseconds).
            if (nTime > nNextFeeler) 
			{
                nNextFeeler = edcPoissonNextSend(nTime, FEELER_INTERVAL);
                fFeeler = true;
            } 
			else 
			{
                continue;
            }
        }

        int64_t nANow = edcGetAdjustedTime();
        int nTries = 0;
        while (true)
        {
            CAddrInfo addr = addrman.Select(fFeeler);

            // if we selected an invalid address, restart
            if (!addr.IsValid() || setConnected.count(addr.GetGroup()) || edcIsLocal(addr))
                break;

            // If we didn't find an appropriate destination after trying 100 addresses fetched from theApp.addrman(),
            // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new theApp.addrman() addresses.
            nTries++;
            if (nTries > 100)
                break;

            if (edcIsLimited(addr))
                continue;

            // only connect to full nodes
			if ((addr.nServices & REQUIRED_SERVICES) != REQUIRED_SERVICES)
                continue;

            // only consider very recently tried nodes after 30 failed attempts
            if (nANow - addr.nLastTry < 600 && nTries < 30)
                continue;

            // only consider nodes missing relevant services after 40 failed attempts
            if ((addr.nServices & nRelevantServices) != nRelevantServices && nTries < 40)
                continue;

            // do not allow non-default ports, unless after 50 invalid addresses selected already
            if (addr.GetPort() != edcParams().GetDefaultPort() && nTries < 50)
                continue;

            addrConnect = addr;
            break;
        }

        if (addrConnect.IsValid()) 
		{
            if (fFeeler) {
                // Add small amount of random noise before connection to avoid synchronization.
                int randsleep = GetRandInt(FEELER_SLEEP_WINDOW * 1000);
                MilliSleep(randsleep);
                edcLogPrint("net", "Making feeler connection to %s\n", addrConnect.ToString());
            }

        	CSemaphoreGrant grant(*semOutbound);
	        CSemaphoreGrant sgrant(*semOutbound);
            OpenNetworkConnection(addrConnect, (int)setConnected.size() >= std::min(nMaxConnections - 1, 2), &grant, &sgrant, NULL, false, fFeeler);
        }
    }
}

void CEDCConnman::ThreadOpenAddedConnections()
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();
    {
        LOCK(theApp.addedNodesCS());
        theApp.addedNodes() = params.addnode;
    }

    for (unsigned int i = 0; true; i++)
    {
        std::vector<AddedNodeInfo> vInfo = GetAddedNodeInfo();

        for (const AddedNodeInfo& info : vInfo) 
		{
            if (!info.fConnected) 
			{
                CSemaphoreGrant grant(*semOutbound);
                CSemaphoreGrant sgrant(*semOutbound);

                // If strAddedNode is an IP/port, decode it immediately, so
                // OpenNetworkConnection can detect existing connections to that IP/port.
                CService service(LookupNumeric(info.strAddedNode.c_str(), edcParams().GetDefaultPort()));

                OpenNetworkConnection(CAddress(service, NODE_NONE), false, &grant, &sgrant,
					info.strAddedNode.c_str(), false);
                MilliSleep(500);
            }
        }

        MilliSleep(120000); // Retry every 2 minutes
    }
}

void CEDCConnman::ThreadMessageHandler()
{
    boost::mutex condition_mutex;
    boost::unique_lock<boost::mutex> lock(condition_mutex);

    while (true)
    {
        std::vector<CEDCNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy) 
			{
                pnode->AddRef();
            }
        }

        bool fSleep = true;

        BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
        {
            if (pnode->fDisconnect)
                continue;

            // Receive messages
            {
                TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                if (lockRecv)
                {
                    if (!edcGetNodeSignals().ProcessMessages(pnode, *this))
                        pnode->CloseSocketDisconnect();

                    if (pnode->nSendSize < GetSendBufferSize())
                    {
                        if (!pnode->vRecvGetData.empty() || 
						(!pnode->vRecvMsg.empty() && 
							pnode->vRecvMsg[0].complete()))
                        {
                            fSleep = false;
                        }
                    }
                }
            }
            boost::this_thread::interruption_point();

            // Send messages
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend)
                    edcGetNodeSignals().SendMessages(pnode, *this);
            }
            boost::this_thread::interruption_point();
        }

        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
                pnode->Release();
        }

        std::vector<CEDCSSLNode*> vSSLNodesCopy;
        {
            LOCK(cs_vNodes);
            vSSLNodesCopy = vSSLNodes;
            BOOST_FOREACH(CEDCSSLNode* pnode, vSSLNodesCopy) 
			{
                pnode->AddRef();
            }
        }

		// Repeat for SSL connections
		//
        fSleep = true;

        BOOST_FOREACH(CEDCSSLNode* pnode, vSSLNodesCopy)
        {
            if (pnode->fDisconnect)
                continue;

            // Receive messages
            {
                TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                if (lockRecv)
                {
                    if (!edcGetNodeSignals().ProcessMessages(pnode, *this))
                        pnode->CloseSocketDisconnect();

                    if (pnode->nSendSize < GetSendBufferSize())
                    {
                        if (!pnode->vRecvGetData.empty() || 
						(!pnode->vRecvMsg.empty() && 
							pnode->vRecvMsg[0].complete()))
                        {
                            fSleep = false;
                        }
                    }
                }
            }
            boost::this_thread::interruption_point();

            // Send messages
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend)
                    edcGetNodeSignals().SendMessages(pnode, *this);
            }
            boost::this_thread::interruption_point();
        }

        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CEDCSSLNode* pnode, vSSLNodesCopy)
                pnode->Release();
        }

        if (fSleep)
            messageHandlerCondition.timed_wait(lock, 
				boost::posix_time::microsec_clock::universal_time() + 
				boost::posix_time::milliseconds(100));
    }
}

bool CEDCConnman::BindListenPort(
	const CService & addrBind, 
       std::string & strError, 
				bool fWhitelisted)
{
    strError = "";
    int nOne = 1;

    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrBind.GetSockAddr((struct sockaddr*)&sockaddr, &len))
    {
        strError = strprintf("Error: Bind address family for %s not supported", addrBind.ToString());
        edcLogPrintf("%s\n", strError);
        return false;
    }

    SOCKET hListenSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %s)", NetworkErrorString(WSAGetLastError()));
        edcLogPrintf("%s\n", strError);
        return false;
    }
    if (!IsSelectableSocket(hListenSocket))
    {
        strError = "Error: Couldn't create a listenable socket for incoming connections";
        edcLogPrintf("%s\n", strError);
        return false;
    }


#ifndef WIN32
#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hListenSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&nOne, sizeof(int));
#endif
    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (void*)&nOne, sizeof(int));
    // Disable Nagle's algorithm
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&nOne, sizeof(int));
#else
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&nOne, sizeof(int));
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&nOne, sizeof(int));
#endif

    // Set to non-blocking, incoming connections will also inherit this
    if (!SetSocketNonBlocking(hListenSocket, true)) 
	{
        strError = strprintf("edcBindListenPort: Setting listening socket to non-blocking failed, error %s\n", NetworkErrorString(WSAGetLastError()));
        edcLogPrintf("%s\n", strError);
        return false;
    }

    // some systems don't have IPV6_V6ONLY but are always v6only; others do have the option
    // and enable it by default or not. Try to enable it, if possible.
    if (addrBind.IsIPv6()) 
	{
#ifdef IPV6_V6ONLY
#ifdef WIN32
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&nOne, sizeof(int));
#else
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&nOne, sizeof(int));
#endif
#endif
#ifdef WIN32
        int nProtLevel = PROTECTION_LEVEL_UNRESTRICTED;
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, (const char*)&nProtLevel, sizeof(int));
#endif
    }

    if (::bind(hListenSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf(_("Unable to bind to %s on this computer. %s is probably already running."), addrBind.ToString(), _(PACKAGE_NAME));
        else
            strError = strprintf(_("Unable to bind to %s on this computer (bind returned error %s)"), addrBind.ToString(), NetworkErrorString(nErr));
        edcLogPrintf("%s\n", strError);
        CloseSocket(hListenSocket);
        return false;
    }
    edcLogPrintf("Bound to %s\n", addrBind.ToString());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf(_("Error: Listening for incoming connections failed (listen returned error %s)"), NetworkErrorString(WSAGetLastError()));
        edcLogPrintf("%s\n", strError);
        CloseSocket(hListenSocket);
        return false;
    }

    vhListenSocket.push_back(ListenSocket(hListenSocket, fWhitelisted));

	EDCparams & params = EDCparams::singleton();
    if (addrBind.IsRoutable() && params.discover && !fWhitelisted)
        edcAddLocal(addrBind, LOCAL_BIND);

    return true;
}

void edcDiscover(boost::thread_group& threadGroup)
{
	EDCparams & params = EDCparams::singleton();
    if (!params.discover)
        return;

#ifdef WIN32
    // Get local host IP
    char pszHostName[256] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        std::vector<CNetAddr> vaddr;
        if (LookupHost(pszHostName, vaddr, 0, true))
        {
            BOOST_FOREACH (const CNetAddr &addr, vaddr)
            {
                if (edcAddLocal(addr, LOCAL_IF))
                    edcLogPrintf("%s: %s - %s\n", __func__, pszHostName, addr.ToString());
            }
        }
    }
#else
    // Get local host ip
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == NULL) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (strcmp(ifa->ifa_name, "lo0") == 0) continue;
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                CNetAddr addr(s4->sin_addr);
                if (edcAddLocal(addr, LOCAL_IF))
                    edcLogPrintf("%s: IPv4 %s: %s\n", __func__, ifa->ifa_name, addr.ToString());
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                CNetAddr addr(s6->sin6_addr);
                if (edcAddLocal(addr, LOCAL_IF))
                    edcLogPrintf("%s: IPv6 %s: %s\n", __func__, ifa->ifa_name, addr.ToString());
            }
        }
        freeifaddrs(myaddrs);
    }
#endif
}

namespace
{

// learn a new local address
bool edcAddLocal(const CService& addr, int nScore)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!addr.IsRoutable())
        return false;

	EDCparams & params = EDCparams::singleton();
    if (!params.discover && nScore < LOCAL_MANUAL)
        return false;

    if (edcIsLimited(addr))
        return false;

    edcLogPrintf("edcAddLocal(%s,%i)\n", addr.ToString(), nScore);

    {
    	LOCK(theApp.mapLocalHostCS());
        bool fAlready = theApp.mapLocalHost().count(addr) > 0;
        LocalServiceInfo &info = theApp.mapLocalHost()[addr];
        if (!fAlready || nScore >= info.nScore) {
            info.nScore = nScore + (fAlready ? 1 : 0);
            info.nPort = addr.GetPort();
        }
    }

    return true;
}

}

bool edcAddLocal(const CNetAddr &addr, int nScore)
{
    return 	edcAddLocal(CService(addr, edcGetListenPort()), nScore) &&
    		edcAddLocal(CService(addr, edcGetListenSecurePort()), nScore);
}

CEDCConnman::CEDCConnman(uint64_t nSeed0In, uint64_t nSeed1In) : nSeed0(nSeed0In), nSeed1(nSeed1In)
{
	setBannedIsDirty = false;
	fAddressesInitialized = false;
	nLastNodeId = 0;
    nSendBufferMaxSize = 0;
    nReceiveFloodSize = 0;
	semOutbound = NULL;
    nMaxConnections = 0;
    nMaxOutbound = 0;
	nBestHeight = 0;
	clientInterface = NULL;
}

NodeId CEDCConnman::GetNewNodeId()
 {
    return nLastNodeId.fetch_add(1, std::memory_order_relaxed);
}
 
bool CEDCConnman::Start(
	  boost::thread_group & threadGroup, 
			   CScheduler & scheduler, 
			  std::string & strNodeError,
					Options connOptions)
{
	EDCparams & params = EDCparams::singleton();

    nTotalBytesRecv = 0;
    nTotalBytesSent = 0;
    nMaxOutboundTotalBytesSentInCycle = 0;
    nMaxOutboundCycleStartTime = 0;

    nRelevantServices = connOptions.nRelevantServices;
    nLocalServices = connOptions.nLocalServices;
    nMaxConnections = connOptions.nMaxConnections;
    nMaxOutbound = std::min((connOptions.nMaxOutbound), nMaxConnections);
	nMaxFeeler = connOptions.nMaxFeeler;

    nSendBufferMaxSize = connOptions.nSendBufferMaxSize;
    nReceiveFloodSize = connOptions.nSendBufferMaxSize;

    nMaxOutboundLimit = connOptions.nMaxOutboundLimit;
    nMaxOutboundTimeframe = connOptions.nMaxOutboundTimeframe;

    SetBestHeight(connOptions.nBestHeight);

    clientInterface = connOptions.uiInterface;
    if (clientInterface)
        clientInterface->InitMessage(_("Loading addresses..."));

    // Load addresses from peers.dat
    int64_t nStart = GetTimeMillis();
    {
        CEDCAddrDB adb;
        if (adb.Read(addrman))
            edcLogPrintf("Loaded %i addresses from peers.dat  %dms\n", addrman.size(), GetTimeMillis() - nStart);
        else 
		{
			addrman.Clear(); // Addrman can be in an inconsistent state after failure, reset it
            edcLogPrintf("Invalid or missing peers.dat; recreating\n");
            DumpAddresses();
        }
    }

    if (clientInterface)
        clientInterface->InitMessage(_("Loading banlist..."));

    // Load addresses from banlist.dat
    nStart = GetTimeMillis();
    CEDCBanDB bandb;
    banmap_t banmap;
    if (bandb.Read(banmap)) 
	{
        SetBanned(banmap); // thread save setter
        SetBannedSetDirty(false); // no need to write down, just read data
        SweepBanned(); // sweep out unused entries

        edcLogPrint("net", "Loaded %d banned node ips/subnets from banlist.dat  %dms\n",
            banmap.size(), GetTimeMillis() - nStart);
    } 
	else 
	{
        edcLogPrintf("Invalid or missing banlist.dat; recreating\n");
        SetBannedSetDirty(true); // force write
        DumpBanlist();
    }

	edcUiInterface.InitMessage(_("Starting network threads..."));

    fAddressesInitialized = true;

    if (semOutbound == NULL) 
	{
        // initialize semaphore
		semOutbound = new CSemaphore(std::min((nMaxOutbound + nMaxFeeler), nMaxConnections));
    }

    if (pnodeLocalHost == NULL) 
	{
        CNetAddr local;
        LookupHost("127.0.0.1", local, false);
        pnodeLocalHost = new CEDCNode( GetNewNodeId(), nLocalServices, GetBestHeight(), INVALID_SOCKET, CAddress(CService(local, 0), nLocalServices), 0);
		edcGetNodeSignals().InitializeNode(pnodeLocalHost->GetId(), pnodeLocalHost);
    }

    //
    // Start threads
    //

    if (!params.dnsseed)
        edcLogPrintf("DNS seeding disabled\n");
    else
		threadGroup.create_thread(boost::bind(&edcTraceThread<boost::function<void()> >, 
			"dnsseed", boost::function<void()>(boost::bind(&CEDCConnman::ThreadDNSAddressSeed, 
			this))));

    // Send and receive from sockets, accept connections
	threadGroup.create_thread(boost::bind(&edcTraceThread<boost::function<void()> >, 
		"net", boost::function<void()>(boost::bind(&CEDCConnman::ThreadSocketHandler, this))));

    // Initiate outbound connections from -eb_addnode
	threadGroup.create_thread(boost::bind(&edcTraceThread<boost::function<void()> >, 
		"addcon", boost::function<void()>(boost::bind(&CEDCConnman::ThreadOpenAddedConnections, 
		this))));

    // Initiate outbound connections
	threadGroup.create_thread(boost::bind(&edcTraceThread<boost::function<void()> >, 
		"opencon", boost::function<void()>(boost::bind(&CEDCConnman::ThreadOpenConnections,this))));

    // Process messages
	threadGroup.create_thread(boost::bind(&edcTraceThread<boost::function<void()> >, "msghand", 
		boost::function<void()>(boost::bind(&CEDCConnman::ThreadMessageHandler, this))));

    // Dump network addresses
    scheduler.scheduleEvery(boost::bind(&CEDCConnman::DumpData, this), DUMP_ADDRESSES_INTERVAL);

	return true;
}

class CNetCleanup
{
public:
    CNetCleanup() {}

    ~CNetCleanup()
    {
#ifdef WIN32
        // Shutdown Windows Sockets
        WSACleanup();
#endif
    }
}
edcinstance_of_cnetcleanup;

void CEDCConnman::Stop()
{
	edcLogPrintf( "%s\n",__func__);
    if (semOutbound)
		for (int i=0; i<(nMaxOutbound + nMaxFeeler); i++)
            semOutbound->post();

    if (fAddressesInitialized)
    {
        DumpData();
        fAddressesInitialized = false;
    }

	// Close sockets
	BOOST_FOREACH(CEDCNode* pnode, vNodes)
		if (!pnode->invalidSocket())
			pnode->closeSocket();
	BOOST_FOREACH(CEDCSSLNode* pnode, vSSLNodes)
		if (!pnode->invalidSocket())
			pnode->closeSocket();
	BOOST_FOREACH(ListenSocket& hListenSocket, vhListenSocket)
		if (hListenSocket.socket != INVALID_SOCKET)
			if (!CloseSocket(hListenSocket.socket))
				edcLogPrintf("CloseSocket(hListenSocket) failed with error %s\n", NetworkErrorString(WSAGetLastError()));

	// clean up some globals (to help leak detection)
	BOOST_FOREACH(CEDCNode *pnode, vNodes)
		DeleteNode( pnode );
	BOOST_FOREACH(CEDCSSLNode *pnode, vSSLNodes)
		DeleteNode( pnode );
	BOOST_FOREACH(CEDCNode *pnode, vNodesDisconnected)
		DeleteNode( pnode );

	vNodes.clear();
	vSSLNodes.clear();
	vNodesDisconnected.clear();
	vhListenSocket.clear();
	delete semOutbound;
	semOutbound = NULL;
	if( pnodeLocalHost )
		DeleteNode( pnodeLocalHost );
    pnodeLocalHost = NULL;
}

void CEDCConnman::DeleteNode(CEDCNode* pnode)
{
    assert(pnode);
    bool fUpdateConnectionTime = false;
    edcGetNodeSignals().FinalizeNode(pnode->GetId(), fUpdateConnectionTime);
    if(fUpdateConnectionTime)
        addrman.Connected(pnode->addr);
    delete pnode;
}

CEDCConnman::~CEDCConnman()
{
	Stop();
}

size_t CEDCConnman::GetAddressCount() const
{
    return addrman.size();
}

void CEDCConnman::SetServices(const CService &addr, ServiceFlags nServices)
{
    addrman.SetServices(addr, nServices);
}

void CEDCConnman::MarkAddressGood(const CAddress& addr)
{
    addrman.Good(addr);
}

void CEDCConnman::AddNewAddress(const CAddress& addr, const CAddress& addrFrom, int64_t nTimePenalty)
{
    addrman.Add(addr, addrFrom, nTimePenalty);
}

void CEDCConnman::AddNewAddresses(const std::vector<CAddress>& vAddr, const CAddress& addrFrom, int64_t nTimePenalty)
{
    addrman.Add(vAddr, addrFrom, nTimePenalty);
}

std::vector<CAddress> CEDCConnman::GetAddresses()
{
    return addrman.GetAddr();
}

bool CEDCConnman::AddNode(const std::string& strNode)
{
	EDCapp & theApp = EDCapp::singleton();

    LOCK(theApp.addedNodesCS());

    for(std::vector<std::string>::const_iterator it = theApp.addedNodes().begin(); 
	it != theApp.addedNodes().end(); ++it) 
	{
        if (strNode == *it)
            return false;
    }

    theApp.addedNodes().push_back(strNode);
    return true;
}

bool CEDCConnman::RemoveAddedNode(const std::string& strNode)
{
	EDCapp & theApp = EDCapp::singleton();

    LOCK(theApp.addedNodesCS());

    for(std::vector<std::string>::iterator it = theApp.addedNodes().begin(); 
	it != theApp.addedNodes().end(); ++it)
	{
        if (strNode == *it) 
		{
            theApp.addedNodes().erase(it);
            return true;
        }
    }
    return false;
}

size_t CEDCConnman::GetNodeCount(NumConnections flags)
{
    LOCK(cs_vNodes);

    if (flags == CEDCConnman::CONNECTIONS_ALL) // Shortcut if we want total
        return vNodes.size();

    int nNum = 0;
    for(std::vector<CEDCNode*>::const_iterator it = vNodes.begin(); 
	it != vNodes.end(); ++it)
        if (flags & ((*it)->fInbound ? CONNECTIONS_IN : CONNECTIONS_OUT))
            nNum++;

    return nNum;
}

void CEDCConnman::GetNodeStats(std::vector<CNodeStats>& vstats)
{
    vstats.clear();

    LOCK(cs_vNodes);
    vstats.reserve(vNodes.size());

    for(std::vector<CEDCNode*>::iterator it = vNodes.begin(); 
	it != vNodes.end(); ++it) 
	{
        CEDCNode* pnode = *it;
        CNodeStats stats;
        pnode->copyStats(stats);
        vstats.push_back(stats);
    }
}

bool CEDCConnman::DisconnectAddress(const CNetAddr& netAddr)
{
    if (CEDCNode* pnode = FindNode(netAddr, false )) 
	{
        pnode->fDisconnect = true;
        return true;
    }
    return false;
}

bool CEDCConnman::DisconnectSubnet(const CSubNet& subNet)
{
    if (CEDCNode* pnode = FindNode(subNet, false )) 
	{
        pnode->fDisconnect = true;
        return true;
    }
    return false;
}

bool CEDCConnman::DisconnectNode(const std::string& strNode)
{
    if (CEDCNode* pnode = FindNode(strNode, false )) 
	{
        pnode->fDisconnect = true;
        return true;
    }
    return false;
}

bool CEDCConnman::DisconnectNode(NodeId id)
{
    LOCK(cs_vNodes);

    for(CEDCNode* pnode : vNodes) 
	{
        if (id == pnode->id) 
		{
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

void CEDCConnman::RelayTransaction(const CEDCTransaction& tx)
{
    CInv inv(MSG_TX, tx.GetHash());
    LOCK(cs_vNodes);
    BOOST_FOREACH(CEDCNode* pnode, vNodes)
    {
        pnode->PushInventory(inv);
    }
}

void CEDCConnman::RelayUserMessage( CUserMessage * um, bool secure )
{
	EDCapp & theApp = EDCapp::singleton();

	theApp.walletMain()->AddMessage( um );

	LOCK(cs_vNodes);
	if(secure)
	{
		BOOST_FOREACH(CEDCSSLNode * pnode, vSSLNodes)
		{
			pnode->PushUserMessage(um);
		}
	}
	else
	{
		BOOST_FOREACH(CEDCNode * pnode, vNodes)
		{
			pnode->PushUserMessage(um);
		}
	}
}

void CEDCConnman::RecordBytesRecv(uint64_t bytes)
{
    LOCK(cs_totalBytesRecv);
    nTotalBytesRecv += bytes;
}

void CEDCConnman::RecordBytesSent(uint64_t bytes)
{
    LOCK(cs_totalBytesSent);
    nTotalBytesSent += bytes;

    uint64_t now = GetTime();
    if (nMaxOutboundCycleStartTime + nMaxOutboundTimeframe < now)
    {
        // timeframe expired, reset cycle
        nMaxOutboundCycleStartTime = now;
        nMaxOutboundTotalBytesSentInCycle = 0;
    }

    // TODO, exclude whitebind peers
    nMaxOutboundTotalBytesSentInCycle += bytes;
}

void CEDCConnman::SetMaxOutboundTarget(uint64_t limit)
{
    LOCK(cs_totalBytesSent);
    nMaxOutboundLimit = limit;
}

uint64_t CEDCConnman::GetMaxOutboundTarget()
{
    LOCK(cs_totalBytesSent);
    return nMaxOutboundLimit;
}

uint64_t CEDCConnman::GetMaxOutboundTimeframe()
{
    LOCK(cs_totalBytesSent);
    return nMaxOutboundTimeframe;
}

uint64_t CEDCConnman::GetMaxOutboundTimeLeftInCycle()
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
        return 0;

    if (nMaxOutboundCycleStartTime == 0)
        return nMaxOutboundTimeframe;

    uint64_t cycleEndTime = nMaxOutboundCycleStartTime + nMaxOutboundTimeframe;
    uint64_t now = GetTime();
    return (cycleEndTime < now) ? 0 : cycleEndTime - GetTime();
}

void CEDCConnman::SetMaxOutboundTimeframe(uint64_t timeframe)
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundTimeframe != timeframe)
    {
        // reset measure-cycle in case of changing
        // the timeframe
        nMaxOutboundCycleStartTime = GetTime();
    }
    nMaxOutboundTimeframe = timeframe;
}

bool CEDCConnman::OutboundTargetReached(bool historicalBlockServingLimit)
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
        return false;

    if (historicalBlockServingLimit)
    {
        // keep a large enough buffer to at least relay each block once
        uint64_t timeLeftInCycle = GetMaxOutboundTimeLeftInCycle();
        uint64_t buffer = timeLeftInCycle / 600 * EDC_MAX_BLOCK_SERIALIZED_SIZE;
        if (buffer >= nMaxOutboundLimit || nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit - buffer)
            return true;
    }
    else if (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit)
        return true;

    return false;
}

uint64_t CEDCConnman::GetOutboundTargetBytesLeft()
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
        return 0;

    return (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit) ? 0 : nMaxOutboundLimit - nMaxOutboundTotalBytesSentInCycle;
}

uint64_t CEDCConnman::GetTotalBytesRecv()
{
    LOCK(cs_totalBytesRecv);
    return nTotalBytesRecv;
}

uint64_t CEDCConnman::GetTotalBytesSent()
{
    LOCK(cs_totalBytesSent);
    return nTotalBytesSent;
}

ServiceFlags CEDCConnman::GetLocalServices() const
{
    return nLocalServices;
}

void CEDCConnman::SetBestHeight(int height)
{
    nBestHeight.store(height, std::memory_order_release);
}

int CEDCConnman::GetBestHeight() const
{
    return nBestHeight.load(std::memory_order_acquire);
}

void CEDCNode::Fuzz(int nChance)
{
    if (!fSuccessfullyConnected) return; // Don't fuzz initial handshake
    if (GetRand(nChance) != 0) return; // Fuzz 1 of every nChance messages

    switch (GetRand(3))
    {
    case 0:
        // xor a random byte with a random value:
        if (!ssSend.empty()) 
		{
            CDataStream::size_type pos = GetRand(ssSend.size());
            ssSend[pos] ^= (unsigned char)(GetRand(256));
        }
        break;
    case 1:
        // delete a random byte:
        if (!ssSend.empty()) 	
		{
            CDataStream::size_type pos = GetRand(ssSend.size());
            ssSend.erase(ssSend.begin()+pos);
        }
        break;
    case 2:
        // insert a random byte at a random position
        {
            CDataStream::size_type pos = GetRand(ssSend.size());
            char ch = (char)GetRand(256);
            ssSend.insert(ssSend.begin()+pos, ch);
        }
        break;
    }
    // Chance of more than one change half the time:
    // (more changes exponentially less likely):
    Fuzz(2);
}

unsigned int CEDCConnman::GetReceiveFloodSize() const
{ 
	return nReceiveFloodSize; 
}
unsigned int CEDCConnman::GetSendBufferSize() const
{ 
	return nSendBufferMaxSize; 
}

CEDCNode::CEDCNode(
				 NodeId idIn,
		   ServiceFlags nLocalServicesIn,
					int nMyStartingHeightIn, 
			     SOCKET hSocketIn, 
	   const CAddress & addrIn, 
			   uint64_t nKeyedNetGroupIn, 
	const std::string & addrNameIn, 
				   bool fInboundIn,
				   bool secure ) :
    ssSend(SER_NETWORK, INIT_PROTO_VERSION),
    addr(addrIn),
	nKeyedNetGroup(nKeyedNetGroupIn),
    addrKnown(5000, 0.001),
    filterInventoryKnown(50000, 0.000001),
	isSecure_(secure)
{
    nServices = NODE_NONE;
	nServicesExpected = NODE_NONE;
    hSocket = hSocketIn;
    nRecvVersion = INIT_PROTO_VERSION;
    nLastSend = 0;
    nLastRecv = 0;
    nSendBytes = 0;
    nRecvBytes = 0;
    nTimeConnected = GetTime();
    nTimeOffset = 0;
    addrName = addrNameIn == "" ? addr.ToStringIPPort() : addrNameIn;
    nVersion = 0;
    strSubVer = "";
    fWhitelisted = false;
    fOneShot = false;
    fClient = false; // set by version message
	fFeeler = false;
    fInbound = fInboundIn;
    fNetworkNode = false;
    fSuccessfullyConnected = false;
    fDisconnect = false;
    nRefCount = 0;
    nSendSize = 0;
    nSendOffset = 0;
    hashContinue = uint256();
    nStartingHeight = -1;
    filterInventoryKnown.reset();
    fSendMempool = false;
    fGetAddr = false;
    nNextLocalAddrSend = 0;
    nNextAddrSend = 0;
    nNextInvSend = 0;
    fRelayTxes = false;
    fSentAddr = false;
    pfilter = new CEDCBloomFilter();
	timeLastMempoolReq = 0;
    nLastBlockTime = 0;
    nLastTXTime = 0;
    nPingNonceSent = 0;
    nPingUsecStart = 0;
    nPingUsecTime = 0;
    fPingQueued = false;
    nMinPingUsecTime = std::numeric_limits<int64_t>::max();
    minFeeFilter = 0;
    lastSentFeeFilter = 0;
    nextSendTimeFeeFilter = 0;
	id = idIn;
	nOptimisticBytesWritten = 0;
	nLocalServices = nLocalServicesIn;

	GetRandBytes((unsigned char*)&nLocalHostNonce, sizeof(nLocalHostNonce));
	nMyStartingHeight = nMyStartingHeightIn;

    BOOST_FOREACH(const std::string &msg, edcgetAllNetMessageTypes())
        mapRecvBytesPerMsgCmd[msg] = 0;
    mapRecvBytesPerMsgCmd[NET_MESSAGE_COMMAND_OTHER] = 0;

	EDCparams & params = EDCparams::singleton();
    if (params.logips)
        edcLogPrint("net", "Added connection to %s peer=%d\n", addrName, id);
    else
        edcLogPrint("net", "Added connection peer=%d\n", id);

    // Be shy and don't send version until we hear
    if (!invalidSocket() && !fInbound && !secure )
        PushVersion();
}

CEDCNode::~CEDCNode()
{
    closeSocket();

    if (pfilter)
        delete pfilter;
}

void CEDCNode::AskFor(const CInv& inv)
{
	EDCapp & theApp = EDCapp::singleton();

    if (mapAskFor.size() > MAPASKFOR_MAX_SZ || setAskFor.size() > SETASKFOR_MAX_SZ)
        return;
    // a peer may not have multiple non-responded queue positions for a single inv item
    if (!setAskFor.insert(inv.hash).second)
        return;

    // We're using mapAskFor as a priority queue,
    // the key is the earliest time the request can be sent
    int64_t nRequestTime;
    limitedmap<uint256, int64_t>::const_iterator it = 
		theApp.mapAlreadyAskedFor().find(inv.hash);

    if (it != theApp.mapAlreadyAskedFor().end())
        nRequestTime = it->second;
    else
        nRequestTime = 0;
    edcLogPrint("net", "askfor %s  %d (%s) peer=%d\n", inv.ToString(), nRequestTime, DateTimeStrFormat("%H:%M:%S", nRequestTime/1000000), id);

    // Make sure not to reuse time indexes to keep things in the same order
    int64_t nNow = GetTimeMicros() - 1000000;
    static int64_t nLastTime;
    ++nLastTime;
    nNow = std::max(nNow, nLastTime);
    nLastTime = nNow;

    // Each retry is 2 minutes after the last
    nRequestTime = std::max(nRequestTime + 2 * 60 * 1000000, nNow);
    if (it != theApp.mapAlreadyAskedFor().end())
        theApp.mapAlreadyAskedFor().update(it, nRequestTime);
    else
        theApp.mapAlreadyAskedFor().insert(std::make_pair(inv.hash, nRequestTime));
    mapAskFor.insert(std::make_pair(nRequestTime, inv));
}

void CEDCNode::BeginMessage(const char* pszCommand) EXCLUSIVE_LOCK_FUNCTION(cs_vSend)
{
    ENTER_CRITICAL_SECTION(cs_vSend);
    assert(ssSend.size() == 0);
    ssSend << CMessageHeader(edcParams().MessageStart(), pszCommand, 0);
    edcLogPrint("net", "sending: %s ", SanitizeString(pszCommand));
}

void CEDCNode::AbortMessage() UNLOCK_FUNCTION(cs_vSend)
{
    ssSend.clear();

    LEAVE_CRITICAL_SECTION(cs_vSend);

    edcLogPrint("net", "(aborted)\n");
}

void CEDCNode::EndMessage(const char* pszCommand) UNLOCK_FUNCTION(cs_vSend)
{
    // The -*messagestest options are intentionally not documented in the help message,
    // since they are only used during development to debug the networking code and are
    // not intended for end-users.
	EDCparams & params = EDCparams::singleton();
    if ( params.dropmessagestest && GetRand(params.dropmessagestest) == 0)
    {
        edcLogPrint("net", "dropmessages DROPPING SEND MESSAGE\n");
        AbortMessage();
        return;
    }
    if (params.fuzzmessagestest > 0 )
        Fuzz(params.fuzzmessagestest);

    if (ssSend.size() == 0)
    {
        LEAVE_CRITICAL_SECTION(cs_vSend);
        return;
    }
    // Set the size
    unsigned int nSize = ssSend.size() - CMessageHeader::HEADER_SIZE;
    WriteLE32((uint8_t*)&ssSend[CMessageHeader::MESSAGE_SIZE_OFFSET], nSize);

    //log total amount of bytes per command
    mapSendBytesPerMsgCmd[std::string(pszCommand)] += nSize + CMessageHeader::HEADER_SIZE;

    // Set the checksum
    uint256 hash = Hash(ssSend.begin() + CMessageHeader::HEADER_SIZE, ssSend.end());
    unsigned int nChecksum = 0;
    memcpy(&nChecksum, &hash, sizeof(nChecksum));
    assert(ssSend.size () >= CMessageHeader::CHECKSUM_OFFSET + sizeof(nChecksum));
    memcpy((char*)&ssSend[CMessageHeader::CHECKSUM_OFFSET], &nChecksum, sizeof(nChecksum));

    edcLogPrint("net", "(%d bytes) peer=%d\n", nSize, id);

    std::deque<CSerializeData>::iterator it = vSendMsg.insert(vSendMsg.end(), CSerializeData());
    ssSend.GetAndClear(*it);
    nSendSize += (*it).size();

    // If write queue empty, attempt "optimistic write"
    if (it == vSendMsg.begin())
        nOptimisticBytesWritten += SocketSendData(this);

    LEAVE_CRITICAL_SECTION(cs_vSend);
}

bool CEDCConnman::ForNode(NodeId id, std::function<bool(CEDCNode* pnode)> func)
{
    CEDCNode* found = nullptr;
    LOCK(cs_vNodes);
    for (auto&& pnode : vNodes) 
	{
        if(pnode->id == id) 
		{
            found = pnode;
            break;
        }
    }
    return found != nullptr && func(found);
}

int64_t edcPoissonNextSend(int64_t nNow, int average_interval_seconds) 
{
    return nNow + (int64_t)(log1p(GetRand(1ULL << 48) * 
		-0.0000000000000035527136788 /* -1/2^48 */) * 
		average_interval_seconds * -1000000.0 + 0.5);
}

void CEDCNode::closeSocket()
{
	CloseSocket(hSocket);
}

ssize_t CEDCNode::send( const void *buf, size_t len, int flags )
{
	return ::send( hSocket, buf, len, flags );
}

ssize_t CEDCNode::recv( void *buf, size_t len, int flags )
{
	return ::recv( hSocket, buf, len, flags );
}

CEDCSSLNode::CEDCSSLNode(
		  		 NodeId id,
		   ServiceFlags nLocalServicesIn, 
					int nMyStartingHeightIn, 
		  		 SOCKET hSocketIn, 
	   const CAddress & addrIn, 
			   uint64_t nKeyedNetGroupIn, 
	const std::string & addrNameIn, 
				   bool fInboundIn,
				  SSL * ssl ):
		CEDCNode(id, nLocalServicesIn, nMyStartingHeightIn, hSocketIn, 
				 addrIn, nKeyedNetGroupIn, addrNameIn, fInboundIn, true ),
		ssl_(ssl)
{
}

namespace
{

const char * sslError( int ec )
{
	switch(ec)
	{
	default:	
		return "Unknown SSL error";

	case SSL_ERROR_NONE:			
		return "The TLS/SSL I/O operation completed successfully";
	case SSL_ERROR_ZERO_RETURN:
    	return "The TLS/SSL connection has been closed.";
	case SSL_ERROR_WANT_READ:
    	return "The read operation did not complete";
	case SSL_ERROR_WANT_WRITE:
    	return "The write operation did not complete";
	case SSL_ERROR_WANT_CONNECT:
    	return "The connect operation did not complete";
	case SSL_ERROR_WANT_ACCEPT:
    	return "The accept operation did not complete";
	case SSL_ERROR_WANT_X509_LOOKUP:
		return "The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again.";
	case SSL_ERROR_WANT_ASYNC:
    	return "The operation did not complete because an asynchronous engine is still processing data";
	case SSL_ERROR_WANT_ASYNC_JOB:
    	return "The asynchronous job could not be started because there were no async jobs available in the pool.";
	case SSL_ERROR_SYSCALL:
		return "Some I/O error occurred";
	case SSL_ERROR_SSL:
    	return "A failure in the SSL library occurred, usually a protocol error";
	}
}
}

SSL * CEDCSSLNode::sslConnect(SOCKET hSocket )
{
	EDCapp & theApp = EDCapp::singleton();
	SSL_CTX * ctx = theApp.sslCtx();

   	SSL * ssl = SSL_new (ctx);
   
	if( !ssl )
	{
		char buf[120];
		int err = ERR_get_error();
		edcLogPrintf ("ERROR:SSL session create failed: %s\n", ERR_error_string( err, buf ) ); 
    	return NULL;
	}
   
    // Assign the socket into the SSL structure (SSL and socket without BIO)
    SSL_set_fd(ssl, hSocket );
   
    // Perform SSL Handshake on the SSL client. Do 100 trys before giving up
	int trys = 0;
	while(true)
	{
    	int rc = SSL_connect(ssl);
   
		if( rc > 0 )
			break;

		++trys;

		int err = SSL_get_error( ssl, rc );
		edcLogPrintf ("WARNING:SSL connect failed: %s\n", sslError(err)); 
	
		if( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE )
		{
			// Sleep 100 milli-seconds (1/10 of a second)
			usleep(100 * 1000);
		}
		else if( trys >= 100 )
		{
			return NULL;
		}
	} 

    edcLogPrintf ("SSL connection using %s\n", SSL_get_cipher (ssl));
   
    /* Get the node's certificate (optional) */
    X509 * server_cert = SSL_get_peer_certificate (ssl);
   
    if (server_cert != NULL)
    {
        char * str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
		if(str)
		{
        	edcLogPrintf( "Peer node certificate subject: %s\n", str);
	        free (str);
		}

        str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
		if(str)
		{
        	edcLogPrintf( "Peer node certificate issuer: %s\n", str);
	        free(str);
		}

        X509_free (server_cert);
    }
    else
	{
        edcLogPrintf("ERROR:The SSL node does not have certificate.\n");
		return NULL;
	}

	return ssl;
}

SSL * CEDCSSLNode::sslAccept( SOCKET hSocket )
{
	EDCapp & theApp = EDCapp::singleton();
	SSL_CTX * ctx = theApp.sslCtx();

	SSL * ssl = SSL_new(ctx);
	if( !ssl )
	{
		char buf[120];
		int err = ERR_get_error();
		edcLogPrintf ("ERROR:SSL session create failed: %s\n", ERR_error_string( err, buf ) ); 
		return NULL;
	}

	SSL_set_fd( ssl, hSocket );

    // Perform SSL Handshake on the SSL server. Do 100 trys before giving up
	int trys = 0;
	while(true)
	{
    	int rc = SSL_accept(ssl);
   
		if( rc > 0 )
			break;

		++trys;

		int err = SSL_get_error( ssl, rc );
		edcLogPrintf ("WARNING:SSL accept failed: %s\n", sslError(err)); 
	
		if( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE )
		{
			// Sleep 100 milli-seconds (1/10 of a second)
			usleep(100 * 1000);
		}
		else if( trys >= 100 )
		{
			return NULL;
		}
	} 

	X509 * clientCert = SSL_get_peer_certificate(ssl);
	if( clientCert )
	{
		char * str = X509_NAME_oneline(X509_get_subject_name(clientCert), 0, 0);

		if(str)
		{
			edcLogPrintf("Peer node certificate subject: %s\n", str);
			free (str);
		}

		str = X509_NAME_oneline(X509_get_issuer_name(clientCert), 0, 0);
		if(str)
		{
			edcLogPrintf ("Peer node certificate issuer: %s\n", str);
			free (str);
		}

		X509_free(clientCert);
	}
	else
	{
		char buf[120];
		int err = ERR_get_error();
		edcLogPrintf ("ERROR:Failed to get peer certificate: %s\n", ERR_error_string( err, buf ) ); 
		return NULL;
	}

	return ssl;
}

void CEDCSSLNode::closeSocket()
{
	int err = SSL_shutdown(ssl_);
	if(err == -1 )
	{
		char buf[120];
    	edcLogPrintf("ERROR:SSL socket close error:%s", ERR_error_string( ERR_get_error(), buf ));
	}
	CloseSocket(hSocket);
	SSL_free(ssl_);
}

ssize_t CEDCSSLNode::send( const void *buf, size_t len, int )
{
	// No-op
	if( len == 0 )
		return 0;

	ssize_t rc = SSL_write( ssl_, buf, len );
	if( rc > 0 )
		return rc;
	else 
	{
		int err = SSL_get_error( ssl_, rc );
		edcLogPrintf( "ERROR:SSL write error:%s\n", sslError(err) );

		if( err == SSL_ERROR_SSL )
		{
			while(int err = ERR_get_error())
			{
				char buf[120];
				edcLogPrintf( "ERROR:SSL_read failed:%s\n", ERR_error_string( err, buf ) );
			}
		}

		return -1;
	}
}

ssize_t CEDCSSLNode::recv( void *buf, size_t len, int )
{
	ssize_t rc=SSL_read( ssl_, buf, len );

	if( rc > 0 )
		return rc;
	else
	{
		int err = SSL_get_error( ssl_, rc );
		edcLogPrintf( "ERROR:SSL read error:%s\n", sslError(err) );

		if( err == SSL_ERROR_SSL )
		{
			while(int err = ERR_get_error())
			{
				char buf[120];
				edcLogPrintf( "ERROR:SSL_read failed:%s\n", ERR_error_string( err, buf ) );
			}
		}

		return -1;
	}
}

CSipHasher CEDCConnman::GetDeterministicRandomizer(uint64_t id)
{
    return CSipHasher(nSeed0, nSeed1).Write(id);
}
 
uint64_t CEDCConnman::CalculateKeyedNetGroup(const CAddress& ad)
{
     std::vector<unsigned char> vchNetGroup(ad.GetGroup());
 
    return GetDeterministicRandomizer(RANDOMIZER_ID_NETGROUP).Write(&vchNetGroup[0], vchNetGroup.size()).Finalize();
 }
