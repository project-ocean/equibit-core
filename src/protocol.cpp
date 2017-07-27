// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"

#include "util.h"
#include "utilstrencodings.h"

#ifndef WIN32
# include <arpa/inet.h>
#endif

namespace NetMsgType {
const char *VERSION="version";
const char *VERACK="verack";
const char *ADDR="addr";
const char *INV="inv";
const char *GETDATA="getdata";
const char *MERKLEBLOCK="merkleblock";
const char *GETBLOCKS="getblocks";
const char *GETHEADERS="getheaders";
const char *TX="tx";
const char *HEADERS="headers";
const char *BLOCK="block";
const char *GETADDR="getaddr";
const char *MEMPOOL="mempool";
const char *PING="ping";
const char *PONG="pong";
const char *NOTFOUND="notfound";
const char *FILTERLOAD="filterload";
const char *FILTERADD="filteradd";
const char *FILTERCLEAR="filterclear";
const char *REJECT="reject";
const char *SENDHEADERS="sendheaders";
const char *FEEFILTER="feefilter";
const char *SENDCMPCT="sendcmpct";
const char *CMPCTBLOCK="cmpctblock";
const char *GETBLOCKTXN="getblocktxn";
const char *BLOCKTXN="blocktxn";
const char *USER="user";
};

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const static std::string allNetMessageTypes[] = {
    NetMsgType::VERSION,    // Provides information about the transmitting node to the receiving node at the beginning of a connection.
    NetMsgType::VERACK,     // Acknowledges a previously-received VERSION message, informing the connecting node that it can begin to send other messages.
    NetMsgType::ADDR,       // Relays connection information for peers on the network.
    NetMsgType::INV,        // Transmits one or more inventories of objects known to the transmitting peer.
    NetMsgType::GETDATA,    // Requests one or more data objects from another node.
    NetMsgType::MERKLEBLOCK,// A reply to a GETDATA message which requested a block using the inventory type.
    NetMsgType::GETBLOCKS,  // Requests an INV message that provides block header hashes starting from a particular point in the block chain.
    NetMsgType::GETHEADERS, // Requests a HEADERS message that provides block headers starting from a particular point in the block chain.
    NetMsgType::TX,         // Transmits a single transaction.
    NetMsgType::HEADERS,    // Sends one or more block headers to a node which previously requested certain headers with a GETHEADERS message.
    NetMsgType::BLOCK,       // Transmits a single serialized block.
    NetMsgType::GETADDR,    // Requests an ADDR message from the receiving node, preferably one with lots of IP addresses of other receiving nodes.
    NetMsgType::MEMPOOL,    // Requests the TXIDs of transactions that the receiving node has verified as valid but which have not yet appeared in a block.
    NetMsgType::PING,       // Sent periodically to help confirm that the receiving peer is still connected.
    NetMsgType::PONG,       // Replies to a PING message, proving to the pingin node that the ponging node is still alive.
    NetMsgType::NOTFOUND,   // A reply to a GETDATA message which requested a object the receiving node does not have available for relay.
    NetMsgType::FILTERLOAD, // Tells the receiving peer to filter all relayed transactions and requested merkle blocks through the provided filter.
    NetMsgType::FILTERADD,  // Tells the receiving peer to add a single element to a previously-set bloom filter, such as a new public key.
    NetMsgType::FILTERCLEAR,// Tells the receiving peer to remove a previously set bloom filter.
    NetMsgType::REJECT,     // Informs the receiving node that one of its previous messages has been rejected.
    NetMsgType::SENDHEADERS,// Indicates that a node prefers to receive new block announcements via a HEADERS message rather than an "inv".
    NetMsgType::FEEFILTER,  // Tells the receiving peer not to inv us any txs which do not meet the specified min fee rate.
    NetMsgType::SENDCMPCT,  // Requests a Compact block
    NetMsgType::CMPCTBLOCK, // Compact block of data
    NetMsgType::GETBLOCKTXN,// Get txns corresponding to a block
    NetMsgType::BLOCKTXN,   // Txns for a specific block
    NetMsgType::USER        // User-to-user message
};
const static std::vector<std::string> allNetMessageTypesVec(allNetMessageTypes, allNetMessageTypes+ARRAYLEN(allNetMessageTypes));

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    nMessageSize = -1;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    strncpy(pchCommand, pszCommand, COMMAND_SIZE);
    nMessageSize = nMessageSizeIn;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

std::string CMessageHeader::GetCommand() const
{
    return std::string(pchCommand, pchCommand + strnlen(pchCommand, COMMAND_SIZE));
}

bool CMessageHeader::IsValid(const MessageStartChars& pchMessageStartIn) const
{
    // Check start string
    if (memcmp(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE) != 0)
        return false;

    // Check the command string for errors
    for (const char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
    {
        if (*p1 == 0)
        {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                if (*p1 != 0)
                    return false;
        }
        else if (*p1 < ' ' || *p1 > 0x7E)
            return false;
    }

    // Message size
    if (nMessageSize > MAX_SIZE)
    {
        LogPrintf("CMessageHeader::IsValid(): (%s, %u bytes) nMessageSize > MAX_SIZE\n", GetCommand(), nMessageSize);
        return false;
    }

    return true;
}



CAddress::CAddress() : CService()
{
    Init();
}

CAddress::CAddress(CService ipIn, ServiceFlags nServicesIn) : CService(ipIn)
{
    Init();
    nServices = nServicesIn;
}

void CAddress::Init()
{
    nServices = NODE_NONE;
    nTime = 100000000;
}

CInv::CInv()
{
    type = 0;
    hash.SetNull();
}

CInv::CInv(int typeIn, const uint256& hashIn)
{
    type = typeIn;
    hash = hashIn;
}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

std::string CInv::GetCommand() const
{
    std::string cmd;
    if (type & MSG_WITNESS_FLAG)
        cmd.append("witness-");
    int masked = type & MSG_TYPE_MASK;
    switch (masked)
    {
    case MSG_TX:             return cmd.append(NetMsgType::TX);
    case MSG_BLOCK:          return cmd.append(NetMsgType::BLOCK);
    case MSG_FILTERED_BLOCK: return cmd.append(NetMsgType::MERKLEBLOCK);
    case MSG_CMPCT_BLOCK:    return cmd.append(NetMsgType::CMPCTBLOCK);
    default:
        throw std::out_of_range(strprintf("CInv::GetCommand(): type=%d unknown type", type));
    }
}

std::string CInv::ToString() const
{
    try {
        return strprintf("%s %s", GetCommand(), hash.ToString());
    } catch(const std::out_of_range &) {
        return strprintf("0x%08x %s", type, hash.ToString());
    }
}

const std::vector<std::string> &getAllNetMessageTypes()
{
    return allNetMessageTypesVec;
}
