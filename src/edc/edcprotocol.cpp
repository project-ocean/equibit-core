// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcprotocol.h"

#include "edcutil.h"
#include "utilstrencodings.h"

#ifndef WIN32
# include <arpa/inet.h>
#endif

namespace NetMsgType 
{
const char *USER="user";
};

namespace
{

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const std::string edcallNetMessageTypes[] = 
{
    NetMsgType::VERSION,	// Provides information about the transmitting node
							// to the receiving node at the beginning of a 
							// connection.
    NetMsgType::VERACK,		// Acknowledges a previously-received VERSION message, 
							// informing the connecting node that it can begin to 
							// send other messages.
    NetMsgType::ADDR,		// Relays connection information for peers on the 
							// network.
    NetMsgType::GETADDR,	// Requests an ADDR message from the receiving node, 
							// preferably one with lots of IP addresses of other 
							// receiving nodes.
    NetMsgType::INV,		// Transmits one or more inventories of objects 
							// known to the transmitting peer.
    NetMsgType::GETDATA,	// Requests one or more data objects from another 
							// node.
    NetMsgType::MERKLEBLOCK,// A reply to a GETDATA message which requested a 
							// block using the inventory type.
    NetMsgType::GETBLOCKS,	// Requests an INV message that provides block 
							// header hashes starting from a particular point in 
							// the block chain.
    NetMsgType::GETHEADERS,	// Requests a HEADERS message that provides block 
							// headers starting from a particular point in the 
							// block chain.
    NetMsgType::TX,			// Transmits a single transaction.
    NetMsgType::HEADERS,	// Sends one or more block headers to a node which 
							// previously requested certain headers with a 
							// GETHEADERS message.
    NetMsgType::BLOCK,		// Transmits a single serialized block.
    NetMsgType::MEMPOOL,	// Requests the TXIDs of transactions that the 
							// receiving node has verified as valid but which 
							// have not yet appeared in a block.
    NetMsgType::PING,		// Sent periodically to help confirm that the 
							// receiving peer is still connected.
    NetMsgType::PONG,		// Replies to a PING message, proving to the pinging 
							// node that the ponging node is still alive.
    NetMsgType::NOTFOUND,	// A reply to a GETDATA message which requested an 
							// object the receiving node does not have available 
							// for relay.
    NetMsgType::FILTERLOAD,	// Tells the receiving peer to filter all relayed 
							// transactions and requested merkle blocks through 
							// the provided filter.
    NetMsgType::FILTERADD,	// Tells the receiving peer to add a single element 
							// to a previously-set bloom filter, such as a new 
							// public key.
    NetMsgType::FILTERCLEAR,// Tells the receiving peer to remove a previously
							// set bloom filter.
    NetMsgType::REJECT,		// Informs the receiving node that one of its 
							// previous messages has been rejected.
    NetMsgType::SENDHEADERS,// Indicates that a node prefers to receive new block 
							// announcements via a HEADERS message rather than an 
							// "inv".
    NetMsgType::FEEFILTER,	// Tells the receiving peer not to inv us any txs 
							// which do not meet the specified min fee rate.
    NetMsgType::SENDCMPCT,  // Requests a Compact block
    NetMsgType::CMPCTBLOCK, // Compact block of data
    NetMsgType::GETBLOCKTXN,// Get txns corresponding to a block
    NetMsgType::BLOCKTXN,   // Txns for a specific block
	NetMsgType::USER		// User-to-user message
};


const std::vector<std::string> edcallNetMessageTypesVec(
	edcallNetMessageTypes, 
	edcallNetMessageTypes+ARRAYLEN(edcallNetMessageTypes));

}

const std::vector<std::string> & edcgetAllNetMessageTypes()
{
    return edcallNetMessageTypesVec;
}
