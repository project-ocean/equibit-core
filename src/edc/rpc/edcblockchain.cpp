// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chain.h"
#include "edc/edcchainparams.h"
#include "checkpoints.h"
#include "edc/edccoins.h"
#include "consensus/validation.h"
#include "edc/edcmain.h"
#include "edc/policy/edcpolicy.h"
#include "edc/primitives/edctransaction.h"
#include "edc/rpc/edcserver.h"
#include "streams.h"
#include "sync.h"
#include "edc/edctxmempool.h"
#include "edc/edcutil.h"
#include "utilstrencodings.h"
#include "hash.h"
#include "edc/edcapp.h"
#include "edc/edcparams.h"

#include <stdint.h>

#include <univalue.h>

#include <boost/thread/thread.hpp> // boost::thread::interrupt
#include <mutex>
#include <condition_variable>
using namespace std;

struct CUpdatedBlock
{
    uint256 hash;
    int height;
};

namespace
{
std::mutex cs_blockchange;
std::condition_variable cond_blockchange;
CUpdatedBlock latestblock;
}

void TxToJSON(const CEDCTransaction& tx, const uint256 hashBlock, UniValue& entry);
void edcScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex);

double edcGetDifficulty(const CBlockIndex* blockindex)
{
	EDCapp & theApp = EDCapp::singleton();

    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (theApp.chainActive().Tip() == NULL)
            return 1.0;
        else
            blockindex = theApp.chainActive().Tip();
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

UniValue edcblockheaderToJSON(const CBlockIndex* blockindex)
{
	EDCapp & theApp = EDCapp::singleton();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", blockindex->GetBlockHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (theApp.chainActive().Contains(blockindex))
        confirmations = theApp.chainActive().Height() - blockindex->nHeight + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", blockindex->nVersion));
    result.push_back(Pair("versionHex", strprintf("%08x", blockindex->nVersion)));
    result.push_back(Pair("merkleroot", blockindex->hashMerkleRoot.GetHex()));
    result.push_back(Pair("time", (int64_t)blockindex->nTime));
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)blockindex->nNonce));
    result.push_back(Pair("bits", strprintf("%08x", blockindex->nBits)));
    result.push_back(Pair("difficulty", edcGetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex()));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = theApp.chainActive().Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}

UniValue blockToJSON(
	  const CEDCBlock & block, 
	const CBlockIndex * blockindex, 
				   bool txDetails = false)
{
	EDCapp & theApp = EDCapp::singleton();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", blockindex->GetBlockHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (theApp.chainActive().Contains(blockindex))
        confirmations = theApp.chainActive().Height() - blockindex->nHeight + 1;
    result.push_back(Pair("confirmations", confirmations));
	result.push_back(Pair("strippedsize", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS)));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
	result.push_back(Pair("weight", (int)::edcGetBlockWeight(block)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("versionHex", strprintf("%08x", block.nVersion)));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    UniValue txs(UniValue::VARR);
    BOOST_FOREACH(const CEDCTransaction&tx, block.vtx)
    {
        if(txDetails)
        {
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(tx, uint256(), objTx);
            txs.push_back(objTx);
        }
        else
            txs.push_back(tx.GetHash().GetHex());
    }
    result.push_back(Pair("tx", txs));
    result.push_back(Pair("time", block.GetBlockTime()));
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("difficulty", edcGetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex()));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = theApp.chainActive().Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}

UniValue edcgetblockcount(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getblockcount\n"
            "\nReturns the number of blocks in the longest block chain.\n"
            "\nResult:\n"
            "n    (numeric) The current block count\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getblockcount", "")
            + HelpExampleRpc("eb_getblockcount", "")
        );

    LOCK(EDC_cs_main);
    return theApp.chainActive().Height();
}

UniValue edcgetbestblockhash(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getbestblockhash\n"
            "\nReturns the hash of the best (tip) block in the longest block chain.\n"
            "\nResult\n"
            "\"hex\"      (string) the block hash hex encoded\n"
            "\nExamples\n"
            + HelpExampleCli("eb_getbestblockhash", "")
            + HelpExampleRpc("eb_getbestblockhash", "")
        );

    LOCK(EDC_cs_main);
    return theApp.chainActive().Tip()->GetBlockHash().GetHex();
}

void edcRPCNotifyBlockChange(bool ibd, const CBlockIndex * pindex)
{
    if(pindex) 
	{
        std::lock_guard<std::mutex> lock(cs_blockchange);
        latestblock.hash = pindex->GetBlockHash();
        latestblock.height = pindex->nHeight;
    }
    cond_blockchange.notify_all();
}

UniValue edcwaitfornewblock(const UniValue & params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_waitfornewblock\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"
            "\nArguments:\n"
            "1. timeout (milliseconds) (int, optional, default=false)\n"
            "\nResult::\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("eb_waitfornewblock", "1000")
            + HelpExampleRpc("eb_waitfornewblock", "1000")
        );
    int timeout = 0;
    if (params.size() > 0)
        timeout = params[0].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        block = latestblock;
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), 
				[&block]{return latestblock.height != block.height || 
								latestblock.hash != block.hash || !edcIsRPCRunning(); });
        else
            cond_blockchange.wait(lock, [&block]{return latestblock.height != block.height || 
				latestblock.hash != block.hash || !edcIsRPCRunning(); });
        block = latestblock;
    }

    UniValue ret(UniValue::VOBJ);

    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));

    return ret;
}

UniValue edcwaitforblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_waitforblock\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"
            "\nArguments:\n"
            "1. blockhash to wait for (string)\n"
            "2. timeout (milliseconds) (int, optional, default=false)\n"
            "\nResult::\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("eb_waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
            + HelpExampleRpc("eb_waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
        );
    int timeout = 0;

    uint256 hash = uint256S(params[0].get_str());

    if (params.size() > 1)
        timeout = params[1].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), 
				[&hash]{return latestblock.hash == hash || !edcIsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&hash]{return latestblock.hash == hash || 
				!edcIsRPCRunning(); });
        block = latestblock;
    }

    UniValue ret(UniValue::VOBJ);

    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));

    return ret;
}

UniValue edcwaitforblockheight(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_waitforblock\n"
            "\nWaits for (at least) block height and returns the height and hash\n"
            "\nof the current tip.\n"
            "\nReturns the current block on timeout or exit.\n"
            "\nArguments:\n"
            "1. block height to wait for (int)\n"
            "2. timeout (milliseconds) (int, optional, default=false)\n"
            "\nResult::\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("eb_waitforblockheight", "\"100\", 1000")
            + HelpExampleRpc("eb_waitforblockheight", "\"100\", 1000")
        );
    int timeout = 0;

    int height = params[0].get_int();

    if (params.size() > 1)
        timeout = params[1].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), 
				[&height]{return latestblock.height >= height || !edcIsRPCRunning();});
        else
            cond_blockchange.wait(lock, 
				[&height]{return latestblock.height >= height || !edcIsRPCRunning(); });
        block = latestblock;
    }

    UniValue ret(UniValue::VOBJ);

    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));

    return ret;
}

UniValue edcgetdifficulty(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getdifficulty", "")
            + HelpExampleRpc("eb_getdifficulty", "")
        );

    LOCK(EDC_cs_main);
    return edcGetDifficulty(NULL);
}

namespace
{

std::string EntryDescriptionString()
{
    return "    \"size\" : n,             (numeric) transaction size in bytes\n"
           "    \"fee\" : n,              (numeric) transaction fee in " + CURRENCY_UNIT + "\n"
           "    \"modifiedfee\" : n,      (numeric) transaction fee with fee deltas used for mining priority\n"
           "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT\n"
           "    \"height\" : n,           (numeric) block height when transaction entered pool\n"
           "    \"startingpriority\" : n, (numeric) priority when transaction entered pool\n"
           "    \"currentpriority\" : n,  (numeric) transaction priority now\n"
           "    \"descendantcount\" : n,  (numeric) number of in-mempool descendant transactions (including this one)\n"
           "    \"descendantsize\" : n,   (numeric) size of in-mempool descendants (including this one)\n"
           "    \"descendantfees\" : n,   (numeric) modified fees (see above) of in-mempool descendants (including this one)\n"
           "    \"ancestorcount\" : n,    (numeric) number of in-mempool ancestor transactions (including this one)\n"
           "    \"ancestorsize\" : n,     (numeric) size of in-mempool ancestors (including this one)\n"
           "    \"ancestorfees\" : n,     (numeric) modified fees (see above) of in-mempool ancestors (including this one)\n"

           "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
           "        \"transactionid\",    (string) parent transaction id\n"
           "       ... ]\n";
}

void entryToJSON(UniValue &info, const CEDCTxMemPoolEntry &e)
{
	EDCapp & theApp = EDCapp::singleton();

    AssertLockHeld(mempool.cs);

    info.push_back(Pair("size", (int)e.GetTxSize()));
    info.push_back(Pair("fee", ValueFromAmount(e.GetFee())));
    info.push_back(Pair("modifiedfee", ValueFromAmount(e.GetModifiedFee())));
    info.push_back(Pair("time", e.GetTime()));
    info.push_back(Pair("height", (int)e.GetHeight()));
    info.push_back(Pair("startingpriority", e.GetPriority(e.GetHeight())));
    info.push_back(Pair("currentpriority", e.GetPriority(theApp.chainActive().Height())));
    info.push_back(Pair("descendantcount", e.GetCountWithDescendants()));
    info.push_back(Pair("descendantsize", e.GetSizeWithDescendants()));
    info.push_back(Pair("descendantfees", e.GetModFeesWithDescendants()));
    info.push_back(Pair("ancestorcount", e.GetCountWithAncestors()));
    info.push_back(Pair("ancestorsize", e.GetSizeWithAncestors()));
    info.push_back(Pair("ancestorfees", e.GetModFeesWithAncestors()));

    const CEDCTransaction& tx = e.GetTx();
    set<string> setDepends;
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin)
    {
        if (mempool.exists(txin.prevout.hash))
            setDepends.insert(txin.prevout.hash.ToString());
    }

    UniValue depends(UniValue::VARR);
    BOOST_FOREACH(const string& dep, setDepends)
    {
        depends.push_back(dep);
    }

    info.push_back(Pair("depends", depends));
}

}

UniValue edcmempoolToJSON(bool fVerbose = false)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fVerbose)
    {
        LOCK(theApp.mempool().cs);
        UniValue o(UniValue::VOBJ);
        BOOST_FOREACH(const CEDCTxMemPoolEntry& e, theApp.mempool().mapTx)
        {
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            entryToJSON(info, e);
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    }
    else
    {
        vector<uint256> vtxid;
        theApp.mempool().queryHashes(vtxid);

        UniValue a(UniValue::VARR);
        BOOST_FOREACH(const uint256& hash, vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue edcgetrawmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_getrawmempool ( verbose )\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
			+ EntryDescriptionString()
			+ "  }, ...\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("eb_getrawmempool", "true")
            + HelpExampleRpc("eb_getrawmempool", "true")
        );

    bool fVerbose = false;
    if (params.size() > 0)
        fVerbose = params[0].get_bool();

    return edcmempoolToJSON(fVerbose);
}

UniValue edcgetmempoolancestors(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 2) 
	{
        throw runtime_error(
            "eb_getmempoolancestors txid (verbose)\n"
            "\nIf txid is in the mempool, returns all in-mempool ancestors.\n"
            "\nArguments:\n"
            "1. \"txid\"                   (string, required) The transaction id (must be in mempool)\n"
            "2. verbose                  (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "\nResult (for verbose=false):\n"
            "[                       (json array of strings)\n"
            "  \"transactionid\"           (string) The transaction id of an in-mempool ancestor transaction\n"
            "  ,...\n"
            "]\n"
            "\nResult (for verbose=true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            + EntryDescriptionString()
            + "  }, ...\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("eb_getmempoolancestors", "\"mytxid\"")
            + HelpExampleRpc("eb_getmempoolancestors", "\"mytxid\"")
            );
    }

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    uint256 hash = ParseHashV(params[0], "parameter 1");

    LOCK(theApp.mempool().cs);

    CEDCTxMemPool::txiter it = theApp.mempool().mapTx.find(hash);
    if (it == theApp.mempool().mapTx.end()) 
	{
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    CEDCTxMemPool::setEntries setAncestors;
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();

    std::string dummy;
    theApp.mempool().CalculateMemPoolAncestors(*it, setAncestors, noLimit, noLimit, noLimit, 
		noLimit, dummy, false);

    if (!fVerbose) 
	{
        UniValue o(UniValue::VARR);
        BOOST_FOREACH(CEDCTxMemPool::txiter ancestorIt, setAncestors) 
		{
            o.push_back(ancestorIt->GetTx().GetHash().ToString());
        }

        return o;
    } 
	else 
	{
        UniValue o(UniValue::VOBJ);
        BOOST_FOREACH(CEDCTxMemPool::txiter ancestorIt, setAncestors) 
		{
            const CEDCTxMemPoolEntry &e = *ancestorIt;
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);

            entryToJSON(info, e);
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    }
}

UniValue edcgetmempooldescendants(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw runtime_error(
            "eb_getmempooldescendants txid (verbose)\n"
            "\nIf txid is in the mempool, returns all in-mempool descendants.\n"
            "\nArguments:\n"
            "1. \"txid\"                   (string, required) The transaction id (must be in mempool)\n"
            "2. verbose                  (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "\nResult (for verbose=false):\n"
            "[                       (json array of strings)\n"
            "  \"transactionid\"           (string) The transaction id of an in-mempool descendant transaction\n"
            "  ,...\n"
            "]\n"
            "\nResult (for verbose=true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            + EntryDescriptionString()
            + "  }, ...\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("eb_getmempooldescendants", "\"mytxid\"")
            + HelpExampleRpc("eb_getmempooldescendants", "\"mytxid\"")
            );
    }

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    uint256 hash = ParseHashV(params[0], "parameter 1");

    LOCK(theApp.mempool().cs);

    CEDCTxMemPool::txiter it = theApp.mempool().mapTx.find(hash);
    if (it == theApp.mempool().mapTx.end()) 
	{
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    CEDCTxMemPool::setEntries setDescendants;
    theApp.mempool().CalculateDescendants(it, setDescendants);

    // CEDCTxMemPool::CalculateDescendants will include the given tx
    setDescendants.erase(it);

    if (!fVerbose) 
	{
        UniValue o(UniValue::VARR);
        BOOST_FOREACH(CEDCTxMemPool::txiter descendantIt, setDescendants) 
		{
            o.push_back(descendantIt->GetTx().GetHash().ToString());
        }

        return o;
    } 
	else 
	{
        UniValue o(UniValue::VOBJ);
        BOOST_FOREACH(CEDCTxMemPool::txiter descendantIt, setDescendants) 
		{
            const CEDCTxMemPoolEntry & e = *descendantIt;
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);

            entryToJSON(info, e);
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    }
}

UniValue edcgetmempoolentry(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() != 1) {
        throw runtime_error(
            "eb_getmempoolentry txid\n"
            "\nReturns mempool data for given transaction\n"
            "\nArguments:\n"
            "1. \"txid\"                   (string, required) The transaction id (must be in mempool)\n"
            "\nResult:\n"
            "{                           (json object)\n"
            + EntryDescriptionString()
            + "}\n"
            "\nExamples\n"
            + HelpExampleCli("eb_getmempoolentry", "\"mytxid\"")
            + HelpExampleRpc("eb_getmempoolentry", "\"mytxid\"")
        );
    }

    uint256 hash = ParseHashV(params[0], "parameter 1");

    LOCK(theApp.mempool().cs);

    CEDCTxMemPool::txiter it = theApp.mempool().mapTx.find(hash);
    if (it == theApp.mempool().mapTx.end()) 
	{
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    const CEDCTxMemPoolEntry &e = *it;
    UniValue info(UniValue::VOBJ);

    entryToJSON(info, e);

    return info;
}

UniValue edcgetblockhash(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_getblockhash index\n"
            "\nReturns hash of block in best-block-chain at index provided.\n"
            "\nArguments:\n"
            "1. index         (numeric, required) The block index\n"
            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getblockhash", "1000")
            + HelpExampleRpc("eb_getblockhash", "1000")
        );

    LOCK(EDC_cs_main);

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > theApp.chainActive().Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = theApp.chainActive()[nHeight];
    return pblockindex->GetBlockHash().GetHex();
}

UniValue edcgetblockheader(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_getblockheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
            "If verbose is true, returns an Object with information about blockheader <hash>.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"versionHex\" : \"00000000\", (string) The block version formatted in hexadecimal\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\",      (string) The hash of the next block\n"
            "  \"chainwork\" : \"0000...1f3\"     (string) Expected number of hashes required to produce the current chain (in hex)\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("eb_getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
        );

    LOCK(EDC_cs_main);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (theApp.mapBlockIndex().count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pblockindex = theApp.mapBlockIndex()[hash];

    if (!fVerbose)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return edcblockheaderToJSON(pblockindex);
}

UniValue edcgetblock(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_getblock \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbose is true, returns an Object with information about block <hash>.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
			"  \"strippedsize\" : n,    (numeric) The block size excluding witness data\n"
			"  \"weight\" : n           (numeric) The block weight (BIP 141)\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"versionHex\" : \"00000000\", (string) The block version formatted in hexadecimal\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"chainwork\" : \"xxxx\",  (string) Expected number of hashes required to produce the chain up to this block (in hex)\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("eb_getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
        );

    LOCK(EDC_cs_main);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (theApp.mapBlockIndex().count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CEDCBlock block;
    CBlockIndex* pblockindex = theApp.mapBlockIndex()[hash];

    if (theApp.havePruned() && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not available (pruned data)");

    if(!ReadBlockFromDisk(block, pblockindex, edcParams().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (!fVerbose)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockToJSON(block, pblockindex);
}

struct CCoinsStats
{
    int nHeight;
    uint256 hashBlock;
    uint64_t nTransactions;
    uint64_t nTransactionOutputs;
    uint64_t nSerializedSize;
    uint256 hashSerialized;
    CAmount nTotalAmount;

    CCoinsStats() : nHeight(0), nTransactions(0), nTransactionOutputs(0), nSerializedSize(0), nTotalAmount(0) {}
};

namespace
{

//! Calculate statistics about the unspent transaction output set
bool GetUTXOStats(CEDCCoinsView *view, CCoinsStats &stats)
{
	EDCapp & theApp = EDCapp::singleton();
    std::unique_ptr<CEDCCoinsViewCursor> pcursor(view->Cursor());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = pcursor->GetBestBlock();
    {
        LOCK(EDC_cs_main);
        stats.nHeight = theApp.mapBlockIndex().find(stats.hashBlock)->second->nHeight;
    }
    ss << stats.hashBlock;
    CAmount nTotalAmount = 0;
    while (pcursor->Valid()) 
	{
        boost::this_thread::interruption_point();
        uint256 key;
        CEDCCoins coins;
        if (pcursor->GetKey(key) && pcursor->GetValue(coins)) 
		{
            stats.nTransactions++;
            ss << key;
            for (unsigned int i=0; i<coins.vout.size(); i++) 
			{
                const CEDCTxOut &out = coins.vout[i];
                if (!out.IsNull()) 
				{
                    stats.nTransactionOutputs++;
                    ss << VARINT(i+1);
                    ss << out;
                    nTotalAmount += out.nValue;
                }
            }
            stats.nSerializedSize += 32 + pcursor->GetValueSize();
            ss << VARINT(0);
        } 
		else 
		{
            return edcError("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    stats.hashSerialized = ss.GetHash();
    stats.nTotalAmount = nTotalAmount;
    return true;
}

UniValue edcgettxoutsetinfo(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_gettxoutsetinfo\n"
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time.\n"
            "\nResult:\n"
            "{\n"
            "  \"height\":n,     (numeric) The current block height (index)\n"
            "  \"bestblock\": \"hex\",   (string) the best block hash hex\n"
            "  \"transactions\": n,      (numeric) The number of transactions\n"
            "  \"txouts\": n,            (numeric) The number of output transactions\n"
            "  \"bytes_serialized\": n,  (numeric) The serialized size\n"
            "  \"hash_serialized\": \"hash\",   (string) The serialized hash\n"
            "  \"total_amount\": x.xxx          (numeric) The total amount\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_gettxoutsetinfo", "")
            + HelpExampleRpc("eb_gettxoutsetinfo", "")
        );

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    edcFlushStateToDisk();
    if (GetUTXOStats(theApp.coinsTip(), stats)) 
	{
        ret.push_back(Pair("height", (int64_t)stats.nHeight));
        ret.push_back(Pair("bestblock", stats.hashBlock.GetHex()));
        ret.push_back(Pair("transactions", (int64_t)stats.nTransactions));
        ret.push_back(Pair("txouts", (int64_t)stats.nTransactionOutputs));
        ret.push_back(Pair("bytes_serialized", (int64_t)stats.nSerializedSize));
        ret.push_back(Pair("hash_serialized", stats.hashSerialized.GetHex()));
        ret.push_back(Pair("total_amount", ValueFromAmount(stats.nTotalAmount)));
    }
    return ret;
}

UniValue edcgettxout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "eb_gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout number\n"
            "3. includemempool  (boolean, optional) Whether to include the mem pool\n"
            "\nResult:\n"
            "{\n"
            "  \"bestblock\" : \"hash\",    (string) the block hash\n"
            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,           (numeric) The transaction value in " + CURRENCY_UNIT + "\n"
            "  \"scriptPubKey\" : {         (json object)\n"
            "     \"asm\" : \"code\",       (string) \n"
            "     \"hex\" : \"hex\",        (string) \n"
            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of string) array of equibit addresses\n"
            "        \"equibitaddress\"     (string) equibit address\n"
            "        ,...\n"
            "     ]\n"
            "  },\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"coinbase\" : true|false   (boolean) Coinbase or not\n"
            "}\n"

            "\nExamples:\n"
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("eb_gettxout", "\"txid\" 1") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_gettxout", "\"txid\", 1")
        );

    LOCK(EDC_cs_main);

    UniValue ret(UniValue::VOBJ);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    int n = params[1].get_int();
    bool fMempool = true;
    if (params.size() > 2)
        fMempool = params[2].get_bool();

    CEDCCoins coins;
	EDCapp & theApp = EDCapp::singleton();
    if (fMempool) 
	{
        LOCK(theApp.mempool().cs);
        CEDCCoinsViewMemPool view(theApp.coinsTip(), theApp.mempool());
        if (!view.GetCoins(hash, coins))
            return NullUniValue;
        theApp.mempool().pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } 
	else 
	{
        if (!theApp.coinsTip()->GetCoins(hash, coins))
            return NullUniValue;
    }

    if (n<0 || (unsigned int)n>=coins.vout.size() || coins.vout[n].IsNull())
        return NullUniValue;

    BlockMap::iterator it = theApp.mapBlockIndex().find(theApp.coinsTip()->GetBestBlock());
    CBlockIndex *pindex = it->second;
    ret.push_back(Pair("bestblock", pindex->GetBlockHash().GetHex()));
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.push_back(Pair("confirmations", 0));
    else
        ret.push_back(Pair("confirmations", pindex->nHeight - coins.nHeight + 1));
    ret.push_back(Pair("value", ValueFromAmount(coins.vout[n].nValue)));
    UniValue o(UniValue::VOBJ);
    edcScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o, true);
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("version", coins.nVersion));
    ret.push_back(Pair("coinbase", coins.fCoinBase));

    return ret;
}

UniValue edcverifychain(const UniValue& param, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    int nCheckLevel = params.checklevel;
    int nCheckDepth = params.checkblocks;

    if (fHelp || param.size() > 2)
        throw runtime_error(
            "eb_verifychain ( checklevel numblocks )\n"
            "\nVerifies blockchain database.\n"
            "\nArguments:\n"
            "1. checklevel   (numeric, optional, 0-4, default=" + strprintf("%d", nCheckLevel) + ") How thorough the block verification is.\n"
            "2. numblocks    (numeric, optional, default=" + strprintf("%d", nCheckDepth) + ", 0=all) The number of blocks to check.\n"
            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_verifychain", "")
            + HelpExampleRpc("eb_verifychain", "")
        );

    LOCK(EDC_cs_main);

    if (param.size() > 0)
        nCheckLevel = param[0].get_int();
    if (param.size() > 1)
        nCheckDepth = param[1].get_int();

    return CEDCVerifyDB().VerifyDB(edcParams(), theApp.coinsTip(), nCheckLevel, nCheckDepth);
}

/** Implementation of IsSuperMajority with better feedback */
UniValue SoftForkMajorityDesc(
						  int version, 
				CBlockIndex * pindex, 
	const Consensus::Params & consensusParams)
{
    UniValue rv(UniValue::VOBJ);
    bool activated = false;
    switch(version)
    {
    case 2:
        activated = pindex->nHeight >= consensusParams.BIP34Height;
        break;
    case 3:
        activated = pindex->nHeight >= consensusParams.BIP66Height;
        break;
    case 4:
        activated = pindex->nHeight >= consensusParams.BIP65Height;
        break;
    }

	rv.push_back(Pair("status", activated));
    return rv;
}

UniValue SoftForkDesc(
		  const std::string & name, 
						  int version, 
				CBlockIndex * pindex, 
	const Consensus::Params & consensusParams)
{
    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("id", name));
    rv.push_back(Pair("version", version));
	rv.push_back(Pair("reject", SoftForkMajorityDesc(version, pindex, consensusParams)));
    return rv;
}

UniValue BIP9SoftForkDesc(const Consensus::Params& consensusParams, Consensus::DeploymentPos id)
{
    UniValue rv(UniValue::VOBJ);
    const ThresholdState thresholdState = edcVersionBitsTipState(consensusParams, id);

    switch (thresholdState) 
	{
    case THRESHOLD_DEFINED: rv.push_back(Pair("status", "defined")); break;
    case THRESHOLD_STARTED: rv.push_back(Pair("status", "started")); break;
    case THRESHOLD_LOCKED_IN: rv.push_back(Pair("status", "locked_in")); break;
    case THRESHOLD_ACTIVE: rv.push_back(Pair("status", "active")); break;
    case THRESHOLD_FAILED: rv.push_back(Pair("status", "failed")); break;
    }

    if (THRESHOLD_STARTED == thresholdState)
    {
        rv.push_back(Pair("bit", consensusParams.vDeployments[id].bit));
    }
    rv.push_back(Pair("startTime", consensusParams.vDeployments[id].nStartTime));
    rv.push_back(Pair("timeout", consensusParams.vDeployments[id].nTimeout));
    return rv;
}

void BIP9SoftForkDescPushBack(
				   UniValue & bip9_softforks, 
		  const std::string & name, 
	const Consensus::Params & consensusParams, 
	 Consensus::DeploymentPos id)
{
    // Deployments with timeout value of 0 are hidden.
    // A timeout value of 0 guarantees a softfork will never be activated.
    // This is used when softfork codes are merged without specifying the deployment schedule.
    if (consensusParams.vDeployments[id].nTimeout > 0)
        bip9_softforks.push_back(Pair(name, BIP9SoftForkDesc(consensusParams, id)));
}

}

UniValue edcgetblockchaininfo(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getblockchaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"
            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",        (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"mediantime\": xxxxxx,     (numeric) median time for the current best block\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"chainwork\": \"xxxx\"     (string) total amount of work in active chain, in hexadecimal\n"
            "  \"pruned\": xx,             (boolean) if the blocks are subject to pruning\n"
            "  \"pruneheight\": xxxxxx,    (numeric) heighest block available\n"
            "  \"softforks\": [            (array) status of softforks in progress\n"
            "     {\n"
            "        \"id\": \"xxxx\",        (string) name of softfork\n"
            "        \"version\": xx,         (numeric) block version\n"
			"        \"reject\": {            (object) progress toward rejecting pre-softfork blocks\n"
            "           \"status\": xx,       (boolean) true if threshold reached\n"
            "        },\n"
            "     }, ...\n"
            "  ],\n"
            "  \"bip9_softforks\": {          (object) status of BIP9 softforks in progress\n"
            "     \"xxxx\" : {                (string) name of the softfork\n"
			"        \"status\": \"xxxx\",    (string) one of \"defined\", \"started\", \"locked_in\", \"active\", \"failed\"\n"

			"        \"bit\": xx,             (numeric) the bit (0-28) in the block version field used to signal this softfork (only for \"started\" status)\n"
            "        \"startTime\": xx,       (numeric) the minimum median time past of a block at which the bit gains its meaning\n"
            "        \"timeout\": xx          (numeric) the median time past of a block at which the deployment is considered failed if not yet locked in\n"
            "     }\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getblockchaininfo", "")
            + HelpExampleRpc("eb_getblockchaininfo", "")
        );

    LOCK(EDC_cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("chain",                 edcParams().NetworkIDString()));
    obj.push_back(Pair("blocks",                (int)theApp.chainActive().Height()));
    obj.push_back(Pair("headers",               theApp.indexBestHeader() ? theApp.indexBestHeader()->nHeight : -1));
    obj.push_back(Pair("bestblockhash",         theApp.chainActive().Tip()->GetBlockHash().GetHex()));
    obj.push_back(Pair("difficulty",            (double)edcGetDifficulty(NULL)));
    obj.push_back(Pair("mediantime",            (int64_t)theApp.chainActive().Tip()->GetMedianTimePast()));
    obj.push_back(Pair("verificationprogress",  Checkpoints::GuessVerificationProgress(edcParams().Checkpoints(), theApp.chainActive().Tip())));
    obj.push_back(Pair("chainwork",             theApp.chainActive().Tip()->nChainWork.GetHex()));
    obj.push_back(Pair("pruned",                theApp.pruneMode() ));

    const Consensus::Params& consensusParams = edcParams().GetConsensus();
    CBlockIndex* tip = theApp.chainActive().Tip();
    UniValue softforks(UniValue::VARR);
    UniValue bip9_softforks(UniValue::VOBJ);
    softforks.push_back(SoftForkDesc("bip34", 2, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip66", 3, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip65", 4, tip, consensusParams));
    BIP9SoftForkDescPushBack(bip9_softforks, "csv", consensusParams, Consensus::DEPLOYMENT_CSV);
    BIP9SoftForkDescPushBack(bip9_softforks, "segwit", consensusParams, Consensus::DEPLOYMENT_SEGWIT);

    obj.push_back(Pair("softforks",             softforks));
    obj.push_back(Pair("bip9_softforks", bip9_softforks));

    if (theApp.pruneMode() )
    {
        CBlockIndex *block = theApp.chainActive().Tip();
        while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA))
            block = block->pprev;

        obj.push_back(Pair("pruneheight",        block->nHeight));
    }
    return obj;
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

UniValue edcgetchaintips(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getchaintips\n"
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the chain tip\n"
            "    \"hash\": \"xxxx\",         (string) block hash of the tip\n"
            "    \"branchlen\": 0          (numeric) zero for main chain\n"
            "    \"status\": \"active\"      (string) \"active\" for the main chain\n"
            "  },\n"
            "  {\n"
            "    \"height\": xxxx,\n"
            "    \"hash\": \"xxxx\",\n"
            "    \"branchlen\": 1          (numeric) length of branch connecting the tip to the main chain\n"
            "    \"status\": \"xxxx\"        (string) status of the chain (active, valid-fork, valid-headers, headers-only, invalid)\n"
            "  }\n"
            "]\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getchaintips", "")
            + HelpExampleRpc("eb_getchaintips", "")
        );

    LOCK(EDC_cs_main);

    /*
     * Idea:  the set of chain tips is theApp.chainActive().tip, plus orphan blocks which do not have another orphan building off of them. 
     * Algorithm:
     *  - Make one pass through theApp.mapBlockIndex(), picking out the orphan blocks, and also storing a set of the orphan block's pprev pointers.
     *  - Iterate through the orphan blocks. If the block isn't pointed to by another orphan, it is a chain tip.
     *  - add theApp.chainActive().Tip()
     */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    std::set<const CBlockIndex*> setOrphans;
    std::set<const CBlockIndex*> setPrevs;

    BOOST_FOREACH(const PAIRTYPE(const uint256, CBlockIndex*)& item, theApp.mapBlockIndex())
    {
        if (!theApp.chainActive().Contains(item.second)) 
		{
            setOrphans.insert(item.second);
            setPrevs.insert(item.second->pprev);
        }
    }

    for (std::set<const CBlockIndex*>::iterator it = setOrphans.begin(); it != setOrphans.end(); ++it)
    {
        if (setPrevs.erase(*it) == 0) 
		{
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(theApp.chainActive().Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    BOOST_FOREACH(const CBlockIndex* block, setTips)
    {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("height", block->nHeight));
        obj.push_back(Pair("hash", block->phashBlock->GetHex()));

        const int branchLen = block->nHeight - theApp.chainActive().FindFork(block)->nHeight;
        obj.push_back(Pair("branchlen", branchLen));

        string status;
        if (theApp.chainActive().Contains(block)) 
		{
            // This block is part of the currently active chain.
            status = "active";
        } 
		else if (block->nStatus & BLOCK_FAILED_MASK) 
		{
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } 
		else if (block->nChainTx == 0) 
		{
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } 
		else if (block->IsValid(BLOCK_VALID_SCRIPTS)) 
		{
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } 
		else if (block->IsValid(BLOCK_VALID_TREE)) 
		{
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } 
		else 
		{
            // No clue.
            status = "unknown";
        }
        obj.push_back(Pair("status", status));

        res.push_back(obj);
    }

    return res;
}

UniValue edcmempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
	EDCapp & theApp = EDCapp::singleton();
    ret.push_back(Pair("size", (int64_t) theApp.mempool().size()));
    ret.push_back(Pair("bytes", (int64_t) theApp.mempool().GetTotalTxSize()));
    ret.push_back(Pair("usage", (int64_t) theApp.mempool().DynamicMemoryUsage()));
	EDCparams & params = EDCparams::singleton();
    size_t maxmempool = params.maxmempool * 1000000;
    ret.push_back(Pair("maxmempool", (int64_t) maxmempool));
    ret.push_back(Pair("mempoolminfee", ValueFromAmount(theApp.mempool().GetMinFee(maxmempool).GetFeePerK())));

    return ret;
}

UniValue edcgetmempoolinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getmempoolinfo\n"
            "\nReturns details on the active state of the TX memory pool.\n"
            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx,               (numeric) Current tx count\n"
            "  \"bytes\": xxxxx,              (numeric) Sum of all tx sizes\n"
            "  \"usage\": xxxxx,              (numeric) Total memory usage for the mempool\n"
            "  \"maxmempool\": xxxxx,         (numeric) Maximum memory usage for the mempool\n"
            "  \"mempoolminfee\": xxxxx       (numeric) Minimum fee for tx to be accepted\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getmempoolinfo", "")
            + HelpExampleRpc("eb_getmempoolinfo", "")
        );

    return edcmempoolInfoToJSON();
}

UniValue edcinvalidateblock(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_invalidateblock \"hash\"\n"
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to mark as invalid\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("eb_invalidateblock", "\"blockhash\"")
        );

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    {
        LOCK(EDC_cs_main);
        if (theApp.mapBlockIndex().count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = theApp.mapBlockIndex()[hash];
        edcInvalidateBlock(state, edcParams(), pblockindex);
    }

    if (state.IsValid()) 
	{
        ActivateBestChain(state, edcParams(), static_cast<CEDCBlock *>(NULL), theApp.connman().get() );
    }

    if (!state.IsValid()) 
	{
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue edcreconsiderblock(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_reconsiderblock \"hash\"\n"
            "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to reconsider\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_reconsiderblock", "\"blockhash\"")
            + HelpExampleRpc("eb_reconsiderblock", "\"blockhash\"")
        );

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    {
        LOCK(EDC_cs_main);
        if (theApp.mapBlockIndex().count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = theApp.mapBlockIndex()[hash];
        edcResetBlockFailureFlags(pblockindex);
    }

	CValidationState state;
    ActivateBestChain(state, edcParams(), static_cast<CEDCBlock *>(NULL), theApp.connman().get() );

    if (!state.IsValid()) 
	{
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

static const CRPCCommand edcCommands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "blockchain",         "eb_getblockchaininfo",      &edcgetblockchaininfo,      true  },
    { "blockchain",         "eb_getbestblockhash",       &edcgetbestblockhash,       true  },
    { "blockchain",         "eb_getblockcount",          &edcgetblockcount,          true  },
    { "blockchain",         "eb_getblock",               &edcgetblock,               true  },
    { "blockchain",         "eb_getblockhash",           &edcgetblockhash,           true  },
    { "blockchain",         "eb_getblockheader",         &edcgetblockheader,         true  },
    { "blockchain",         "eb_getchaintips",           &edcgetchaintips,           true  },
    { "blockchain",         "eb_getdifficulty",          &edcgetdifficulty,          true  },
    { "blockchain",         "eb_getmempoolancestors",    &edcgetmempoolancestors,    true  },
    { "blockchain",         "eb_getmempooldescendants",  &edcgetmempooldescendants,  true  },
	{ "blockchain",         "eb_getmempoolentry",        &edcgetmempoolentry,        true  },
    { "blockchain",         "eb_getmempoolinfo",         &edcgetmempoolinfo,         true  },
    { "blockchain",         "eb_getrawmempool",          &edcgetrawmempool,          true  },
    { "blockchain",         "eb_gettxout",               &edcgettxout,               true  },
    { "blockchain",         "eb_gettxoutsetinfo",        &edcgettxoutsetinfo,        true  },
    { "blockchain",         "eb_verifychain",            &edcverifychain,            true  },

    /* Not shown in help */
    { "hidden",             "eb_invalidateblock",        &edcinvalidateblock,        true  },
    { "hidden",             "eb_reconsiderblock",        &edcreconsiderblock,        true  },
    { "hidden",             "eb_waitfornewblock",        &edcwaitfornewblock,        true  },
    { "hidden",             "eb_waitforblock",           &edcwaitforblock,           true  },
    { "hidden",             "eb_waitforblockheight",     &edcwaitforblockheight,     true  },
};

void edcRegisterBlockchainRPCCommands(CEDCRPCTable & t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        t.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
