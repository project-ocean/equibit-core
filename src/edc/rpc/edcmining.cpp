// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/edcbase58.h"
#include "amount.h"
#include "chain.h"
#include "edc/edcchainparams.h"
#include "edc/consensus/edcconsensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "edc/edccore_io.h"
#include "init.h"
#include "edc/edcmain.h"
#include "edc/edcminer.h"
#include "edc/edcnet.h"
#include "pow.h"
#include "edc/rpc/edcserver.h"
#include "edc/edctxmempool.h"
#include "edc/edcutil.h"
#include "utilstrencodings.h"
#include "edc/edcvalidationinterface.h"
#include "edc/edcapp.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/shared_ptr.hpp>

#include <univalue.h>

using namespace std;

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive.
 * If 'height' is nonnegative, compute the estimate at the time when a given block was found.
 */
UniValue edcGetNetworkHashPS(int lookup, int height) 
{
	EDCapp & theApp = EDCapp::singleton();

    CBlockIndex *pb = theApp.chainActive().Tip();

    if (height >= 0 && height < theApp.chainActive().Height())
        pb = theApp.chainActive()[height];

    if (pb == NULL || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0)
        lookup = pb->nHeight % edcParams().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) 
	{
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

UniValue edcgetnetworkhashps(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "eb_getnetworkhashps ( blocks height )\n"
            "\nReturns the estimated network hashes per second based on the last n blocks.\n"
            "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
            "Pass in [height] to estimate the network speed at the time when a certain block was found.\n"
            "\nArguments:\n"
            "1. blocks     (numeric, optional, default=120) The number of blocks, or -1 for blocks since last difficulty change.\n"
            "2. height     (numeric, optional, default=-1) To estimate at the time of the given height.\n"
            "\nResult:\n"
            "x             (numeric) Hashes per second estimated\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getnetworkhashps", "")
            + HelpExampleRpc("eb_getnetworkhashps", "")
       );

    LOCK(EDC_cs_main);
    return edcGetNetworkHashPS(params.size() > 0 ? params[0].get_int() : 120, params.size() > 1 ? params[1].get_int() : -1);
}

UniValue edcgenerateBlocks(
	boost::shared_ptr<CReserveScript> coinbaseScript, 
	int nGenerate, 
	uint64_t nMaxTries, 
	bool keepScript)
{
	EDCapp & theApp = EDCapp::singleton();

    static const int nInnerLoopCount = 0x10000;
    int nHeightStart = 0;
    int nHeightEnd = 0;
    int nHeight = 0;

    {   // Don't keep EDC_cs_main locked
        LOCK(EDC_cs_main);
        nHeightStart = theApp.chainActive().Height();
        nHeight = nHeightStart;
        nHeightEnd = nHeightStart+nGenerate;
    }
    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);
    while (nHeight < nHeightEnd)
    {
		std::unique_ptr<CEDCBlockTemplate> pblocktemplate(EDCBlockAssembler(edcParams()).CreateNewBlock(coinbaseScript->reserveScript));

        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");

        CEDCBlock *pblock = &pblocktemplate->block;
        {
            LOCK(EDC_cs_main);
            IncrementExtraNonce(pblock, theApp.chainActive().Tip(), nExtraNonce);
        }

        while (nMaxTries > 0 && pblock->nNonce < nInnerLoopCount && 
		!CheckProofOfWork(pblock->GetHash(), pblock->nBits, edcParams().GetConsensus())) 
		{
            ++pblock->nNonce;
            --nMaxTries;
        }
        if (nMaxTries == 0) 
		{
            break;
        }
        if (pblock->nNonce == nInnerLoopCount) 
		{
            continue;
        }
        CValidationState state;
        if (!ProcessNewBlock(state, edcParams(), NULL, pblock, true, NULL, theApp.connman().get()))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight;
        blockHashes.push_back(pblock->GetHash().GetHex());

        //mark script as important because it was used at least for one coinbase output if the script came from the wallet
        if (keepScript)
        {
            coinbaseScript->KeepScript();
        }
    }
    return blockHashes;
}

UniValue edcgenerate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_generate numblocks ( maxtries )\n"
            "\nMine up to numblocks blocks immediately (before the RPC call returns)\n"
            "\nArguments:\n"
            "1. numblocks    (numeric, required) How many blocks are generated immediately.\n"
            "2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
            "\nResult\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks\n"
            + HelpExampleCli("eb_generate", "11")
        );

    int nGenerate = params[0].get_int();
    uint64_t nMaxTries = 1000000;

    if (params.size() > 1) 
	{
        nMaxTries = params[1].get_int();
    }

    boost::shared_ptr<CReserveScript> coinbaseScript;
    edcGetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call eb_keypoolrefill first");

    //throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    return edcgenerateBlocks(coinbaseScript, nGenerate, nMaxTries, true);
}

UniValue edcgeneratetoaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "eb_generatetoaddress numblocks \"address\" (maxtries)\n"
            "\nMine blocks immediately to a specified address (before the RPC call returns)\n"
            "\nArguments:\n"
            "1. numblocks    (numeric, required) How many blocks are generated immediately.\n"
            "2. address    (string, required) The address to send the newly generated equibit to.\n"
            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
            "\nResult\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("eb_generatetoaddress", "11 \"myaddress\"")
        );

    int nGenerate = params[0].get_int();
    uint64_t nMaxTries = 1000000;

    if (params.size() > 2) 
	{
        nMaxTries = params[2].get_int();
    }

    CEDCBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    
    boost::shared_ptr<CReserveScript> coinbaseScript(new CReserveScript());
    coinbaseScript->reserveScript = GetScriptForDestination(address.Get());

    return edcgenerateBlocks(coinbaseScript, nGenerate, nMaxTries, false);
}

UniValue edcgetmininginfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getmininginfo\n"
            "\nReturns a json object containing mining-related information."
            "\nResult:\n"
            "{\n"
            "  \"blocks\": nnn,             (numeric) The current block\n"
            "  \"currentblocksize\": nnn,   (numeric) The last block size\n"
			"  \"currentblockweight\": nnn, (numeric) The last block weight\n"
            "  \"currentblocktx\": nnn,     (numeric) The last block transaction\n"
            "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
            "  \"errors\": \"...\"            (string) Current errors\n"
            "  \"networkhashps\": nnn,      (numeric) The network hashes per second\n"
            "  \"pooledtx\": n              (numeric) The size of the mem pool\n"
            "  \"testnet\": true|false      (boolean) If using testnet or not\n"
			"  \"chain\": \"xxxx\",           (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getmininginfo", "")
            + HelpExampleRpc("eb_getmininginfo", "")
        );


	EDCapp & theApp = EDCapp::singleton();
    LOCK(EDC_cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("blocks",           (int)theApp.chainActive().Height()));
    obj.push_back(Pair("currentblocksize", (uint64_t)theApp.lastBlockSize()));
	obj.push_back(Pair("currentblockweight", (uint64_t)theApp.lastBlockWeight() ));
    obj.push_back(Pair("currentblocktx",   (uint64_t)theApp.lastBlockTx() ));
    obj.push_back(Pair("difficulty",       (double)edcGetDifficulty()));
    obj.push_back(Pair("errors",           edcGetWarnings("statusbar")));
    obj.push_back(Pair("networkhashps",    edcgetnetworkhashps(params, false)));
    obj.push_back(Pair("pooledtx",         (uint64_t)theApp.mempool().size()));
    obj.push_back(Pair("testnet",          edcParams().TestnetToBeDeprecatedFieldRPC()));
    obj.push_back(Pair("chain",            edcParams().NetworkIDString()));
    return obj;
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
UniValue edcprioritisetransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "eb_prioritisetransaction \"txid\" priority_delta fee_delta\n"
            "Accepts the transaction into mined blocks at a higher (or lower) priority\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id.\n"
            "2. priority_delta (numeric, required) The priority to add or subtract.\n"
            "                  The transaction selection algorithm considers the tx as it would have a higher priority.\n"
            "                  (priority of a transaction is calculated: coinage * value_in_satoshis / txsize) \n"
            "3. fee_delta      (numeric, required) The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee.\n"
            "\nResult\n"
            "true              (boolean) Returns true\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("eb_prioritisetransaction", "\"txid\", 0.0, 10000")
        );

    LOCK(EDC_cs_main);

    uint256 hash = edcParseHashStr(params[0].get_str(), "txid");
    CAmount nAmount = params[2].get_int64();

	EDCapp & theApp = EDCapp::singleton();
    theApp.mempool().PrioritiseTransaction(hash, params[0].get_str(), params[1].get_real(), nAmount);
    return true;
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid())
    {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

std::string gbt_vb_name(const Consensus::DeploymentPos pos);

UniValue edcgetblocktemplate(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_getblocktemplate ( \"jsonrequestobject\" )\n"
            "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
            "It returns data needed to construct a block to work on.\n"
            "For full specification, see BIPs 22 and 9:\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n"

            "\nArguments:\n"
            "1. \"jsonrequestobject\"       (string, optional) A json object in the following spec\n"
            "     {\n"
            "       \"mode\":\"template\"    (string, optional) This must be set to \"template\" or omitted\n"
            "       \"capabilities\":[       (array, optional) A list of strings\n"
            "           \"support\"           (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
            "           ,...\n"
            "         ]\n"
            "     }\n"
            "\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                    (numeric) The block version\n"
            "  \"rules\" : [ \"rulename\", ... ],    (array of strings) specific block rules that are to be enforced\n"
            "  \"vbavailable\" : {                 (json object) set of pending, supported versionbit (BIP 9) softfork deployments\n"
            "      \"rulename\" : bitnumber        (numeric) identifies the bit number as indicating acceptance and readiness for the named softfork rule\n"
            "      ,...\n"
            "  },\n"
            "  \"vbrequired\" : n,                 (numeric) bit mask of versionbits the server requires set in submissions\n"

            "  \"previousblockhash\" : \"xxxx\",    (string) The hash of current highest block\n"
            "  \"transactions\" : [                (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",          (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"txid\" : \"xxxx\",          (string) transaction id encoded in little-endian hexadecimal\n"
			"         \"hash\" : \"xxxx\",          (string) hash encoded in little-endian hexadecimal (including witness data)\n"

            "         \"depends\" : [              (array) array of numbers \n"
            "             n                        (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                   (numeric) difference in value between transaction inputs and outputs (in Satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,               (numeric) total SigOps cost, as counted for purposes of block limits; if key is not present, sigop cost is unknown and clients MUST NOT assume it is zero\n"
            "         \"weight\" : n,               (numeric) total transaction weight, as counted for purposes of block limits\n"
            "         \"required\" : true|false     (boolean) if provided and true, this transaction must be in the final block\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
            "  \"coinbaseaux\" : {                  (json object) data that should be included in the coinbase's scriptSig content\n"
            "      \"flags\" : \"flags\"            (string) \n"
            "  },\n"
            "  \"coinbasevalue\" : n,               (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in Satoshis)\n"
            "  \"coinbasetxn\" : { ... },           (json object) information for coinbase transaction\n"
            "  \"target\" : \"xxxx\",               (string) The hash target\n"
            "  \"mintime\" : xxx,                   (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                      (array of string) list of ways the block template may be changed \n"
            "     \"value\"                         (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",   (string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) cost limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"weightlimit\" : n,                (numeric) limit of block weight\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxx\",                 (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_getblocktemplate", "")
            + HelpExampleRpc("eb_getblocktemplate", "")
         );

    LOCK(EDC_cs_main);

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
	int64_t nMaxVersionPreVB = -1;
    if (params.size() > 0)
    {
        const UniValue& oparam = params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CEDCBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            BlockMap::iterator mi = theApp.mapBlockIndex().find(hash);

            if (mi != theApp.mapBlockIndex().end()) 
			{
                CBlockIndex *pindex = mi->second;
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = theApp.chainActive().Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, edcParams(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = find_value(oparam, "rules");
        if (aClientRules.isArray()) 
		{
            for (unsigned int i = 0; i < aClientRules.size(); ++i) 
			{
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        } 
		else 
		{
        	// NOTE: It is important that this NOT be read if versionbits is supported
            const UniValue& uvMaxVersion = find_value(oparam, "maxversion");
            if (uvMaxVersion.isNum()) 
			{
                nMaxVersionPreVB = uvMaxVersion.get_int64();
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (theApp.connman()->GetNodeCount(CEDCConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Equibit is not connected!");

    if (edcIsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Equibit is downloading blocks...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        boost::system_time checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = theApp.chainActive().Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release the wallet and main lock while waiting
        LEAVE_CRITICAL_SECTION(EDC_cs_main);
        {
            checktxtime = boost::get_system_time() + boost::posix_time::minutes(1);

            boost::unique_lock<boost::mutex> lock(edccsBestBlock);
            while (theApp.chainActive().Tip()->GetBlockHash() == hashWatchedChain && edcIsRPCRunning())
            {
                if (!theApp.blockChange().timed_wait(lock, checktxtime))
                {
                    // Timeout: Check transactions for update
                    if (theApp.mempool().GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += boost::posix_time::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(EDC_cs_main);

        if (!edcIsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static CEDCBlockTemplate* pblocktemplate;
    if (pindexPrev != theApp.chainActive().Tip() ||
        (theApp.mempool().GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = theApp.mempool().GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = theApp.chainActive().Tip();
        nStart = GetTime();

        // Create new block
        if(pblocktemplate)
        {
            delete pblocktemplate;
            pblocktemplate = NULL;
        }
        CScript scriptDummy = CScript() << OP_TRUE;
        pblocktemplate = EDCBlockAssembler(edcParams()).CreateNewBlock(scriptDummy);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CEDCBlock* pblock = &pblocktemplate->block; // pointer for convenience
	const Consensus::Params& consensusParams = edcParams().GetConsensus();

    // Update nTime
	UpdateTime(pblock, consensusParams, pindexPrev);
    pblock->nNonce = 0;

    // NOTE: If at some point we support pre-segwit miners post-segwit-activation, this needs 
	// to take segwit support into consideration
    const bool fPreSegWit = (THRESHOLD_ACTIVE != VersionBitsState(pindexPrev, consensusParams, 
							Consensus::DEPLOYMENT_SEGWIT, theApp.versionbitscache()));

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    map<uint256, int64_t> setTxIndex;
    int i = 0;
    BOOST_FOREACH (CEDCTransaction& tx, pblock->vtx) 
	{
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.push_back(Pair("data", EncodeHexTx(tx)));

        entry.push_back(Pair("txid", txHash.GetHex()));
        entry.push_back(Pair("hash", tx.GetWitnessHash().GetHex()));

        UniValue deps(UniValue::VARR);
        BOOST_FOREACH (const CEDCTxIn &in, tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.push_back(Pair("depends", deps));

        int index_in_template = i - 1;
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template]));
        int64_t nTxSigOps = pblocktemplate->vTxSigOpsCost[index_in_template];
        if (fPreSegWit) 
		{
            assert(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
            nTxSigOps /= WITNESS_SCALE_FACTOR;
        }
        entry.push_back(Pair("sigops", nTxSigOps));
        entry.push_back(Pair("weight", edcGetTransactionWeight(tx)));

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.push_back(Pair("flags", HexStr( theApp.coinbaseFlags().begin(), 
		theApp.coinbaseFlags().end())));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("capabilities", aCaps));

    UniValue aRules(UniValue::VARR);
    UniValue vbavailable(UniValue::VOBJ);

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) 
	{
        Consensus::DeploymentPos pos = Consensus::DeploymentPos(i);
        ThresholdState state = VersionBitsState(pindexPrev, consensusParams, pos, 
			theApp.versionbitscache());

        switch (state) 
		{
        case THRESHOLD_DEFINED:
        case THRESHOLD_FAILED:
            // Not exposed to GBT at all
            break;
        case THRESHOLD_LOCKED_IN:
            // Ensure bit is set in block version
            pblock->nVersion |= VersionBitsMask(consensusParams, pos);
            // FALL THROUGH to get vbavailable set...
        case THRESHOLD_STARTED:
        {
			const struct BIP9DeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
            vbavailable.push_back(Pair(gbt_vb_name(pos), consensusParams.vDeployments[pos].bit));
			if (setClientRules.find(vbinfo.name) == setClientRules.end()) 
			{
                if (!vbinfo.gbt_force) 
				{
                    // If the client doesn't support this,don't indicate it in the [default] version
                    pblock->nVersion &= ~VersionBitsMask(consensusParams, pos);
                }
            }
            break;
        }
        case THRESHOLD_ACTIVE:
        {
			// Add to rules only
            const struct BIP9DeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
            aRules.push_back(gbt_vb_name(pos));
            if (setClientRules.find(vbinfo.name) == setClientRules.end()) 
			{
           		// Not supported by the client; make sure it's safe to proceed
                if (!vbinfo.gbt_force) 
				{
					// If we do anything other than throw an exception here, be sure 
					// version/force isn't sent to old clients
                	throw JSONRPCError(RPC_INVALID_PARAMETER, 
						strprintf("Support for '%s' rule requires explicit client support", 
						vbinfo.name));
                }
            }
            break;
        }
        }
    }

    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("rules", aRules));
    result.push_back(Pair("vbavailable", vbavailable));
    result.push_back(Pair("vbrequired", int(0)));

    if (nMaxVersionPreVB >= 2) 
	{
        // If VB is supported by the client, nMaxVersionPreVB is -1, so we won't get here
        // Because BIP 34 changed how the generation transaction is serialized, we can only use version/force back to v2 blocks
        // This is safe to do [otherwise-]unconditionally only because we are throwing an exception above if a non-force deployment gets activated
        // Note that this can probably also be removed entirely after the first BIP9 non-force deployment (ie, probably segwit) gets activated
        aMutable.push_back("version/force");
    }

    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
    result.push_back(Pair("longpollid", theApp.chainActive().Tip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast)));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));

    int64_t nSigOpLimit = EDC_MAX_BLOCK_SIGOPS_COST;
    if (fPreSegWit) 
	{
        assert(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
        nSigOpLimit /= WITNESS_SCALE_FACTOR;
    }

    result.push_back(Pair("sigoplimit", nSigOpLimit));
    result.push_back(Pair("sizelimit", (int64_t)EDC_MAX_BLOCK_SERIALIZED_SIZE));
    result.push_back(Pair("weightlimit", (int64_t)EDC_MAX_BLOCK_WEIGHT));
    result.push_back(Pair("curtime", pblock->GetBlockTime()));
    result.push_back(Pair("bits", strprintf("%08x", pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));
    if (!pblocktemplate->vchCoinbaseCommitment.empty()) 
	{
        result.push_back(Pair("default_witness_commitment", 
			HexStr(pblocktemplate->vchCoinbaseCommitment.begin(), 
			pblocktemplate->vchCoinbaseCommitment.end())));
    }


    return result;
}

class submitblock_StateCatcher : public CEDCValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {};

protected:
    virtual void BlockChecked(const CEDCBlock& block, const CValidationState& stateIn) 
	{
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    };
};

UniValue edcsubmitblock(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_submitblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAttempts to submit new block to network.\n"
            "The 'jsonparametersobject' parameter is currently ignored.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"    (string, required) the hex-encoded block data to submit\n"
            "2. \"jsonparametersobject\"     (string, optional) object of optional parameters\n"
            "    {\n"
            "      \"workid\" : \"id\"    (string, optional) if the server provided a workid, it MUST be included with submissions\n"
            "    }\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_submitblock", "\"mydata\"")
            + HelpExampleRpc("eb_submitblock", "\"mydata\"")
        );

    CEDCBlock block;
    if (!DecodeHexBlk(block, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(EDC_cs_main);
        BlockMap::iterator mi = theApp.mapBlockIndex().find(hash);

        if (mi != theApp.mapBlockIndex().end()) 
		{
            CBlockIndex *pindex = mi->second;
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                return "duplicate";
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return "duplicate-invalid";
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    {
        LOCK(EDC_cs_main);
        BlockMap::iterator mi = theApp.mapBlockIndex().find(block.hashPrevBlock);
        if (mi != mapBlockIndex.end()) 
		{
            edcUpdateUncommittedBlockStructures(block, mi->second, edcParams().GetConsensus());
        }
    }

    CValidationState state;
    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(state, edcParams(), NULL, &block, true, NULL, theApp.connman().get());
    UnregisterValidationInterface(&sc);

    if (fBlockPresent)
    {
        if (fAccepted && !sc.found)
            return "duplicate-inconclusive";
        return "duplicate";
    }
    if (fAccepted)
    {
        if (!sc.found)
            return "inconclusive";
        state = sc.state;
    }
    return BIP22ValidationResult(state);
}

UniValue edcestimatefee(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_estimatefee nblocks\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric,required)\n"
            "\nResult:\n"
            "n              (numeric) estimated fee-per-kilobyte\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate.\n"
            "\nExample:\n"
            + HelpExampleCli("eb_estimatefee", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM));

    int nBlocks = params[0].get_int();
    if (nBlocks < 1)
        nBlocks = 1;

	EDCapp & theApp = EDCapp::singleton();
    CFeeRate feeRate = theApp.mempool().estimateFee(nBlocks);
    if (feeRate == CFeeRate(0))
        return -1.0;

    return ValueFromAmount(feeRate.GetFeePerK());
}

UniValue edcestimatepriority(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_estimatepriority nblocks\n"
            "\nEstimates the approximate priority a zero-fee transaction needs to begin\n"
            "confirmation within nblocks blocks.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric,required)\n"
            "\nResult:\n"
            "n              (numeric) estimated priority\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate.\n"
            "\nExample:\n"
            + HelpExampleCli("eb_estimatepriority", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM));

    int nBlocks = params[0].get_int();
    if (nBlocks < 1)
        nBlocks = 1;

	EDCapp & theApp = EDCapp::singleton();
    return theApp.mempool().estimatePriority(nBlocks);
}

UniValue edcestimatesmartfee(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_estimatesmartfee nblocks\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric,required)\n"
            "\nResult:\n"
            "{\n"
            "  \"feerate\" : x.x,     (numeric) estimate fee-per-kilobyte (in BTC)\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However it will not return a value below the mempool reject fee.\n"
            "\nExample:\n"
            + HelpExampleCli("eb_estimatesmartfee", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM));

    int nBlocks = params[0].get_int();

    UniValue result(UniValue::VOBJ);
    int answerFound;
	EDCapp & theApp = EDCapp::singleton();
    CFeeRate feeRate = theApp.mempool().estimateSmartFee(nBlocks, &answerFound);
    result.push_back(Pair("feerate", feeRate == CFeeRate(0) ? -1.0 : ValueFromAmount(feeRate.GetFeePerK())));
    result.push_back(Pair("blocks", answerFound));
    return result;
}

UniValue edcestimatesmartpriority(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_estimatesmartpriority nblocks\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nEstimates the approximate priority a zero-fee transaction needs to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric,required)\n"
            "\nResult:\n"
            "{\n"
            "  \"priority\" : x.x,    (numeric) estimated priority\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However if the mempool reject fee is set it will return 1e9 * MAX_MONEY.\n"
            "\nExample:\n"
            + HelpExampleCli("eb_estimatesmartpriority", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM));

    int nBlocks = params[0].get_int();

    UniValue result(UniValue::VOBJ);
    int answerFound;
	EDCapp & theApp = EDCapp::singleton();
    double priority = theApp.mempool().estimateSmartPriority(nBlocks, &answerFound);
    result.push_back(Pair("priority", priority));
    result.push_back(Pair("blocks", answerFound));
    return result;
}

static const CRPCCommand edcCommands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "eb_getnetworkhashps",       &edcgetnetworkhashps,       true  },
    { "mining",             "eb_getmininginfo",          &edcgetmininginfo,          true  },
    { "mining",             "eb_prioritisetransaction",  &edcprioritisetransaction,  true  },
    { "mining",             "eb_getblocktemplate",       &edcgetblocktemplate,       true  },
    { "mining",             "eb_submitblock",            &edcsubmitblock,            true  },

    { "generating",         "eb_generate",               &edcgenerate,               true  },
    { "generating",         "eb_generatetoaddress",      &edcgeneratetoaddress,      true  },

    { "util",               "eb_estimatefee",            &edcestimatefee,            true  },
    { "util",               "eb_estimatepriority",       &edcestimatepriority,       true  },
    { "util",               "eb_estimatesmartfee",       &edcestimatesmartfee,       true  },
    { "util",               "eb_estimatesmartpriority",  &edcestimatesmartpriority,  true  },
};

void edcRegisterMiningRPCCommands( CEDCRPCTable & t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        t.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
