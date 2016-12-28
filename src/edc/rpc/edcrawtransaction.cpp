// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/edcbase58.h"
#include "chain.h"
#include "edc/edccoins.h"
#include "consensus/validation.h"
#include "edc/edccore_io.h"
#include "init.h"
#include "keystore.h"
#include "edc/edcmain.h"
#include "edc/edcmerkleblock.h"
#include "edc/edcnet.h"
#include "edc/policy/edcpolicy.h"
#include "edc/primitives/edctransaction.h"
#include "edc/rpc/edcserver.h"
#include "script/script.h"
#include "script/script_error.h"
#include "edc/script/edcsign.h"
#include "script/standard.h"
#include "edc/edctxmempool.h"
#include "uint256.h"
#include "utilstrencodings.h"
#ifdef ENABLE_WALLET
#include "edc/wallet/edcwallet.h"
#endif
#include "edc/edcapp.h"
#include "edc/edcchainparams.h"


#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

using namespace std;

void edcScriptPubKeyToJSON(
	const CScript & scriptPubKey, 
		 UniValue & out, 
			   bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) 
	{
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    UniValue a(UniValue::VARR);
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CEDCBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}

void TxToJSON(
	const CEDCTransaction & tx, 
			  const uint256 hashBlock, 
				 UniValue & entry)
{
	EDCapp & theApp = EDCapp::singleton();

    entry.push_back(Pair("txid", tx.GetHash().GetHex()));
	entry.push_back(Pair("hash", tx.GetWitnessHash().GetHex()));
    entry.push_back(Pair("size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION)));
	entry.push_back(Pair("vsize", (int)::edcGetVirtualTransactionSize(tx)));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));
    UniValue vin(UniValue::VARR);

    for (unsigned int i = 0; i < tx.vin.size(); i++) 
	{
        const CEDCTxIn& txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);

        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else 
		{
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (int64_t)txin.prevout.n));
            UniValue o(UniValue::VOBJ);
            o.push_back(Pair("asm", ScriptToAsmStr(txin.scriptSig, true)));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
        }

        if (!tx.wit.IsNull()) 
		{
            if (!tx.wit.vtxinwit[i].IsNull()) 
			{
                UniValue txinwitness(UniValue::VARR);
                for (unsigned int j = 0; j < tx.wit.vtxinwit[i].scriptWitness.stack.size(); j++) 
				{
                    std::vector<unsigned char> item = tx.wit.vtxinwit[i].scriptWitness.stack[j];
                    txinwitness.push_back(HexStr(item.begin(), item.end()));
                }
                in.push_back(Pair("txinwitness", txinwitness));
            }

        }

        in.push_back(Pair("sequence", (int64_t)txin.nSequence));
        vin.push_back(in);
    }

    entry.push_back(Pair("vin", vin));
    UniValue vout(UniValue::VARR);

    for (unsigned int i = 0; i < tx.vout.size(); i++) 
	{
        const CEDCTxOut& txout = tx.vout[i];
        UniValue out(UniValue::VOBJ);
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("n", (int64_t)i));
        UniValue o(UniValue::VOBJ);
        edcScriptPubKeyToJSON(txout.scriptPubKey, o, true);
        out.push_back(Pair("scriptPubKey", o));
        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));

    if (!hashBlock.IsNull()) 
	{
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = theApp.mapBlockIndex().find(hashBlock);

        if (mi != theApp.mapBlockIndex().end() && (*mi).second) 
		{
            CBlockIndex* pindex = (*mi).second;
            if (theApp.chainActive().Contains(pindex)) 
			{
                entry.push_back(Pair("confirmations", 1 + theApp.chainActive().Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

UniValue edcgetrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_getrawtransaction \"txid\" ( verbose )\n"
            "\nNOTE: By default this function only works sometimes. This is when the tx is in the mempool\n"
            "or there is an unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -eb_txindex command line option.\n"
            "\nReturn the raw transaction data.\n"
            "\nIf verbose=0, returns a string that is serialized, hex-encoded data for 'txid'.\n"
            "If verbose is non-zero, returns an Object with information about 'txid'.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction id\n"
            "2. verbose       (numeric, optional, default=0) If 0, return a string, other return a json object\n"

            "\nResult (if verbose is not set or set to 0):\n"
            "\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

            "\nResult (if verbose > 0):\n"
            "{\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
			"  \"hash\" : \"id\",        (string) The transaction hash (differs from txid for witness transactions)\n"
			"  \"size\" : n,             (numeric) The serialized transaction size\n"
			"  \"vsize\" : n,            (numeric) The virtual transaction size (differs from size for witness transactions)\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) \n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n      (numeric) The script sequence number\n"
			"       \"txinwitness\": [\"hex\", ...] (array of string) hex-encoded witness data (if any)\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [              (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"equibitaddress\"        (string) equibit address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("eb_getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("eb_getrawtransaction", "\"mytxid\", 1")
        );

    LOCK(EDC_cs_main);

    uint256 hash = ParseHashV(params[0], "parameter 1");

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0);

    CEDCTransaction tx;
    uint256 hashBlock;
    if (!GetTransaction(hash, tx, edcParams().GetConsensus(), hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    string strHex = EncodeHexTx(tx);

    if (!fVerbose)
        return strHex;

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);
    return result;
}

UniValue edcgettxoutproof(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || (params.size() != 1 && params.size() != 2))
        throw runtime_error(
            "eb_gettxoutproof [\"txid\",...] ( \"blockhash\" )\n"
            "\nReturns a hex-encoded proof that \"txid\" was included in a block.\n"
            "\nNOTE: By default this function only works sometimes. This is when there is an\n"
            "unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -eb_txindex command line option or\n"
            "specify the block in which the transaction is included manually (by blockhash).\n"
            "\nReturn the raw transaction data.\n"
            "\nArguments:\n"
            "1. \"txids\"       (string) A json array of txids to filter\n"
            "    [\n"
            "      \"txid\"     (string) A transaction hash\n"
            "      ,...\n"
            "    ]\n"
            "2. \"block hash\"  (string, optional) If specified, looks for txid in the block with this hash\n"
            "\nResult:\n"
            "\"data\"           (string) A string that is a serialized, hex-encoded data for the proof.\n"
        );

    set<uint256> setTxids;
    uint256 oneTxid;
    UniValue txids = params[0].get_array();

    for (unsigned int idx = 0; idx < txids.size(); idx++) 	
	{
        const UniValue& txid = txids[idx];
        if (txid.get_str().length() != 64 || !IsHex(txid.get_str()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid txid ")+txid.get_str());
        uint256 hash(uint256S(txid.get_str()));
        if (setTxids.count(hash))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated txid: ")+txid.get_str());
       setTxids.insert(hash);
       oneTxid = hash;
    }

    LOCK(EDC_cs_main);

    CBlockIndex* pblockindex = NULL;

    uint256 hashBlock;
    if (params.size() > 1)
    {
        hashBlock = uint256S(params[1].get_str());
        if (!theApp.mapBlockIndex().count(hashBlock))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        pblockindex = theApp.mapBlockIndex()[hashBlock];
    } 
	else 
	{
        CEDCCoins coins;
        if (theApp.coinsTip()->GetCoins(oneTxid, coins) && coins.nHeight > 0 && coins.nHeight <= theApp.chainActive().Height())
            pblockindex = theApp.chainActive()[coins.nHeight];
    }

    if (pblockindex == NULL)
    {
        CEDCTransaction tx;
        if (!GetTransaction(oneTxid, tx, edcParams().GetConsensus(), hashBlock, false) || hashBlock.IsNull())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
        if (!theApp.mapBlockIndex().count(hashBlock))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
        pblockindex = theApp.mapBlockIndex()[hashBlock];
    }

    CEDCBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, edcParams().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    unsigned int ntxFound = 0;
    BOOST_FOREACH(const CEDCTransaction&tx, block.vtx)
        if (setTxids.count(tx.GetHash()))
            ntxFound++;
    if (ntxFound != setTxids.size())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "(Not all) transactions not found in specified block");

    CDataStream ssMB(SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    CEDCMerkleBlock mb(block, setTxids);
    ssMB << mb;
    std::string strHex = HexStr(ssMB.begin(), ssMB.end());
    return strHex;
}

UniValue edcverifytxoutproof(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_verifytxoutproof \"proof\"\n"
            "\nVerifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
            "and throwing an RPC error if the block is not in our best chain\n"
            "\nArguments:\n"
            "1. \"proof\"    (string, required) The hex-encoded proof generated by eb_gettxoutproof\n"
            "\nResult:\n"
            "[\"txid\"]      (array, strings) The txid(s) which the proof commits to, or empty array if the proof is invalid\n"
        );

    CDataStream ssMB(ParseHexV(params[0], "proof"), SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    CEDCMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    UniValue res(UniValue::VARR);

    vector<uint256> vMatch;
    vector<unsigned int> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot)
        return res;

    LOCK(EDC_cs_main);

    if (!theApp.mapBlockIndex().count(merkleBlock.header.GetHash()) || !theApp.chainActive().Contains(theApp.mapBlockIndex()[merkleBlock.header.GetHash()]))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

    BOOST_FOREACH(const uint256& hash, vMatch)
        res.push_back(hash.GetHex());
    return res;
}

UniValue edccreaterawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "eb_createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,\"data\":\"hex\",...} ( locktime )\n"
            "\nCreate a transaction spending the given inputs and creating new outputs.\n"
            "Outputs can be addresses or data.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"transactions\"        (string, required) A json array of json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",    (string, required) The transaction id\n"
            "         \"vout\":n        (numeric, required) The output number\n"
			"         \"sequence\":n    (numeric, optional) The sequence number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "2. \"outputs\"             (string, required) a json object with outputs\n"
            "    {\n"
            "      \"address\": x.xxx   (numeric or string, required) The key is the equibit address, the numeric value (can be string) is the " + CURRENCY_UNIT + " amount\n"
            "      \"data\": \"hex\",     (string, required) The key is \"data\", the value is hex encoded data\n"
            "      ...\n"
            "    }\n"
            "3. locktime                (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs\n"
            "\nResult:\n"
            "\"transaction\"            (string) hex string of the transaction\n"

            "\nExamples\n"
            + HelpExampleCli("eb_createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"")
            + HelpExampleCli("eb_createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"data\\\":\\\"00010203\\\"}\"")
            + HelpExampleRpc("eb_createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"")
            + HelpExampleRpc("eb_createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"data\\\":\\\"00010203\\\"}\"")
        );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VARR)(UniValue::VOBJ)(UniValue::VNUM), true);
    if (params[0].isNull() || params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");

    UniValue inputs = params[0].get_array();
    UniValue sendTo = params[1].get_obj();

    CEDCMutableTransaction rawTx;

    if (params.size() > 2 && !params[2].isNull()) 
	{
        int64_t nLockTime = params[2].get_int64();
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }

    for (unsigned int idx = 0; idx < inputs.size(); idx++) 
	{
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        uint32_t nSequence = (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max());

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum()) 
		{
            int64_t seqNr64 = sequenceObj.get_int64();
            if (seqNr64 < 0 || seqNr64 > std::numeric_limits<uint32_t>::max())
                throw JSONRPCError(RPC_INVALID_PARAMETER, 
					"Invalid parameter, sequence number is out of range");
            else
                nSequence = (uint32_t)seqNr64;
        }

        CEDCTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    set<CEDCBitcoinAddress> setAddress;
    vector<string> addrList = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, addrList) 
	{

        if (name_ == "data") 
		{
            std::vector<unsigned char> data = ParseHexV(sendTo[name_].getValStr(),"Data");

            CEDCTxOut out(0, CScript() << OP_RETURN << data);
            rawTx.vout.push_back(out);
        } 
		else 
		{
            CEDCBitcoinAddress address(name_);
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid equibit address: ")+name_);

            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
            setAddress.insert(address);

            CScript scriptPubKey = GetScriptForDestination(address.Get());
            CAmount nAmount = AmountFromValue(sendTo[name_]);

            CEDCTxOut out(nAmount, scriptPubKey);
            rawTx.vout.push_back(out);
        }
    }

    return EncodeHexTx(rawTx);
}

UniValue edcdecoderawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_decoderawtransaction \"hexstring\"\n"
            "\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

            "\nArguments:\n"
            "1. \"hex\"      (string, required) The transaction hex string\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"id\",        (string) The transaction id\n"
			"  \"hash\" : \"id\",        (string) The transaction hash (differs from txid for witness transactions)\n"
			"  \"size\" : n,             (numeric) The transaction size\n"
			"  \"vsize\" : n,            (numeric) The virtual transaction size (differs from size for witness transactions)\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) The output number\n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
			"       \"txinwitness\": [\"hex\", ...] (array of string) hex-encoded witness data (if any)\n"
            "       \"sequence\": n     (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [             (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"12tvKAXCxZjSmdNbao16dKXC8tRWfcF5oc\"   (string) equibit address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("eb_decoderawtransaction", "\"hexstring\"")
        );

    LOCK(EDC_cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

    CEDCTransaction tx;

    if (!DecodeHexTx(tx, params[0].get_str(), true))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    UniValue result(UniValue::VOBJ);
    TxToJSON(tx, uint256(), result);

    return result;
}

UniValue edcdecodescript(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_decodescript \"hex\"\n"
            "\nDecode a hex-encoded script.\n"
            "\nArguments:\n"
            "1. \"hex\"     (string,required) the hex encoded script\n"
            "\nResult:\n"
            "{\n"
            "  \"asm\":\"asm\",   (string) Script public key\n"
            "  \"hex\":\"hex\",   (string) hex encoded public key\n"
            "  \"type\":\"type\", (string) The output type\n"
            "  \"reqSigs\": n,    (numeric) The required signatures\n"
            "  \"addresses\": [   (json array of string)\n"
            "     \"address\"     (string) equibit address\n"
            "     ,...\n"
            "  ],\n"
            "  \"p2sh\",\"address\" (string) script address\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_decodescript", "\"hexstring\"")
            + HelpExampleRpc("eb_decodescript", "\"hexstring\"")
        );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

    UniValue r(UniValue::VOBJ);
    CScript script;

    if (params[0].get_str().size() > 0)
	{
        vector<unsigned char> scriptData(ParseHexV(params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } 
	else 
	{
        // Empty scripts are valid
    }
    edcScriptPubKeyToJSON(script, r, false);

    r.push_back(Pair("p2sh", CEDCBitcoinAddress(CScriptID(script)).ToString()));
    return r;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
static void TxInErrorToJSON(const CEDCTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.push_back(Pair("txid", txin.prevout.hash.ToString()));
    entry.push_back(Pair("vout", (uint64_t)txin.prevout.n));
    entry.push_back(Pair("scriptSig", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    entry.push_back(Pair("sequence", (uint64_t)txin.nSequence));
    entry.push_back(Pair("error", strMessage));
    vErrorsRet.push_back(entry);
}

std::string edcHelpRequiringPassphrase();

UniValue edcsignrawtransaction(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "eb_signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
#ifdef ENABLE_WALLET
            + edcHelpRequiringPassphrase() + "\n"
#endif

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"
            "     [               (json array of json objects, or 'null' if none provided)\n"
            "       {\n"
            "         \"txid\":\"id\",             (string, required) The transaction id\n"
            "         \"vout\":n,                  (numeric, required) The output number\n"
            "         \"scriptPubKey\": \"hex\",   (string, required) script key\n"
			"         \"redeemScript\": \"hex\",   (string, required for P2SH or P2WSH) redeem script\n"
            "         \"amount\": value            (numeric, required) The amount spent\n"
            "       }\n"
            "       ,...\n"
            "    ]\n"
            "3. \"privatekeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
            "    [                  (json array of strings, or 'null' if none provided)\n"
            "      \"privatekey\"   (string) private key in base58-encoding\n"
            "      ,...\n"
            "    ]\n"
            "4. \"sighashtype\"     (string, optional, default=ALL) The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",           (string) The hex-encoded raw transaction with signature(s)\n"
            "  \"complete\" : true|false,   (boolean) If the transaction has a complete set of signatures\n"
            "  \"errors\" : [                 (json array of objects) Script verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",           (string) The hash of the referenced, previous transaction\n"
            "      \"vout\" : n,                (numeric) The index of the output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",       (string) The hex-encoded signature script\n"
            "      \"sequence\" : n,            (numeric) Script sequence number\n"
            "      \"error\" : \"text\"           (string) Verification or signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("eb_signrawtransaction", "\"myhex\"")
        );

#ifdef ENABLE_WALLET
    LOCK2(EDC_cs_main, theApp.walletMain() ? &theApp.walletMain()->cs_wallet : NULL);
#else
    LOCK(EDC_cs_main);
#endif
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VARR)(UniValue::VARR)(UniValue::VSTR), true);

    vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CEDCMutableTransaction> txVariants;

    while (!ssData.empty()) 
	{
        try 
		{
            CEDCMutableTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (const std::exception&) 
		{
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CEDCMutableTransaction mergedTx(txVariants[0]);

    // Fetch previous transactions (inputs):
    CEDCCoinsView viewDummy;
    CEDCCoinsViewCache view(&viewDummy);
    {
		EDCapp & theApp = EDCapp::singleton();
        LOCK(theApp.mempool().cs);
        CEDCCoinsViewCache &viewChain = *theApp.coinsTip();
        CEDCCoinsViewMemPool viewMempool(&viewChain, theApp.mempool());
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH(const CEDCTxIn& txin, mergedTx.vin) 
		{
            const uint256& prevHash = txin.prevout.hash;
            CEDCCoins coins;
            view.AccessCoins(prevHash); // this is certainly allowed to fail
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;

    if (params.size() > 2 && !params[2].isNull()) 
	{
        fGivenKeys = true;
        UniValue keys = params[2].get_array();

        for (unsigned int idx = 0; idx < keys.size(); idx++) 
		{
            UniValue k = keys[idx];
            CEDCBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey();
            if (!key.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
            tempKeystore.AddKey(key);
        }
    }
#ifdef ENABLE_WALLET
    else if (theApp.walletMain())
        edcEnsureWalletIsUnlocked();
#endif

    // Add previous txouts given in the RPC call:
    if (params.size() > 1 && !params[1].isNull()) 
	{
        UniValue prevTxs = params[1].get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); idx++) 
		{
            const UniValue& p = prevTxs[idx];
            if (!p.isObject())
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                {
                    {"txid", UniValueType(UniValue::VSTR)},
                    {"vout", UniValueType(UniValue::VNUM)},
                    {"scriptPubKey", UniValueType(UniValue::VSTR)},
                });

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                CEDCCoinsModifier coins = view.ModifyCoins(txid);
                if (coins->IsAvailable(nOut) && coins->vout[nOut].scriptPubKey != scriptPubKey) 
				{
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coins->vout[nOut].scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                if ((unsigned int)nOut >= coins->vout.size())
                    coins->vout.resize(nOut+1);
                coins->vout[nOut].scriptPubKey = scriptPubKey;
                coins->vout[nOut].nValue = 0;
                if (prevOut.exists("amount")) 
				{
                    coins->vout[nOut].nValue = AmountFromValue(find_value(prevOut, "amount"));
                }
            }

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
			if (fGivenKeys && (scriptPubKey.IsPayToScriptHash() || 
				scriptPubKey.IsPayToWitnessScriptHash()))
			{
                RPCTypeCheckObj(prevOut,
                    {
                        {"txid", UniValueType(UniValue::VSTR)},
                        {"vout", UniValueType(UniValue::VNUM)},
                        {"scriptPubKey", UniValueType(UniValue::VSTR)},
                        {"redeemScript", UniValueType(UniValue::VSTR)},
                    });
                UniValue v = find_value(prevOut, "redeemScript");

                if (!v.isNull()) 
				{
                    vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = ((fGivenKeys || !theApp.walletMain()) ? tempKeystore : *theApp.walletMain());
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    if (params.size() > 3 && !params[3].isNull()) 
	{
        static map<string, int> mapSigHashValues =
            boost::assign::map_list_of
            (string("ALL"), int(SIGHASH_ALL))
            (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
            (string("NONE"), int(SIGHASH_NONE))
            (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
            (string("SINGLE"), int(SIGHASH_SINGLE))
            (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
            ;
        string strHashType = params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CEDCTransaction txConst(mergedTx);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) 
	{
        CEDCTxIn& txin = mergedTx.vin[i];
        const CEDCCoins* coins = view.AccessCoins(txin.prevout.hash);
        if (coins == NULL || !coins->IsAvailable(txin.prevout.n)) 
		{
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coins->vout[txin.prevout.n].scriptPubKey;
		const CAmount& amount = coins->vout[txin.prevout.n].nValue;

		SignatureData sigdata;
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
			edcProduceSignature(EDCMutableTransactionSignatureCreator(&keystore, &mergedTx, i, 
				amount, nHashType), prevPubKey, sigdata);

        // ... and merge in other signatures:
        BOOST_FOREACH(const CEDCMutableTransaction& txv, txVariants) 
		{
			sigdata = edcCombineSignatures(prevPubKey, 
				EDCTransactionSignatureChecker(&txConst, i, amount), sigdata, 
				edcDataFromTransaction(txv, i));
        }

		edcUpdateTransaction(mergedTx, i, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
		if (!edcVerifyScript(txin.scriptSig, prevPubKey, 
		mergedTx.wit.vtxinwit.size() > i ? &mergedTx.wit.vtxinwit[i].scriptWitness : NULL, 
		STANDARD_SCRIPT_VERIFY_FLAGS, EDCTransactionSignatureChecker(&txConst, i, amount), &serror))
		{
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }
    bool fComplete = vErrors.empty();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(mergedTx)));
    result.push_back(Pair("complete", fComplete));

    if (!vErrors.empty()) 
	{
        result.push_back(Pair("errors", vErrors));
    }

    return result;
}

UniValue edcsendrawtransaction(const UniValue & params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_sendrawtransaction \"hexstring\" ( allowhighfees )\n"
            "\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see eb_createrawtransaction and eb_signrawtransaction calls.\n"
            "\nArguments:\n"
            "1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
            "2. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
            "\nResult:\n"
            "\"hex\"             (string) The transaction hash in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("eb_createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("eb_signrawtransaction", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("eb_sendrawtransaction", "\"signedhex\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_sendrawtransaction", "\"signedhex\"")
        );

    LOCK(EDC_cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VBOOL));

    // parse hex string from parameter
    CEDCTransaction tx;
    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash();

	EDCapp & theApp = EDCapp::singleton();
    CAmount nMaxRawTxFee = theApp.maxTxFee();
    if (params.size() > 1 && params[1].get_bool())
        nMaxRawTxFee = 0;

    CEDCCoinsViewCache &view = *theApp.coinsTip();
    const CEDCCoins* existingCoins = view.AccessCoins(hashTx);
    bool fHaveMempool = theApp.mempool().exists(hashTx);
    bool fHaveChain = existingCoins && existingCoins->nHeight < 1000000000;

    if (!fHaveMempool && !fHaveChain) 
	{
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;

        if (!AcceptToMemoryPool( theApp.mempool(), state, tx, false, &fMissingInputs, false, nMaxRawTxFee)) 
		{
            if (state.IsInvalid()) 
			{
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            } 
			else 
			{
                if (fMissingInputs) 
				{
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
    } 
	else if (fHaveChain) 
	{
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }

    if(!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
 
    CInv inv(MSG_TX, hashTx);
    theApp.connman()->ForEachNode([&inv](CEDCNode* pnode)
    {
        pnode->PushInventory(inv);
    });

    return hashTx.GetHex();
}

static const CRPCCommand edcCommands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "rawtransactions",    "eb_getrawtransaction",      &edcgetrawtransaction,      true  },
    { "rawtransactions",    "eb_createrawtransaction",   &edccreaterawtransaction,   true  },
    { "rawtransactions",    "eb_decoderawtransaction",   &edcdecoderawtransaction,   true  },
    { "rawtransactions",    "eb_decodescript",           &edcdecodescript,           true  },
    { "rawtransactions",    "eb_sendrawtransaction",     &edcsendrawtransaction,     false },
    { "rawtransactions",    "eb_signrawtransaction",     &edcsignrawtransaction,     false }, /* uses wallet if enabled */

    { "blockchain",         "eb_gettxoutproof",          &edcgettxoutproof,          true  },
    { "blockchain",         "eb_verifytxoutproof",       &edcverifytxoutproof,       true  },
};

void edcRegisterRawTransactionRPCCommands(CEDCRPCTable & t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        t.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
