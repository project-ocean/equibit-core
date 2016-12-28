// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/edcbase58.h"
#include "chain.h"
#include "edc/rpc/edcserver.h"
#include "init.h"
#include "edc/edcmain.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include "edc/edcutil.h"
#include "utiltime.h"
#include "edc/wallet/edcwallet.h"
#include "edc/edcmerkleblock.h"
#include "edc/edccore_io.h"
#include "edc/edcapp.h"

#include <fstream>
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <univalue.h>

#include <boost/foreach.hpp>

using namespace std;

void edcEnsureWalletIsUnlocked();
bool edcEnsureWalletIsAvailable(bool avoidException);

std::string static EncodeDumpTime(int64_t nTime) 
{
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

int64_t static DecodeDumpTime(const std::string &str) 
{
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    static const std::locale loc(std::locale::classic(),
        new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ"));

    std::istringstream iss(str);
    iss.imbue(loc);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;

    if (ptime.is_not_a_date_time())
        return 0;

    return (ptime - epoch).total_seconds();
}

std::string static EncodeDumpString(const std::string &str) 
{
    std::stringstream ret;
    BOOST_FOREACH(unsigned char c, str) 
	{
        if (c <= 32 || c >= 128 || c == '%') 
		{
            ret << '%' << HexStr(&c, &c + 1);
        } 
		else 
		{
            ret << c;
        }
    }
    return ret.str();
}

std::string edcDecodeDumpString(const std::string &str) 
{
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) 
	{
        unsigned char c = str[pos];
        if (c == '%' && pos+2 < str.length()) 
		{
            c = (((str[pos+1]>>6)*9+((str[pos+1]-'0')&15)) << 4) | 
                ((str[pos+2]>>6)*9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

UniValue edcimportprivkey(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "eb_importprivkey \"equibitprivkey\" ( \"label\" rescan )\n"
            "\nAdds a private key (as returned by dumpprivkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"equibitprivkey\"   (string, required) The private key (see dumpprivkey)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nDump a private key\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
            "\nImport the private key with rescan\n"
            + HelpExampleCli("eb_importprivkey", "\"mykey\"") +
            "\nImport using a label and without rescan\n"
            + HelpExampleCli("eb_importprivkey", "\"mykey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("eb_importprivkey", "\"mykey\", \"testing\", false")
        );


    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    edcEnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    if (fRescan && theApp.pruneMode())
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    CEDCBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CKey key = vchSecret.GetKey();
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));
    CKeyID vchAddress = pubkey.GetID();
    {
        theApp.walletMain()->MarkDirty();
        theApp.walletMain()->SetAddressBook(vchAddress, strLabel, "receive");

        // Don't throw error in case a key is already there
        if (theApp.walletMain()->HaveKey(vchAddress))
            return NullUniValue;

        theApp.walletMain()->mapKeyMetadata[vchAddress].nCreateTime = 1;

        if (!theApp.walletMain()->AddKeyPubKey(key, pubkey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        // whenever a key is imported, we need to scan the whole chain
        theApp.walletMain()->nTimeFirstKey = 1; // 0 would be considered 'no value'

        if (fRescan) 
		{
            theApp.walletMain()->ScanForWalletTransactions(theApp.chainActive().Genesis(), true);
        }
    }

    return NullUniValue;
}

void edcImportAddress(const CEDCBitcoinAddress& address, const string& strLabel);

void edcImportScript(
	const CScript & script, 
	 const string & strLabel, 
			   bool isRedeemScript)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!isRedeemScript && edcIsMine(*theApp.walletMain(), script) == ISMINE_SPENDABLE)
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

    theApp.walletMain()->MarkDirty();

    if (!theApp.walletMain()->HaveWatchOnly(script) && !theApp.walletMain()->AddWatchOnly(script))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");

    if (isRedeemScript) 
	{
        if (!theApp.walletMain()->HaveCScript(script) && !theApp.walletMain()->AddCScript(script))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding p2sh redeemScript to wallet");
        edcImportAddress(CEDCBitcoinAddress(CScriptID(script)), strLabel);
    }
	else 
	{
        CTxDestination destination;
        if (ExtractDestination(script, destination)) 
		{
            theApp.walletMain()->SetAddressBook(destination, strLabel, "receive");
		}
	}
}

void edcImportAddress(const CEDCBitcoinAddress& address, const string& strLabel)
{
	EDCapp & theApp = EDCapp::singleton();

    CScript script = GetScriptForDestination(address.Get());
    edcImportScript(script, strLabel, false);
    // add to address book or update label
    if (address.IsValid())
        theApp.walletMain()->SetAddressBook(address.Get(), strLabel, "receive");
}

UniValue edcimportaddress(const UniValue& params, bool fHelp)
{
    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "eb_importaddress \"address\" ( \"label\" rescan p2sh )\n"
            "\nAdds a script (in hex) or address that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"script\"           (string, required) The hex-encoded script (or address)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "4. p2sh                 (boolean, optional, default=false) Add the P2SH version of the script as well\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "If you have the full public key, you should call eb_importpubkey instead of this.\n"
            "\nNote: If you import a non-standard raw script in hex form, outputs sending to it will be treated\n"
            "as change, and not show up in many RPCs.\n"
            "\nExamples:\n"
            "\nImport a script with rescan\n"
            + HelpExampleCli("eb_importaddress", "\"myscript\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("eb_importaddress", "\"myscript\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("eb_importaddress", "\"myscript\", \"testing\", false")
        );


    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

	EDCapp & theApp = EDCapp::singleton();
    if (fRescan && theApp.pruneMode())
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    // Whether to import a p2sh version, too
    bool fP2SH = false;
    if (params.size() > 3)
        fP2SH = params[3].get_bool();

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    CEDCBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) 
	{
        if (fP2SH)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot use the p2sh flag with an address - use a script instead");
        edcImportAddress(address, strLabel);
    } 
	else if (IsHex(params[0].get_str())) 
	{
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        edcImportScript(CScript(data.begin(), data.end()), strLabel, fP2SH);
    } 
	else 
	{
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit address or script");
    }

    if (fRescan)
    {
        theApp.walletMain()->ScanForWalletTransactions(theApp.chainActive().Genesis(), true);
        theApp.walletMain()->ReacceptWalletTransactions();
    }

    return NullUniValue;
}

UniValue edcimportprunedfunds(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 2)
        throw runtime_error(
            "eb_importprunedfunds\n"
            "\nImports funds without rescan. Corresponding address or script must previously be included in wallet. Aimed towards pruned wallets. The end-user is responsible to import additional transactions that subsequently spend the imported outputs or rescan after the point in the blockchain the transaction is included.\n"
            "\nArguments:\n"
            "1. \"rawtransaction\" (string, required) A raw transaction in hex funding an already-existing address in wallet\n"
            "2. \"txoutproof\"     (string, required) The hex output from gettxoutproof that contains the transaction\n"
        );

    CEDCTransaction tx;
    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash();
    CEDCWalletTx wtx(theApp.walletMain(),tx);

    CDataStream ssMB(ParseHexV(params[1], "proof"), SER_NETWORK, PROTOCOL_VERSION);
    CEDCMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    //Search partial merkle tree in proof for our transaction and index in valid block
    vector<uint256> vMatch;
    vector<unsigned int> vIndex;
    unsigned int txnIndex = 0;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) == merkleBlock.header.hashMerkleRoot) 
	{
        LOCK(EDC_cs_main);

        if (!theApp.mapBlockIndex().count(merkleBlock.header.GetHash()) || !theApp.chainActive().Contains(theApp.mapBlockIndex()[merkleBlock.header.GetHash()]))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

        vector<uint256>::const_iterator it;
        if ((it = std::find(vMatch.begin(), vMatch.end(), hashTx))==vMatch.end()) 
		{
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction given doesn't exist in proof");
        }

        txnIndex = vIndex[it - vMatch.begin()];
    }
    else 
	{
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Something wrong with merkleblock");
    }

    wtx.nIndex = txnIndex;
    wtx.hashBlock = merkleBlock.header.GetHash();

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (theApp.walletMain()->IsMine(tx)) 
	{
        theApp.walletMain()->AddToWallet(wtx, false);
        return NullUniValue;
    }

    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No addresses in wallet correspond to included transaction");
}

UniValue edcremoveprunedfunds(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_removeprunedfunds \"txid\"\n"
            "\nDeletes the specified transaction from the wallet. Meant for use with pruned wallets and as a companion to importprunedfunds. This will effect wallet balances.\n"
            "\nArguments:\n"
            "1. \"txid\"           (string, required) The hex-encoded id of the transaction you are deleting\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("eb_removprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());
    vector<uint256> vHash;
    vHash.push_back(hash);
    vector<uint256> vHashOut;

    if(theApp.walletMain()->ZapSelectTx(vHash, vHashOut) != DB_LOAD_OK) 
	{
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not properly delete the transaction.");
    }

    if(vHashOut.empty()) 
	{
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction does not exist in wallet.");
    }

    return NullUniValue;
}

UniValue edcimportpubkey(const UniValue& params, bool fHelp)
{
    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "eb_importpubkey \"pubkey\" ( \"label\" rescan )\n"
            "\nAdds a public key (in hex) that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"pubkey\"           (string, required) The hex-encoded public key\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nImport a public key with rescan\n"
            + HelpExampleCli("eb_importpubkey", "\"mypubkey\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("eb_importpubkey", "\"mypubkey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("eb_importpubkey", "\"mypubkey\", \"testing\", false")
        );


    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

	EDCapp & theApp = EDCapp::singleton();
    if (fRescan && theApp.pruneMode())
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    if (!IsHex(params[0].get_str()))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey must be a hex string");
    std::vector<unsigned char> data(ParseHex(params[0].get_str()));
    CPubKey pubKey(data.begin(), data.end());
    if (!pubKey.IsFullyValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey is not a valid public key");

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    edcImportAddress(CEDCBitcoinAddress(pubKey.GetID()), strLabel);
    edcImportScript(GetScriptForRawPubKey(pubKey), strLabel, false);

    if (fRescan)
    {
        theApp.walletMain()->ScanForWalletTransactions(theApp.chainActive().Genesis(), true);
        theApp.walletMain()->ReacceptWalletTransactions();
    }

    return NullUniValue;
}


UniValue edcimportwallet(const UniValue& params, bool fHelp)
{
    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_importwallet \"filename\"\n"
            "\nImports keys from a wallet dump file (see dumpwallet).\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The wallet file\n"
            "\nExamples:\n"
            "\nDump the wallet\n"
            + HelpExampleCli("dumpwallet", "\"test\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("importwallet", "\"test\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("importwallet", "\"test\"")
        );

	EDCapp & theApp = EDCapp::singleton();
    if (theApp.pruneMode())
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets is disabled in pruned mode");

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    edcEnsureWalletIsUnlocked();

    ifstream file;
    file.open(params[0].get_str().c_str(), std::ios::in | std::ios::ate);
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    int64_t nTimeBegin = theApp.chainActive().Tip()->GetBlockTime();

    bool fGood = true;

    int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg());
    file.seekg(0, file.beg);

    theApp.walletMain()->ShowProgress(_("Importing..."), 0); // show progress dialog in GUI
    while (file.good()) 
	{
        theApp.walletMain()->ShowProgress("", std::max(1, std::min(99, (int)(((double)file.tellg() / (double)nFilesize) * 100))));
        std::string line;
        std::getline(file, line);

        if (line.empty() || line[0] == '#')
            continue;

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" "));

        if (vstr.size() < 2)
            continue;
        CEDCBitcoinSecret vchSecret;

        if (!vchSecret.SetString(vstr[0]))
            continue;

        CKey key = vchSecret.GetKey();
        CPubKey pubkey = key.GetPubKey();
        assert(key.VerifyPubKey(pubkey));
        CKeyID keyid = pubkey.GetID();

        if (theApp.walletMain()->HaveKey(keyid)) 
		{
            edcLogPrintf("Skipping import of %s (key already present)\n", CEDCBitcoinAddress(keyid).ToString());
            continue;
        }

        int64_t nTime = DecodeDumpTime(vstr[1]);
        std::string strLabel;
        bool fLabel = true;

        for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) 
		{
            if (boost::algorithm::starts_with(vstr[nStr], "#"))
                break;
            if (vstr[nStr] == "change=1")
                fLabel = false;
            if (vstr[nStr] == "reserve=1")
                fLabel = false;
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) 
			{
                strLabel = edcDecodeDumpString(vstr[nStr].substr(6));
                fLabel = true;
            }
        }

        edcLogPrintf("Importing %s...\n", CEDCBitcoinAddress(keyid).ToString());

        if (!theApp.walletMain()->AddKeyPubKey(key, pubkey)) 
		{
            fGood = false;
            continue;
        }
        theApp.walletMain()->mapKeyMetadata[keyid].nCreateTime = nTime;
        if (fLabel)
            theApp.walletMain()->SetAddressBook(keyid, strLabel, "receive");
        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close();
    theApp.walletMain()->ShowProgress("", 100); // hide progress dialog in GUI

    CBlockIndex *pindex = theApp.chainActive().Tip();
    while (pindex && pindex->pprev && pindex->GetBlockTime() > nTimeBegin - 7200)
        pindex = pindex->pprev;

    if (!theApp.walletMain()->nTimeFirstKey || nTimeBegin < theApp.walletMain()->nTimeFirstKey)
        theApp.walletMain()->nTimeFirstKey = nTimeBegin;

    edcLogPrintf("Rescanning last %i blocks\n", theApp.chainActive().Height() - pindex->nHeight + 1);
    theApp.walletMain()->ScanForWalletTransactions(pindex);
    theApp.walletMain()->MarkDirty();

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return NullUniValue;
}

UniValue edcdumpprivkey(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_dumpprivkey \"equibitaddress\"\n"
            "\nReveals the private key corresponding to 'equibitaddress'.\n"
            "Then the eb_importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"equibitaddress\"   (string, required) The equibit address for the private key\n"
            "\nResult:\n"
            "\"key\"                (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("eb_importprivkey", "\"mykey\"")
            + HelpExampleRpc("eb_dumpprivkey", "\"myaddress\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    edcEnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    CEDCBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CKey vchSecret;
    if (!theApp.walletMain()->GetKey(keyID, vchSecret))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CEDCBitcoinSecret(vchSecret).ToString();
}

UniValue edcdumpwallet(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_dumpwallet \"filename\"\n"
            "\nDumps all wallet keys in a human-readable format.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_dumpwallet", "\"test\"")
            + HelpExampleRpc("eb_dumpwallet", "\"test\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    edcEnsureWalletIsUnlocked();

    ofstream file;
    file.open(params[0].get_str().c_str());
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    std::map<CKeyID, int64_t> mapKeyBirth;
    std::set<CKeyID> setKeyPool;
    theApp.walletMain()->GetKeyBirthTimes(mapKeyBirth);
    theApp.walletMain()->GetAllReserveKeys(setKeyPool);

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth;
    for (std::map<CKeyID, int64_t>::const_iterator it = mapKeyBirth.begin(); it != mapKeyBirth.end(); it++) 
	{
        vKeyBirth.push_back(std::make_pair(it->second, it->first));
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    // produce output
	file << strprintf("# Wallet dump created by Equibit %s\n", CLIENT_BUILD);
    file << strprintf("# * Created on %s\n", EncodeDumpTime(GetTime()));
    file << strprintf("# * Best block at time of backup was %i (%s),\n", theApp.chainActive().Height(), 
		theApp.chainActive().Tip()->GetBlockHash().ToString());
    file << strprintf("#   mined on %s\n", EncodeDumpTime(theApp.chainActive().Tip()->GetBlockTime()));
    file << "\n";

    // add the base58check encoded extended master if the wallet uses HD 
    CKeyID masterKeyID = theApp.walletMain()->GetHDChain().masterKeyID;
    if (!masterKeyID.IsNull())
    {
        CKey key;
        if (theApp.walletMain()->GetKey(masterKeyID, key))
        {
            CExtKey masterKey;
            masterKey.SetMaster(key.begin(), key.size());

            CBitcoinExtKey b58extkey;
            b58extkey.SetKey(masterKey);

            file << "# extended private masterkey: " << b58extkey.ToString() << "\n\n";
        }
    }

    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++)
	{
        const CKeyID &keyid = it->second;
        std::string strTime = EncodeDumpTime(it->first);
        std::string strAddr = CEDCBitcoinAddress(keyid).ToString();
        CKey key;
        if (theApp.walletMain()->GetKey(keyid, key)) 
		{
			file << strprintf("%s %s ", CEDCBitcoinSecret(key).ToString(), strTime);
            if (theApp.walletMain()->mapAddressBook.count(keyid)) 
			{
				file << strprintf("label=%s", 
					EncodeDumpString(theApp.walletMain()->mapAddressBook[keyid].name));
            } else if (keyid == masterKeyID) 
			{
                file << "hdmaster=1";
            } 
			else if (setKeyPool.count(keyid)) 
			{
                file << "reserve=1";
            } else if (theApp.walletMain()->mapKeyMetadata[keyid].hdKeypath == "m") 
			{
                file << "inactivehdmaster=1";
            } 
			else 
			{
				file << "change=1";
			}
            file << strprintf(" # addr=%s%s\n", strAddr, 
				(theApp.walletMain()->mapKeyMetadata[keyid].hdKeypath.size() > 0 ? 
				" hdkeypath=" + theApp.walletMain()->mapKeyMetadata[keyid].hdKeypath : ""));
        }
    }

#ifdef USE_HSM
    std::map<CKeyID, int64_t> mapHSMKeyBirth;
    std::set<CKeyID> setHSMKeyPool;
    theApp.walletMain()->GetHSMKeyBirthTimes(mapHSMKeyBirth);
    theApp.walletMain()->GetAllReserveHSMKeys(setHSMKeyPool);

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vHSMKeyBirth;
    for (std::map<CKeyID, int64_t>::const_iterator it = mapHSMKeyBirth.begin(); it != mapHSMKeyBirth.end(); it++) 
	{
        vHSMKeyBirth.push_back(std::make_pair(it->second, it->first));
    }
    mapHSMKeyBirth.clear();
    std::sort(vHSMKeyBirth.begin(), vHSMKeyBirth.end());

    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vHSMKeyBirth.begin(); it !=vHSMKeyBirth.end();it++)
	{
        const CKeyID &keyid = it->second;
        std::string strTime = EncodeDumpTime(it->first);
        std::string strAddr = CEDCBitcoinAddress(keyid).ToString();
        std::string hsmid;
        if (theApp.walletMain()->GetHSMKey(keyid, hsmid)) 
		{
            if (theApp.walletMain()->mapAddressBook.count(keyid)) 
			{
                file << strprintf("%s %s label=%s # addr=%s\n", hsmid, strTime, EncodeDumpString(theApp.walletMain()->mapAddressBook[keyid].name), strAddr);
            } 
			else if (setKeyPool.count(keyid)) 
			{
                file << strprintf("%s %s reserve=1 # addr=%s\n", hsmid, strTime, strAddr);
            } 
			else 
			{
                file << strprintf("%s %s change=1 # addr=%s\n", hsmid, strTime, strAddr);
            }
        }
    }
#endif

    file << "\n";
    file << "# End of dump\n";
    file.close();

    return NullUniValue;
}

UniValue edcdumpwalletdb(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_dumpwalletdb \"filename\"\n"
            "\nDumps the wallet DB in a human-readable format.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_dumpwalletdb", "\"walletdb.txt\"")
            + HelpExampleRpc("eb_dumpwalletdb", "\"walletdb.txt\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    edcEnsureWalletIsUnlocked();

    ofstream file;
    file.open(params[0].get_str().c_str());
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

	walletdb.Dump( file );

    file.close();

    return NullUniValue;
}
