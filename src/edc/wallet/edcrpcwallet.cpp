// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "edc/edcbase58.h"
#include "chain.h"
#include "edc/edccore_io.h"
#include "init.h"
#include "edc/edcmain.h"
#include "edc/edcnet.h"
#include "edc/edcnetbase.h"
#include "edc/policy/edcrbf.h"
#include "edc/rpc/edcserver.h"
#include "timedata.h"
#include "edc/edcutil.h"
#include "utilmoneystr.h"
#include "edcwallet.h"
#include "edc/wallet/edcwalletdb.h"
#include "edc/edcapp.h"
#include "edc/edcparams.h"

#ifdef USE_HSM

#include "Thales/interface.h"
#include <secp256k1.h>

namespace
{
secp256k1_context   * secp256k1_context_verify;

struct Verifier
{
    Verifier()
    {
        secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    }
    ~Verifier()
    {
        secp256k1_context_destroy(secp256k1_context_verify);
    }
};

Verifier    verifier;

}

#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

using namespace std;

namespace
{
CCriticalSection cs_nWalletUnlockTime;
};

std::string edcHelpRequiringPassphrase()
{
	EDCapp & theApp = EDCapp::singleton();

    return theApp.walletMain() && theApp.walletMain()->IsCrypted()
        ? "\nRequires wallet passphrase to be set with eb_walletpassphrase call."
        : "";
}

bool edcEnsureWalletIsAvailable(bool avoidException)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!theApp.walletMain())
    {
        if (!avoidException)
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (disabled)");
        else
            return false;
    }
    return true;
}

void edcEnsureWalletIsUnlocked()
{
	EDCapp & theApp = EDCapp::singleton();

    if (theApp.walletMain()->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
}

void WalletTxToJSON(const CEDCWalletTx& wtx, UniValue& entry)
{
	EDCapp & theApp = EDCapp::singleton();

    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms));
    if (wtx.IsCoinBase())
        entry.push_back(Pair("generated", true));
    if (confirms > 0)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", theApp.mapBlockIndex()[wtx.hashBlock]->GetBlockTime()));
    } 
	else 
	{
        entry.push_back(Pair("trusted", wtx.IsTrusted()));
    }

    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex()));
    UniValue conflicts(UniValue::VARR);

    BOOST_FOREACH(const uint256& conflict, wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.push_back(Pair("walletconflicts", conflicts));
    entry.push_back(Pair("time", wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));

    // Add opt-in RBF status
    std::string rbfStatus = "no";
    if (confirms <= 0) 
	{
		EDCapp & theApp = EDCapp::singleton();
        LOCK(theApp.mempool().cs);
        RBFTransactionState rbfState = IsRBFOptIn(wtx, theApp.mempool());
        if (rbfState == RBF_TRANSACTIONSTATE_UNKNOWN)
            rbfStatus = "unknown";
        else if (rbfState == RBF_TRANSACTIONSTATE_REPLACEABLE_BIP125)
            rbfStatus = "yes";
    }
    entry.push_back(Pair("bip125-replaceable", rbfStatus));

    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string edcAccountFromValue(const UniValue& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

UniValue edcgetnewaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_getnewaddress ( \"account\" )\n"
            "\nReturns a new Equibit address for receiving payments.\n"
            "If 'account' is specified (DEPRECATED), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
            "\nResult:\n"
            "\"equibitaddress\"    (string) The new equibit address\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getnewaddress", "")
            + HelpExampleRpc("eb_getnewaddress", "")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = edcAccountFromValue(params[0]);

	// If keys can be generated
    if (!theApp.walletMain()->IsLocked())
        theApp.walletMain()->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!theApp.walletMain()->GetKeyFromPool(newKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call eb_keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    theApp.walletMain()->SetAddressBook(keyID, strAccount, "receive");

    return CEDCBitcoinAddress(keyID).ToString();
}

UniValue edcgetnewhsmaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_getnewhsmaddress ( \"account\" )\n"
            "\nReturns a new Equibit address, derived from an HSM key pair, that can be used for receiving payments.\n"
            "If 'account' is specified (DEPRECATED), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
            "\nResult:\n"
            "\"equibitaddress\"    (string) The new equibit address\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getnewhsmaddress", "")
            + HelpExampleRpc("eb_getnewhsmaddress", "")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = edcAccountFromValue(params[0]);

#ifdef USE_HSM
	EDCparams & theParams = EDCparams::singleton();

	if( theParams.usehsm )
	{
		// If keys can be generated
	    if (!theApp.walletMain()->IsLocked())
			theApp.walletMain()->TopUpHSMKeyPool();

    	// Generate a new key that is added to wallet
	    CPubKey newKey;
   	 	if (!theApp.walletMain()->GetHSMKeyFromPool(newKey))
        	throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call eb_hsmkeypoolrefill first");
    	CKeyID keyID = newKey.GetID();

    	theApp.walletMain()->SetAddressBook(keyID, strAccount, "receive");

	    return CEDCBitcoinAddress(keyID).ToString();
	}
	else
    	throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM processing disabled. "
			"Use -eb_usehsm command line option to enable HSM processing" );
#else
    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM support is not included in the build");
#endif
}

CEDCBitcoinAddress edcGetAccountAddress(string strAccount, bool bForceNew=false)
{
	EDCapp & theApp = EDCapp::singleton();

    CPubKey pubKey;
	if (!theApp.walletMain()->GetAccountPubkey(pubKey, strAccount, bForceNew)) 
	{
		throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
	}
 
    return CEDCBitcoinAddress(pubKey.GetID());
}

UniValue edcgetaccountaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_getaccountaddress \"account\"\n"
            "\nDEPRECATED. Returns the current Equibit address for receiving payments to this account.\n"
            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"
            "\nResult:\n"
            "\"equibitaddress\"   (string) The account equibit address\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getaccountaddress", "")
            + HelpExampleCli("eb_getaccountaddress", "\"\"")
            + HelpExampleCli("eb_getaccountaddress", "\"myaccount\"")
            + HelpExampleRpc("eb_getaccountaddress", "\"myaccount\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = edcAccountFromValue(params[0]);

    UniValue ret(UniValue::VSTR);

    ret = edcGetAccountAddress(strAccount).ToString();
    return ret;
}

CEDCBitcoinAddress edcGetHSMAccountAddress(string strAccount, bool bForceNew=false)
{
	EDCapp & theApp = EDCapp::singleton();

    CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    if (!bForceNew) 
	{
        if (!account.vchPubKey.IsValid())
            bForceNew = true;
        else 
		{
            // Check if the current key has been used
            CScript scriptPubKey = GetScriptForDestination(account.vchPubKey.GetID());
            for (map<uint256, CEDCWalletTx>::iterator it = theApp.walletMain()->mapWallet.begin();
                 it != theApp.walletMain()->mapWallet.end() && account.vchPubKey.IsValid();
                 ++it)
                BOOST_FOREACH(const CEDCTxOut& txout, (*it).second.vout)
                    if (txout.scriptPubKey == scriptPubKey) 
					{
                        bForceNew = true;
                        break;
                    }
        }
    }

    // Generate a new key
    if (bForceNew) 
	{
#ifdef USE_HSM
		EDCparams & params = EDCparams::singleton();
		if( params.usehsm )
		{
        	if (!theApp.walletMain()->GetHSMKeyFromPool(account.vchPubKey))
           		throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM Keypool ran out, please call eb_hsmkeypoolrefill first");

        	theApp.walletMain()->SetAddressBook(account.vchPubKey.GetID(), strAccount, "receive");
        	walletdb.WriteAccount(strAccount, account);
		}
		else
    		throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM processing disabled. "
				"Use -eb_usehsm command line option to enable HSM processing" );
#else
	    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM support is not included in the build");
#endif
    }

    return CEDCBitcoinAddress(account.vchPubKey.GetID());
}

UniValue edcgethsmaccountaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_gethsmaccountaddress \"account\"\n"
            "\nDEPRECATED. Returns the current Equibit HSM address for receiving payments to this account.\n"
            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new HSM address created  if there is no account by the given name.\n"
            "\nResult:\n"
            "\"equibitaddress\"   (string) The account equibit address\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_gethsmaccountaddress", "\"myaccount\"")
            + HelpExampleCli("eb_gethsmaccountaddress", "\"\"" )
            + HelpExampleRpc("eb_gethsmaccountaddress", "\"\"" )
            + HelpExampleRpc("eb_gethsmaccountaddress", "\"myaccount\"")
        );

#ifdef USE_HSM
	EDCparams & theParams = EDCparams::singleton();
	if(theParams.usehsm)
	{
    	LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

	    // Parse the account first so we don't generate a key if there's an error
		string strAccount = edcAccountFromValue(params[0]);

		UniValue ret(UniValue::VSTR);

		ret = edcGetHSMAccountAddress(strAccount).ToString();

		return ret;
	}
	else
    	throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM processing disabled. "
			"Use -eb_usehsm command line option to enable HSM processing" );
#else
    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM support is not included in the build");
#endif
}

UniValue edcgetrawchangeaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_getrawchangeaddress\n"
            "\nReturns a new Equibit address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getrawchangeaddress", "")
            + HelpExampleRpc("eb_getrawchangeaddress", "")
       );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (!theApp.walletMain()->IsLocked())
        theApp.walletMain()->TopUpKeyPool();

    CEDCReserveKey reservekey(theApp.walletMain());
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call eb_keypoolrefill first");

    reservekey.KeepKey();

    CKeyID keyID = vchPubKey.GetID();

    return CEDCBitcoinAddress(keyID).ToString();
}

UniValue edcsetaccount(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_setaccount \"equibitaddress\" \"account\"\n"
            "\nDEPRECATED. Sets the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"equibitaddress\"  (string, required) The equibit address to be associated with an account.\n"
            "2. \"account\"         (string, required) The account to assign the address to.\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"tabby\"")
            + HelpExampleRpc("eb_setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"tabby\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    CEDCBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit address");

    string strAccount;
    if (params.size() > 1)
        strAccount = edcAccountFromValue(params[1]);

    // Only add the account if the address is yours.
    if (edcIsMine(*theApp.walletMain(), address.Get()))
    {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (theApp.walletMain()->mapAddressBook.count(address.Get()))
        {
            string strOldAccount = theApp.walletMain()->mapAddressBook[address.Get()].name;
            if (address == edcGetAccountAddress(strOldAccount))
                edcGetAccountAddress(strOldAccount, true);
        }
        theApp.walletMain()->SetAddressBook(address.Get(), strAccount, "receive");
    }
    else
        throw JSONRPCError(RPC_MISC_ERROR, "eb_setaccount can only be used with own address");

    return NullUniValue;
}


UniValue edcgetaccount(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_getaccount \"equibitaddress\"\n"
            "\nDEPRECATED. Returns the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"equibitaddress\"  (string, required) The equibit address for account lookup.\n"
            "\nResult:\n"
            "\"accountname\"        (string) the account address\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"")
            + HelpExampleRpc("eb_getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    CEDCBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit address");

    string strAccount;
    map<CTxDestination, CAddressBookData>::iterator mi = theApp.walletMain()->mapAddressBook.find(address.Get());
    if (mi != theApp.walletMain()->mapAddressBook.end() && !(*mi).second.name.empty())
        strAccount = (*mi).second.name;
    return strAccount;
}


UniValue edcgetaddressesbyaccount(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_getaddressesbyaccount \"account\"\n"
            "\nDEPRECATED. Returns the list of addresses for the given account.\n"
            "\nArguments:\n"
            "1. \"account\"  (string, required) The account name.\n"
            "\nResult:\n"
            "[                     (json array of string)\n"
            "  \"equibitaddress\"  (string) a equibit address associated with the given account\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getaddressesbyaccount", "\"tabby\"")
            + HelpExampleRpc("eb_getaddressesbyaccount", "\"tabby\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    string strAccount = edcAccountFromValue(params[0]);

    // Find all addresses that have the given account
    UniValue ret(UniValue::VARR);
    BOOST_FOREACH(const PAIRTYPE(CEDCBitcoinAddress, CAddressBookData)& item, theApp.walletMain()->mapAddressBook)
    {
        const CEDCBitcoinAddress& address = item.first;
        const string& strName = item.second.name;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}

namespace
{

void SendMoney(
	const CTxDestination & address, 
				   CAmount nValue, 
					  bool fSubtractFeeFromAmount, 
			CEDCWalletTx & wtxNew)
{
	EDCapp & theApp = EDCapp::singleton();

    CAmount curBalance = theApp.walletMain()->GetBalance();

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (theApp.walletMain()->GetBroadcastTransactions() && !theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    // Parse Equibit address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CEDCReserveKey reservekey(theApp.walletMain());
    CAmount nFeeRequired;
    std::string strError;
    vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount};

    vecSend.push_back(recipient);

    if (!theApp.walletMain()->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError)) 
	{
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > theApp.walletMain()->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    if (!theApp.walletMain()->CommitTransaction(wtxNew, reservekey, theApp.connman().get()))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of the wallet and coins were spent in the copy but not marked as spent here.");
}

}


UniValue edcsendtoaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "eb_sendtoaddress \"equibitaddress\" amount ( \"comment\" \"comment-to\" subtractfeefromamount )\n"
            "\nSend an amount to a given address.\n"
            + edcHelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"equibitaddress\"  (string, required) The equibit address to send to.\n"
            "2. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"     (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment-to\"  (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less equibits than you enter in the amount field.\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1")
            + HelpExampleCli("eb_sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("eb_sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("eb_sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.1, \"donation\", \"seans outpost\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    CEDCBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit address");

    // Amount
    CAmount nAmount = AmountFromValue(params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Wallet comments
    CEDCWalletTx wtx;
    if (params.size() > 2 && !params[2].isNull() && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str();
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["to"]      = params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (params.size() > 4)
        fSubtractFeeFromAmount = params[4].get_bool();

    edcEnsureWalletIsUnlocked();

    SendMoney(address.Get(), nAmount, fSubtractFeeFromAmount, wtx);

    return wtx.GetHash().GetHex();
}

UniValue edclistaddressgroupings(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp)
        throw runtime_error(
            "eb_listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"equibitaddress\",     (string) The equibit address\n"
            "      amount,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"account\"             (string, optional) The account (DEPRECATED)\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_listaddressgroupings", "")
            + HelpExampleRpc("eb_listaddressgroupings", "")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    map<CTxDestination, CAmount> balances = theApp.walletMain()->GetAddressBalances();
    BOOST_FOREACH(set<CTxDestination> grouping, theApp.walletMain()->GetAddressGroupings())
    {
        UniValue jsonGrouping(UniValue::VARR);
        BOOST_FOREACH(CTxDestination address, grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(CEDCBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                if (theApp.walletMain()->mapAddressBook.find(CEDCBitcoinAddress(address).Get()) != theApp.walletMain()->mapAddressBook.end())
                    addressInfo.push_back(theApp.walletMain()->mapAddressBook.find(CEDCBitcoinAddress(address).Get())->second.name);
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

UniValue edcsignmessage(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 2)
        throw runtime_error(
            "eb_signmessage \"equibitaddress\" \"message\"\n"
            "\nSign a message with the private key of an address"
            + edcHelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"equibitaddress\"  (string, required) The equibit address to use for the private key.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("eb_walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("eb_signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("eb_signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"my message\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    edcEnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    string strMessage = params[1].get_str();

    CEDCBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not refer to key");

    CKey key;
    if (!theApp.walletMain()->GetKey(keyID, key))
	{
#ifdef USE_HSM
		EDCparams & theParams = EDCparams::singleton();

		if( theParams.usehsm )
		{
			std::string hsmid;
			if(theApp.walletMain()->GetHSMKey(keyID, hsmid ))
			{
    			CHashWriter ss(SER_GETHASH, 0);
			    ss << edcstrMessageMagic;
			    ss << strMessage;

    			vector<unsigned char> vchSig;

   		 		if (!NFast::sign( *theApp.nfHardServer(), *theApp.nfModule(), 
				hsmid, ss.GetHash().begin(), 256, vchSig))
        			throw JSONRPCError(RPC_MISC_ERROR, "HSM Sign failed");
	
				secp256k1_ecdsa_signature sig;
				memcpy( sig.data, vchSig.data(), sizeof(sig.data));

				secp256k1_ecdsa_signature_normalize( secp256k1_context_verify, &sig, &sig );
	
				vchSig.resize(65);

				vchSig[0] = 27;	// TODO: recid needs to be computed. It is from 0 to 3.
				memcpy( &vchSig[1], sig.data, sizeof(sig.data));
	
    			return EncodeBase64(&vchSig[0], vchSig.size());
			}
			else
        		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not refer to key");
		}
		else
    		throw JSONRPCError(RPC_MISC_ERROR, "Error: HSM processing disabled. "
				"Use -eb_usehsm command line option to enable HSM processing" );
#endif
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key not available");
	}

    CHashWriter ss(SER_GETHASH, 0);
    ss << edcstrMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_MISC_ERROR, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue edcgetreceivedbyaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_getreceivedbyaddress \"equibitaddress\" ( minconf )\n"
            "\nReturns the total amount received by the given equibitaddress in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"equibitaddress\"  (string, required) The equibit address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount   (numeric) The total amount in " + CURRENCY_UNIT + " received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("eb_getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("eb_getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n"
            + HelpExampleCli("eb_getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", 6")
       );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    // Equibit address
    CEDCBitcoinAddress address = CEDCBitcoinAddress(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit address");
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!edcIsMine(*theApp.walletMain(), scriptPubKey))
        return ValueFromAmount(0);

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    CAmount nAmount = 0;
    for (map<uint256, CEDCWalletTx>::iterator it = theApp.walletMain()->mapWallet.begin(); it != theApp.walletMain()->mapWallet.end(); ++it)
    {
        const CEDCWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx))
            continue;

        BOOST_FOREACH(const CEDCTxOut& txout, wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


UniValue edcgetreceivedbyaccount(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_getreceivedbyaccount \"account\" ( minconf )\n"
            "\nDEPRECATED. Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nAmount received by the default account with at least 1 confirmation\n"
            + HelpExampleCli("eb_getreceivedbyaccount", "\"\"") +
            "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("eb_getreceivedbyaccount", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n"
            + HelpExampleCli("eb_getreceivedbyaccount", "\"tabby\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_getreceivedbyaccount", "\"tabby\", 6")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Get the set of pub keys assigned to account
    string strAccount = edcAccountFromValue(params[0]);
    set<CTxDestination> setAddress = theApp.walletMain()->GetAccountAddresses(strAccount);

    // Tally
    CAmount nAmount = 0;
    for (map<uint256, CEDCWalletTx>::iterator it = theApp.walletMain()->mapWallet.begin(); it != theApp.walletMain()->mapWallet.end(); ++it)
    {
        const CEDCWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx))
            continue;

        BOOST_FOREACH(const CEDCTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && edcIsMine(*theApp.walletMain(), address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return ValueFromAmount(nAmount);
}

UniValue edcgetbalance(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 3)
        throw runtime_error(
            "eb_getbalance ( \"account\" minconf includeWatchonly )\n"
            "\nIf account is not specified, returns the server's total available balance.\n"
            "If account is specified (DEPRECATED), returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, optional) DEPRECATED. The selected account, or \"*\" for entire wallet. It may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. includeWatchonly (bool, optional, default=false) Also include balance in watchonly addresses (see 'eb_importaddress')\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet\n"
            + HelpExampleCli("eb_getbalance", "") +
            "\nThe total amount in the wallet at least 5 blocks confirmed\n"
            + HelpExampleCli("eb_getbalance", "\"*\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_getbalance", "\"*\", 6")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (params.size() == 0)
        return  ValueFromAmount(theApp.walletMain()->GetBalance());

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (params[0].get_str() == "*") 
	{
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and "getbalance * 1 true" should return the same number
        CAmount nBalance = 0;

        for (map<uint256, CEDCWalletTx>::iterator it = theApp.walletMain()->mapWallet.begin(); 
		it != theApp.walletMain()->mapWallet.end(); ++it)
        {
            const CEDCWalletTx& wtx = (*it).second;
            if (!CheckFinalTx(wtx) || wtx.GetBlocksToMaturity() > 0 || wtx.GetDepthInMainChain() < 0)
                continue;

            CAmount allFee;
            string strSentAccount;
            list<COutputEntry> listReceived;
            list<COutputEntry> listSent;
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);
            if (wtx.GetDepthInMainChain() >= nMinDepth)
            {
                BOOST_FOREACH(const COutputEntry& r, listReceived)
                    nBalance += r.amount;
            }
            BOOST_FOREACH(const COutputEntry& s, listSent)
                nBalance -= s.amount;
            nBalance -= allFee;
        }
        return  ValueFromAmount(nBalance);
    }

    string strAccount = edcAccountFromValue(params[0]);

    CAmount nBalance = theApp.walletMain()->GetAccountBalance(strAccount, nMinDepth, filter);

    return ValueFromAmount(nBalance);
}

UniValue edcgetunconfirmedbalance(const UniValue &params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 0)
        throw runtime_error(
                "eb_getunconfirmedbalance\n"
                "Returns the server's total unconfirmed balance\n");

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    return ValueFromAmount(theApp.walletMain()->GetUnconfirmedBalance());
}

UniValue edcmovecmd(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "eb_move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
            "\nDEPRECATED. Move a specified amount from one account in your wallet to another.\n"
            "\nArguments:\n"
            "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
            "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
            "3. amount            (numeric) Quantity of " + CURRENCY_UNIT + " to move between accounts.\n"
            "4. minconf           (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"       (string, optional) An optional comment, stored in the wallet only.\n"
            "\nResult:\n"
            "true|false           (boolean) true if successful.\n"
            "\nExamples:\n"
            "\nMove 0.01 " + CURRENCY_UNIT + " from the default account to the account named tabby\n"
            + HelpExampleCli("eb_move", "\"\" \"tabby\" 0.01") +
            "\nMove 0.01 " + CURRENCY_UNIT + " timotei to akiko with a comment and funds have 6 confirmations\n"
            + HelpExampleCli("eb_move", "\"timotei\" \"akiko\" 0.01 6 \"happy birthday!\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_move", "\"timotei\", \"akiko\", 0.01, 6, \"happy birthday!\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    string strFrom = edcAccountFromValue(params[0]);
    string strTo = edcAccountFromValue(params[1]);
    CAmount nAmount = AmountFromValue(params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

	if (!theApp.walletMain()->AccountMove(strFrom, strTo, nAmount, strComment))
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true;
}


UniValue edcsendfrom(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 3 || params.size() > 6)
        throw runtime_error(
            "eb_sendfrom \"fromaccount\" \"toequibitaddress\" amount ( minconf \"comment\" \"comment-to\" )\n"
            "\nDEPRECATED (use eb_sendtoaddress). Sent an amount from an account to a equibit address."
            + edcHelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"       (string, required) The name of the account to send funds from. May be the default account using \"\".\n"
            "2. \"toequibitaddress\"  (string, required) The equibit address to send funds to.\n"
            "3. amount                (numeric or string, required) The amount in " + CURRENCY_UNIT + " (transaction fee is added on top).\n"
            "4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"           (string, optional) A comment used to store what the transaction is for. \n"
            "                                     This is not part of the transaction, just kept in your wallet.\n"
            "6. \"comment-to\"        (string, optional) An optional comment to store the name of the person or organization \n"
            "                                     to which you're sending the transaction. This is not part of the transaction, \n"
            "                                     it is just kept in your wallet.\n"
            "\nResult:\n"
            "\"transactionid\"        (string) The transaction id.\n"
            "\nExamples:\n"
            "\nSend 0.01 " + CURRENCY_UNIT + " from the default account to the address, must have at least 1 confirmation\n"
            + HelpExampleCli("eb_sendfrom", "\"\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01") +
            "\nSend 0.01 from the tabby account to the given address, funds must have at least 6 confirmations\n"
            + HelpExampleCli("eb_sendfrom", "\"tabby\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01 6 \"donation\" \"seans outpost\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_sendfrom", "\"tabby\", \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.01, 6, \"donation\", \"seans outpost\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    string strAccount = edcAccountFromValue(params[0]);
    CEDCBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit address");
    CAmount nAmount = AmountFromValue(params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CEDCWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && !params[4].isNull() && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();
    if (params.size() > 5 && !params[5].isNull() && !params[5].get_str().empty())
        wtx.mapValue["to"]      = params[5].get_str();

    edcEnsureWalletIsUnlocked();

    // Check funds
    CAmount nBalance = theApp.walletMain()->GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    SendMoney(address.Get(), nAmount, false, wtx);

    return wtx.GetHash().GetHex();
}


UniValue edcsendmany(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "eb_sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] )\n"
            "\nSend multiple times. Amounts are double-precision floating point numbers."
            + edcHelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"         (string, required) DEPRECATED. The account to send the funds from. Should be \"\" for the default account\n"
            "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
            "    {\n"
            "      \"address\":amount   (numeric or string) The equibit address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
            "      ,...\n"
            "    }\n"
            "3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
            "4. \"comment\"             (string, optional) A comment\n"
            "5. subtractfeefromamount   (string, optional) A json array with addresses.\n"
            "                           The fee will be equally deducted from the amount of each selected address.\n"
            "                           Those recipients will receive less equibits than you enter in their corresponding amount field.\n"
            "                           If no addresses are specified here, the sender pays the fee.\n"
            "    [\n"
            "      \"address\"            (string) Subtract fee from this address\n"
            "      ,...\n"
            "    ]\n"
            "\nResult:\n"
            "\"transactionid\"          (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
            "                                    the number of addresses.\n"
            "\nExamples:\n"
            "\nSend two amounts to two different addresses:\n"
            + HelpExampleCli("eb_sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
            + HelpExampleCli("eb_sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 6 \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from amount:\n"
            + HelpExampleCli("eb_sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 1 \"\" \"[\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\",\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_sendmany", "\"\", \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\", 6, \"testing\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (theApp.walletMain()->GetBroadcastTransactions() && !theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    string strAccount = edcAccountFromValue(params[0]);
    UniValue sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2)
        nMinDepth = params[2].get_int();

    CEDCWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (params.size() > 4)
        subtractFeeFromAmount = params[4].get_array();

    set<CEDCBitcoinAddress> setAddress;
    vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, keys)
    {
        CEDCBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Equibit address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[name_]);
        if (nAmount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount;

        bool fSubtractFeeFromAmount = false;
        for (unsigned int idx = 0; idx < subtractFeeFromAmount.size(); idx++) 
		{
            const UniValue& addr = subtractFeeFromAmount[idx];
            if (addr.get_str() == name_)
                fSubtractFeeFromAmount = true;
        }

        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
        vecSend.push_back(recipient);
    }

    edcEnsureWalletIsUnlocked();

    // Check funds
    CAmount nBalance = theApp.walletMain()->GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CEDCReserveKey reservekey(theApp.walletMain());
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    string strFailReason;
    bool fCreated = theApp.walletMain()->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strFailReason);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!theApp.walletMain()->CommitTransaction(wtx, reservekey, theApp.connman().get()))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}

// Defined in rpc/misc.cpp
CScript edc_createmultisig_redeemScript(const UniValue& params);

UniValue edcaddmultisigaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        string msg = "eb_addmultisigaddress nrequired [\"key\",...] ( \"account\" )\n"
            "\nAdd a nrequired-to-sign multisignature address to the wallet.\n"
            "Each key is a Equibit address or hex-encoded public key.\n"
            "If 'account' is specified (DEPRECATED), assign address to that account.\n"

            "\nArguments:\n"
            "1. nrequired        (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keysobject\"   (string, required) A json array of equibit addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"address\"  (string) equibit address or hex-encoded public key\n"
            "       ...,\n"
            "     ]\n"
            "3. \"account\"      (string, optional) DEPRECATED. An account to assign the addresses to.\n"

            "\nResult:\n"
            "\"equibitaddress\"  (string) A equibit address associated with the keys.\n"

            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("eb_addmultisigaddress", "2 \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("eb_addmultisigaddress", "2, \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"")
        ;
        throw runtime_error(msg);
    }

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    string strAccount;
    if (params.size() > 2)
        strAccount = edcAccountFromValue(params[2]);

    // Construct using pay-to-script-hash:
    CScript inner = edc_createmultisig_redeemScript(params);
    CScriptID innerID(inner);
    theApp.walletMain()->AddCScript(inner);

    theApp.walletMain()->SetAddressBook(innerID, strAccount, "send");
    return CEDCBitcoinAddress(innerID).ToString();
}

class Witnessifier : public boost::static_visitor<bool>
{
public:
    CScriptID result;

    bool operator()(const CNoDestination &dest) const { return false; }

    bool operator()(const CKeyID &keyID) 
	{
        CPubKey pubkey;
		EDCapp & theApp = EDCapp::singleton();
        if (theApp.walletMain() && theApp.walletMain()->GetPubKey(keyID, pubkey)) 
		{
            CScript basescript;
            basescript << ToByteVector(pubkey) << OP_CHECKSIG;
            CScript witscript = GetScriptForWitness(basescript);
            theApp.walletMain()->AddCScript(witscript);
            result = CScriptID(witscript);
            return true;
        }
        return false;
    }

    bool operator()(const CScriptID &scriptID) 
	{
        CScript subscript;
		EDCapp & theApp = EDCapp::singleton();
        if (theApp.walletMain() && theApp.walletMain()->GetCScript(scriptID, subscript)) 
		{
            int witnessversion;
            std::vector<unsigned char> witprog;
            if (subscript.IsWitnessProgram(witnessversion, witprog)) 
			{
                result = scriptID;
                return true;
            }
            CScript witscript = GetScriptForWitness(subscript);
            theApp.walletMain()->AddCScript(witscript);
            result = CScriptID(witscript);
            return true;
        }
        return false;
    }
};

UniValue edcaddwitnessaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 1)
    {
        string msg = "eb_addwitnessaddress \"address\"\n"
            "\nAdd a witness address for a script (with pubkey or redeemscript known).\n"
            "It returns the witness script.\n"

            "\nArguments:\n"
            "1. \"address\"       (string, required) An address known to the wallet\n"

            "\nResult:\n"
            "\"witnessaddress\",  (string) The value of the new address (P2SH of witness script).\n"
            "}\n"
        ;
        throw runtime_error(msg);
    }

	EDCparams & theParams = EDCparams::singleton();

    {
        LOCK(EDC_cs_main);
        if (!IsWitnessEnabled(theApp.chainActive().Tip(), edcParams().GetConsensus())) 
		if (!IsWitnessEnabled(theApp.chainActive().Tip(), edcParams().GetConsensus()) && 
		theParams.walletprematurewitness)
		{
            throw JSONRPCError(RPC_WALLET_ERROR, "Segregated witness not enabled on network");
        }
    }

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit address");

    Witnessifier w;
    CTxDestination dest = address.Get();
    bool ret = boost::apply_visitor(w, dest);
    if (!ret) 
	{
        throw JSONRPCError(RPC_WALLET_ERROR, "Public key or redeemscript not known to wallet");
    }

	theApp.walletMain()->SetAddressBook(w.result, "", "receive");

    return CBitcoinAddress(w.result).ToString();
}

struct tallyitem
{
    CAmount nAmount;
    int nConf;
    vector<uint256> txids;
    bool fIsWatchonly;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue edcListReceived(const UniValue& params, bool fByAccounts)
{
	EDCapp & theApp = EDCapp::singleton();

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    // Tally
    map<CEDCBitcoinAddress, tallyitem> mapTally;
    for (map<uint256, CEDCWalletTx>::iterator it = theApp.walletMain()->mapWallet.begin(); it != theApp.walletMain()->mapWallet.end(); ++it)
    {
        const CEDCWalletTx& wtx = (*it).second;

        if (wtx.IsCoinBase() || !CheckFinalTx(wtx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        BOOST_FOREACH(const CEDCTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            isminefilter mine = edcIsMine(*theApp.walletMain(), address);
            if(!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    map<string, tallyitem> mapAccountTally;
    BOOST_FOREACH(const PAIRTYPE(CEDCBitcoinAddress, CAddressBookData)& item, theApp.walletMain()->mapAddressBook)
    {
        const CEDCBitcoinAddress& address = item.first;
        const string& strAccount = item.second.name;
        map<CEDCBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (fByAccounts)
        {
            tallyitem& _item = mapAccountTally[strAccount];
            _item.nAmount += nAmount;
            _item.nConf = min(_item.nConf, nConf);
            _item.fIsWatchonly = fIsWatchonly;
        }
        else
        {
            UniValue obj(UniValue::VOBJ);
            if(fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("address",       address.ToString()));
            obj.push_back(Pair("account",       strAccount));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));

            if (!fByAccounts)
                obj.push_back(Pair("label", strAccount));
            UniValue transactions(UniValue::VARR);

            if (it != mapTally.end())
            {
                BOOST_FOREACH(const uint256& _item, (*it).second.txids)
                {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.push_back(Pair("txids", transactions));
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        {
            CAmount nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            UniValue obj(UniValue::VOBJ);
            if((*it).second.fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("account",       (*it).first));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

UniValue edclistreceivedbyaddress(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 3)
        throw runtime_error(
            "eb_listreceivedbyaddress ( minconf includeempty includeWatchonly)\n"
            "\nList balances by receiving address.\n"
            "\nArguments:\n"
            "1. minconf       (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty  (bool, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'eb_importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,        (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
            "    \"account\" : \"accountname\",       (string) DEPRECATED. The account of the receiving address. The default account is \"\".\n"
            "    \"amount\" : x.xxx,                  (numeric) The total amount in " + CURRENCY_UNIT + " received by the address\n"
            "    \"confirmations\" : n,               (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"                (string) A comment for the address/transaction, if any\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_listreceivedbyaddress", "")
            + HelpExampleCli("eb_listreceivedbyaddress", "6 true")
            + HelpExampleRpc("eb_listreceivedbyaddress", "6, true, true")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    return edcListReceived(params, false);
}

UniValue edclistreceivedbyaccount(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 3)
        throw runtime_error(
            "eb_listreceivedbyaccount ( minconf includeempty includeWatchonly)\n"
            "\nDEPRECATED. List balances by account.\n"
            "\nArguments:\n"
            "1. minconf      (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty (bool, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'eb_importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,   (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"account\" : \"accountname\",  (string) The account name of the receiving account\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n"
            "    \"confirmations\" : n,          (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"           (string) A comment for the address/transaction, if any\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_listreceivedbyaccount", "")
            + HelpExampleCli("eb_listreceivedbyaccount", "6 true")
            + HelpExampleRpc("eb_listreceivedbyaccount", "6, true, true")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    return edcListReceived(params, true);
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    CEDCBitcoinAddress addr;
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(
	const CEDCWalletTx & wtx, 
		  const string & strAccount, 
					 int nMinDepth, 
					bool fLong, 
			  UniValue & ret, 
	const isminefilter & filter)
{
	EDCapp & theApp = EDCapp::singleton();

    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        BOOST_FOREACH(const COutputEntry& s, listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if(involvesWatchonly || (edcIsMine(*theApp.walletMain(), s.destination) & ISMINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            entry.push_back(Pair("account", strSentAccount));
            MaybePushAddress(entry, s.destination);
            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount)));
            if (theApp.walletMain()->mapAddressBook.count(s.destination))
                entry.push_back(Pair("label", theApp.walletMain()->mapAddressBook[s.destination].name));
            entry.push_back(Pair("vout", s.vout));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            entry.push_back(Pair("abandoned", wtx.isAbandoned()));
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            string account;
            if (theApp.walletMain()->mapAddressBook.count(r.destination))
                account = theApp.walletMain()->mapAddressBook[r.destination].name;
            if (fAllAccounts || (account == strAccount))
            {
                UniValue entry(UniValue::VOBJ);
                if(involvesWatchonly || (edcIsMine(*theApp.walletMain(), r.destination) & ISMINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
                entry.push_back(Pair("account", account));
                MaybePushAddress(entry, r.destination);

                if (wtx.IsCoinBase())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                }
                else
                {
                    entry.push_back(Pair("category", "receive"));
                }
                entry.push_back(Pair("amount", ValueFromAmount(r.amount)));
                if (theApp.walletMain()->mapAddressBook.count(r.destination))
                    entry.push_back(Pair("label", account));
                entry.push_back(Pair("vout", r.vout));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

void edcAcentryToJSON(
	const CAccountingEntry & acentry, 
			  const string & strAccount, 
				  UniValue & ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

UniValue edclisttransactions(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 4)
        throw runtime_error(
            "eb_listtransactions ( \"account\" count from includeWatchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. from           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. includeWatchonly (bool, optional, default=false) Include transactions to watchonly addresses (see 'eb_importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"equibitaddress\",    (string) The equibit address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are respendable).\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations indicate the\n"
            "                                         transaction conflicts with the block chain\n"
            "    \"trusted\": xxx            (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\": \"label\"        (string) A comment for the address/transaction, if any\n"
            "    \"otheraccount\": \"accountname\",  (string) For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\"  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                     may be unknown for unconfirmed transactions not in the mempool\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("eb_listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("eb_listtransactions", "\"*\" 20 100") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_listtransactions", "\"*\", 20, 100")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 3)
        if(params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    const CEDCWallet::TxItems & txOrdered = theApp.walletMain()->wtxOrdered;

    // iterate backwards until we have nCount items to return:
    for (CEDCWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CEDCWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            edcAcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount+nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    vector<UniValue> arrTmp = ret.getValues();

    vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);
    vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom+nCount);

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue edclistaccounts(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 2)
        throw runtime_error(
            "eb_listaccounts ( minconf includeWatchonly)\n"
            "\nDEPRECATED. Returns Object that has account names as keys, account balances as values.\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
            "2. includeWatchonly (bool, optional, default=false) Include balances in watchonly addresses (see 'importaddress')\n"
            "\nResult:\n"
            "{                      (json object where keys are account names, and values are numeric balances\n"
            "  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n"
            "  ...\n"
            "}\n"
            "\nExamples:\n"
            "\nList account balances where there at least 1 confirmation\n"
            + HelpExampleCli("eb_listaccounts", "") +
            "\nList account balances including zero confirmation transactions\n"
            + HelpExampleCli("eb_listaccounts", "0") +
            "\nList account balances for 6 or more confirmations\n"
            + HelpExampleCli("eb_listaccounts", "6") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("eb_listaccounts", "6")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if(params.size() > 1)
        if(params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;

    map<string, CAmount> mapAccountBalances;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& entry, theApp.walletMain()->mapAddressBook) 
	{
        if (edcIsMine(*theApp.walletMain(), entry.first) & includeWatchonly) // This address belongs to me
            mapAccountBalances[entry.second.name] = 0;
    }

    for (map<uint256, CEDCWalletTx>::iterator it = theApp.walletMain()->mapWallet.begin(); it != theApp.walletMain()->mapWallet.end(); ++it)
    {
        const CEDCWalletTx& wtx = (*it).second;
        CAmount nFee;
        string strSentAccount;
        list<COutputEntry> listReceived;
        list<COutputEntry> listSent;
        int nDepth = wtx.GetDepthInMainChain();
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0)
            continue;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        BOOST_FOREACH(const COutputEntry& s, listSent)
            mapAccountBalances[strSentAccount] -= s.amount;
        if (nDepth >= nMinDepth)
        {
            BOOST_FOREACH(const COutputEntry& r, listReceived)
                if (theApp.walletMain()->mapAddressBook.count(r.destination))
                    mapAccountBalances[theApp.walletMain()->mapAddressBook[r.destination].name] += r.amount;
                else
                    mapAccountBalances[""] += r.amount;
        }
    }

    const list<CAccountingEntry> & acentries = theApp.walletMain()->laccentries;
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    UniValue ret(UniValue::VOBJ);
    BOOST_FOREACH(const PAIRTYPE(string, CAmount)& accountBalance, mapAccountBalances) 
	{
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
    }
    return ret;
}

UniValue edclistsinceblock(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp)
        throw runtime_error(
            "eb_listsinceblock ( \"blockhash\" target-confirmations includeWatchonly)\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted\n"
            "\nArguments:\n"
            "1. \"blockhash\"   (string, optional) The block hash to list transactions since\n"
            "2. target-confirmations:    (numeric, optional) The confirmations required, must be 1 or more\n"
            "3. includeWatchonly:        (bool, optional, default=false) Include transactions to watchonly addresses (see 'eb_importaddress')"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"equibitaddress\",    (string) The equibit address of the transaction. Not present for move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\" : \"label\"       (string) A comment for the address/transaction, if any\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
             "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the last block\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_listsinceblock", "")
            + HelpExampleCli("eb_listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("eb_listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    CBlockIndex *pindex = NULL;
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (params.size() > 0)
    {
        uint256 blockId;

        blockId.SetHex(params[0].get_str());
        BlockMap::iterator it = theApp.mapBlockIndex().find(blockId);
        if (it != theApp.mapBlockIndex().end())
            pindex = it->second;
    }

    if (params.size() > 1)
    {
        target_confirms = params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    int depth = pindex ? (1 + theApp.chainActive().Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VARR);

    for (map<uint256, CEDCWalletTx>::iterator it = theApp.walletMain()->mapWallet.begin(); it != theApp.walletMain()->mapWallet.end(); it++)
    {
        CEDCWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListTransactions(tx, "*", 0, true, transactions, filter);
    }

    CBlockIndex *pblockLast = theApp.chainActive()[theApp.chainActive().Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

UniValue edcgettransaction(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_gettransaction \"txid\" ( includeWatchonly )\n"
            "\nGet detailed information about in-wallet transaction <txid>\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "2. \"includeWatchonly\"    (bool, optional, default=false) Whether to include watchonly addresses in balance calculation and details[]\n"
            "\nResult:\n"
            "{\n"
            "  \"amount\" : x.xxx,        (numeric) The transaction amount in " + CURRENCY_UNIT + "\n"
            "  \"confirmations\" : n,     (numeric) The number of confirmations\n"
            "  \"blockhash\" : \"hash\",  (string) The block hash\n"
            "  \"blockindex\" : xx,       (numeric) The index of the transaction in the block that includes it\n"
            "  \"blocktime\" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
            "  \"time\" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"timereceived\" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"bip125-replaceable\": \"yes|no|unknown\"  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "  \"details\" : [\n"
            "    {\n"
            "      \"account\" : \"accountname\",  (string) DEPRECATED. The account name involved in the transaction, can be \"\" for the default account.\n"
            "      \"address\" : \"equibitaddress\",   (string) The equibit address involved in the transaction\n"
            "      \"category\" : \"send|receive\",    (string) The category, either 'send' or 'receive'\n"
            "      \"amount\" : x.xxx,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"label\" : \"label\",              (string) A comment for the address/transaction, if any\n"
            "      \"vout\" : n,                       (numeric) the vout value\n"
            "    }\n"
            "    ,...\n"
            "  ],\n"
            "  \"hex\" : \"data\"         (string) Raw data for transaction\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleCli("eb_gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleRpc("eb_gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());

    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 1)
        if(params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    UniValue entry(UniValue::VOBJ);
    if (!theApp.walletMain()->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    const CEDCWalletTx& wtx = theApp.walletMain()->mapWallet[hash];

    CAmount nCredit = wtx.GetCredit(filter);
    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = (wtx.IsFromMe(filter) ? wtx.GetValueOut() - nDebit : 0);

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
    if (wtx.IsFromMe(filter))
        entry.push_back(Pair("fee", ValueFromAmount(nFee)));

    WalletTxToJSON(wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(wtx, "*", 0, false, details, filter);
    entry.push_back(Pair("details", details));

    string strHex = EncodeHexTx(static_cast<CEDCTransaction>(wtx));
    entry.push_back(Pair("hex", strHex));

    return entry;
}

UniValue edcabandontransaction(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_abandontransaction \"txid\"\n"
            "\nMark in-wallet transaction <txid> as abandoned\n"
            "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
            "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
            "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
            "It has no effect on transactions which are already conflicted or abandoned.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("eb_abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());

    if (!theApp.walletMain()->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    if (!theApp.walletMain()->AbandonTransaction(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");

    return NullUniValue;
}


UniValue edcbackupwallet(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_backupwallet \"destination\"\n"
            "\nSafely copies current wallet file to destination, which can be a directory or a path with filename.\n"
            "\nArguments:\n"
            "1. \"destination\"   (string, required) The destination directory or file\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("eb_backupwallet", "\"backup.dat\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    string strDest = params[0].get_str();
    if (!theApp.walletMain()->BackupWallet(strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return NullUniValue;
}

UniValue edckeypoolrefill(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_keypoolrefill ( newsize )\n"
            "\nFills the keypool."
            + edcHelpRequiringPassphrase() + "\n"
            "\nArguments\n"
            "1. newsize     (numeric, optional, default=100) The new keypool size\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_keypoolrefill", "")
            + HelpExampleRpc("eb_keypoolrefill", "")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -eb_keypool
    unsigned int kpSize = 0;
    if (params.size() > 0) 
	{
        if (params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)params[0].get_int();
    }

    edcEnsureWalletIsUnlocked();
    theApp.walletMain()->TopUpKeyPool(kpSize);

    if (theApp.walletMain()->GetKeyPoolSize() < kpSize)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return NullUniValue;
}

UniValue edchsmkeypoolrefill(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "eb_hsmkeypoolrefill ( newsize )\n"
            "\nFills the keypool."
            + edcHelpRequiringPassphrase() + "\n"
            "\nArguments\n"
            "1. newsize     (numeric, optional, default=50) The new HSM keypool size\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_hsmkeypoolrefill", "")
            + HelpExampleRpc("eb_hsmkeypoolrefill", "")
        );

#ifdef USE_HSM
	EDCparams & theParams = EDCparams::singleton();
	if(theParams.usehsm)
	{
		LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

	    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -eb_keypool
	    unsigned int kpSize = 0;
	    if (params.size() > 0) 
		{
   	     	if (params[0].get_int() < 0)
   	        	throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
   	    	kpSize = (unsigned int)params[0].get_int();
   		}

    	edcEnsureWalletIsUnlocked();
    	theApp.walletMain()->TopUpHSMKeyPool(kpSize);

    	if (theApp.walletMain()->GetHSMKeyPoolSize() < kpSize)
        	throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing HSM keypool.");

    	return NullUniValue;
	}
	else
    	throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM processing disabled. "
			"Use -eb_usehsm command line option to enable HSM processing" );
#else
    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM support is not included in the build");
#endif
}


static void LockWallet(CEDCWallet* pWallet)
{
    LOCK(cs_nWalletUnlockTime);
	EDCapp & theApp = EDCapp::singleton();
    theApp.walletUnlockTime( 0 );
    pWallet->Lock();
}

UniValue edcwalletpassphrase(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (theApp.walletMain()->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "eb_walletpassphrase \"passphrase\" timeout\n"
            "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
            "This is needed prior to performing transactions related to private keys such as sending equibits\n"
            "\nArguments:\n"
            "1. \"passphrase\"     (string, required) The wallet passphrase\n"
            "2. timeout            (numeric, required) The time to keep the decryption key in seconds.\n"
            "\nNote:\n"
            "Issuing the eb_walletpassphrase command while the wallet is already unlocked will set a new unlock\n"
            "time that overrides the old one.\n"
            "\nExamples:\n"
            "\nunlock the wallet for 60 seconds\n"
            + HelpExampleCli("eb_walletpassphrase", "\"my pass phrase\" 60") +
            "\nLock the wallet again (before 60 seconds)\n"
            + HelpExampleCli("eb_walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("eb_walletpassphrase", "\"my pass phrase\", 60")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (fHelp)
        return true;
    if (!theApp.walletMain()->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but eb_walletpassphrase was called.");

    // Note that the eb_walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing 
	// SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!theApp.walletMain()->Unlock(strWalletPass))
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw runtime_error(
            "eb_walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    theApp.walletMain()->TopUpKeyPool();

    int64_t nSleepTime = params[1].get_int64();
    LOCK(cs_nWalletUnlockTime);
    theApp.walletUnlockTime( GetTime() + nSleepTime );
    edcRPCRunLater("lockwallet", boost::bind(LockWallet, theApp.walletMain()), nSleepTime);

    return NullUniValue;
}


UniValue edcwalletpassphrasechange(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (theApp.walletMain()->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "eb_walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
            "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n"
            "\nArguments:\n"
            "1. \"oldpassphrase\"      (string, required) The current passphrase\n"
            "2. \"newpassphrase\"      (string, required) The new passphrase\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_walletpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("eb_walletpassphrasechange", "\"old one\", \"new one\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (fHelp)
        return true;
    if (!theApp.walletMain()->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but eb_walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing 
	// SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "eb_walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!theApp.walletMain()->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return NullUniValue;
}

UniValue edcwalletlock(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (theApp.walletMain()->IsCrypted() && (fHelp || params.size() != 0))
        throw runtime_error(
            "eb_walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call eb_walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
            "\nExamples:\n"
            "\nSet the passphrase for 2 minutes to perform a transaction\n"
            + HelpExampleCli("eb_walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n"
            + HelpExampleCli("eb_sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n"
            + HelpExampleCli("eb_walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("eb_walletlock", "")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (fHelp)
        return true;
    if (!theApp.walletMain()->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but eb_walletlock was called.");

    {
		EDCapp & theApp = EDCapp::singleton();

        LOCK(cs_nWalletUnlockTime);
        theApp.walletMain()->Lock();
        theApp.walletUnlockTime( 0 );
    }

    return NullUniValue;
}


UniValue edcencryptwallet(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (!theApp.walletMain()->IsCrypted() && (fHelp || params.size() != 1))
        throw runtime_error(
            "eb_encryptwallet \"passphrase\"\n"
            "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
            "After this, any calls that interact with private keys such as sending or signing \n"
            "will require the passphrase to be set prior the making these calls.\n"
            "Use the eb_walletpassphrase call for this, and then eb_walletlock call.\n"
            "If the wallet is already encrypted, use the eb_walletpassphrasechange call.\n"
            "Note that this will shutdown the server.\n"
            "\nArguments:\n"
            "1. \"passphrase\"    (string, required) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.\n"
            "\nExamples:\n"
            "\nEncrypt you wallet\n"
            + HelpExampleCli("eb_encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending equibit\n"
            + HelpExampleCli("eb_walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can so something like sign\n"
            + HelpExampleCli("eb_signmessage", "\"equibitaddress\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n"
            + HelpExampleCli("eb_walletlock", "") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_encryptwallet", "\"my pass phrase\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (fHelp)
        return true;
    if (theApp.walletMain()->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but eb_encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing 
	// SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "eb_encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!theApp.walletMain()->EncryptWallet(strWalletPass))
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();

	return "wallet encrypted; Equibit/Bitcoin server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";
}

UniValue edclockunspent(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_lockunspent unlock ([{\"txid\":\"txid\",\"vout\":n},...])\n"
            "\nUpdates list of temporarily unspendable outputs.\n"
            "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
            "If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.\n"
            "A locked transaction output will not be chosen by automatic coin selection, when spending equibits.\n"
            "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
            "is always cleared (by virtue of process exit) when a node stops or fails.\n"
            "Also see the eb_listunspent call\n"
            "\nArguments:\n"
            "1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions\n"
            "2. \"transactions\"  (string, optional) A json array of objects. Each object the txid (string) vout (numeric)\n"
            "     [           (json array of json objects)\n"
            "       {\n"
            "         \"txid\":\"id\",    (string) The transaction id\n"
            "         \"vout\": n         (numeric) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "true|false    (boolean) Whether the command was successful or not\n"

            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("eb_listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("eb_lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("eb_listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("eb_lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (params.size() == 1)
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL));
    else
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL)(UniValue::VARR));

    bool fUnlock = params[0].get_bool();

    if (params.size() == 1) 
	{
        if (fUnlock)
            theApp.walletMain()->UnlockAllCoins();
        return true;
    }

    UniValue outputs = params[1].get_array();
    for (unsigned int idx = 0; idx < outputs.size(); idx++) 
	{
        const UniValue& output = outputs[idx];
        if (!output.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected object");
        const UniValue& o = output.get_obj();

        RPCTypeCheckObj(o,
            {
                {"txid", UniValueType(UniValue::VSTR)},
                {"vout", UniValueType(UniValue::VNUM)},
            });

        string txid = find_value(o, "txid").get_str();
        if (!IsHex(txid))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

        int nOutput = find_value(o, "vout").get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        COutPoint outpt(uint256S(txid), nOutput);

        if (fUnlock)
            theApp.walletMain()->UnlockCoin(outpt);
        else
            theApp.walletMain()->LockCoin(outpt);
    }

    return true;
}

UniValue edclistlockunspent(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 0)
        throw runtime_error(
            "eb_listlockunspent\n"
            "\nReturns list of temporarily unspendable outputs.\n"
            "See the lockunspent call to lock and unlock transactions for spending.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id locked\n"
            "    \"vout\" : n                      (numeric) The vout value\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("eb_listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("eb_lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("eb_listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("eb_lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_listlockunspent", "")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    vector<COutPoint> vOutpts;
    theApp.walletMain()->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    BOOST_FOREACH(COutPoint &outpt, vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.push_back(Pair("txid", outpt.hash.GetHex()));
        o.push_back(Pair("vout", (int)outpt.n));
        ret.push_back(o);
    }

    return ret;
}

UniValue edcsettxfee(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "eb_settxfee amount\n"
            "\nSet the transaction fee per kB. Overwrites the paytxfee parameter.\n"
            "\nArguments:\n"
            "1. amount         (numeric or sting, required) The transaction fee in " + CURRENCY_UNIT + "/kB\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_settxfee", "0.00001")
            + HelpExampleRpc("eb_settxfee", "0.00001")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    // Amount
    CAmount nAmount = AmountFromValue(params[0]);

    theApp.payTxFee( CFeeRate(nAmount, 1000) );
    return true;
}

UniValue edcgetwalletinfo(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getwalletinfo\n"
            "Returns an object containing various wallet state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"walletversion\": xxxxx,       (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,           (numeric) the total confirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"unconfirmed_balance\": xxx,   (numeric) the total unconfirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"immature_balance\": xxxxxx,   (numeric) the total immature balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"txcount\": xxxxxxx,           (numeric) the total number of transactions in the wallet\n"
            "  \"keypoololdest\": xxxxxx,      (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,          (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,        (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,           (numeric) the transaction fee configuration, set in " + CURRENCY_UNIT + "/kB\n"
            "  \"hdmasterkeyid\": \"<hash160>\", (string) the Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getwalletinfo", "")
            + HelpExampleRpc("eb_getwalletinfo", "")
        );

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("walletversion", theApp.walletMain()->GetVersion()));
    obj.push_back(Pair("balance",       ValueFromAmount(theApp.walletMain()->GetBalance())));
    obj.push_back(Pair("unconfirmed_balance", ValueFromAmount(theApp.walletMain()->GetUnconfirmedBalance())));
    obj.push_back(Pair("immature_balance",    ValueFromAmount(theApp.walletMain()->GetImmatureBalance())));
    obj.push_back(Pair("txcount",       (int)theApp.walletMain()->mapWallet.size()));
    obj.push_back(Pair("keypoololdest", theApp.walletMain()->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize",   (int)theApp.walletMain()->GetKeyPoolSize()));
#ifdef USE_HSM
    obj.push_back(Pair("keypoololdest", theApp.walletMain()->GetOldestHSMKeyPoolTime()));
    obj.push_back(Pair("keypoolsize",   (int)theApp.walletMain()->GetHSMKeyPoolSize()));
#endif
    if (theApp.walletMain()->IsCrypted())
        obj.push_back(Pair("unlocked_until", theApp.walletUnlockTime() ));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(theApp.payTxFee().GetFeePerK())));
    CKeyID masterKeyID = theApp.walletMain()->GetHDChain().masterKeyID;
    if (!masterKeyID.IsNull())
		obj.push_back(Pair("hdmasterkeyid", masterKeyID.GetHex()));

    return obj;
}

UniValue edcresendwallettransactions(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns array of transaction ids that were re-broadcast.\n"
            );

    if (!theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    std::vector<uint256> txids = theApp.walletMain()->ResendWalletTransactionsBefore(GetTime(), 
		theApp.connman().get());
    UniValue result(UniValue::VARR);
    BOOST_FOREACH(const uint256& txid, txids)
    {
        result.push_back(txid.ToString());
    }
    return result;
}

UniValue edclistunspent(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 3)
        throw runtime_error(
            "eb_listunspent ( minconf maxconf  [\"address\",...] )\n"
            "\nReturns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filter to only include txouts paid to specified addresses.\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, confirmations}\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) The minimum confirmations to filter\n"
            "2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter\n"
            "3. \"addresses\"    (string) A json array of equibit addresses to filter\n"
            "    [\n"
            "      \"address\"   (string) equibit address\n"
            "      ,...\n"
            "    ]\n"
            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"txid\" : \"txid\",        (string) the transaction id \n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"address\" : \"address\",  (string) the equibit address\n"
            "    \"account\" : \"account\",  (string) DEPRECATED. The associated account, or \"\" for the default account\n"
            "    \"scriptPubKey\" : \"key\", (string) the script key\n"
            "    \"amount\" : x.xxx,         (numeric) the transaction amount in " + CURRENCY_UNIT + "\n"
            "    \"confirmations\" : n       (numeric) The number of confirmations\n"
			"    \"redeemScript\" : n        (string) The redeemScript if scriptPubKey is P2SH\n"
            "    \"spendable\" : xxx,        (bool) Whether we have the private keys to spend this output\n"
            "    \"solvable\" : xxx,         (bool) Whether we know how to spend this output, ignoring the lack of keys\n"
			"    \"issuer\" : xxx,           (string, optional) Name of issuer\n" 
			"    \"issuerAddr\" : xxx,       (string, optional) Address of the issuer\n"
			"    \"issuerPubKey\" : xxx,     (string, optional) Public key of the issuer\n"
			"    \"wotLevel\" : n            (numeric, optional) Web-of-trust level of the equibit\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples\n"
            + HelpExampleCli("eb_listunspent", "")
            + HelpExampleCli("eb_listunspent", "6 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
            + HelpExampleRpc("eb_listunspent", "6, 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
        );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM)(UniValue::VARR));

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    int nMaxDepth = 9999999;
    if (params.size() > 1)
        nMaxDepth = params[1].get_int();

    set<CEDCBitcoinAddress> setAddress;
    if (params.size() > 2) 
	{
        UniValue inputs = params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) 
		{
            const UniValue& input = inputs[idx];
            CEDCBitcoinAddress address(input.get_str());
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Equibit address: ")+input.get_str());
            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.get_str());
           setAddress.insert(address);
        }
    }

	CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);
	std::vector<std::pair<std::string,CIssuer>> issuers;
    walletdb.ListIssuers( issuers );
	auto e = issuers.end();

    UniValue results(UniValue::VARR);
    vector<CEDCOutput> vecOutputs;
    assert(theApp.walletMain() != NULL);
    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);
    theApp.walletMain()->AvailableCoins(vecOutputs, false, NULL, true);

    BOOST_FOREACH(const CEDCOutput& out, vecOutputs) 
	{
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        CTxDestination address;
        const CScript& scriptPubKey = out.tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);

        if (setAddress.size() && (!fValidAddress || !setAddress.count(address)))
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));

		if(fValidAddress)
		{
            entry.push_back(Pair("address", CEDCBitcoinAddress(address).ToString()));
            if (theApp.walletMain()->mapAddressBook.count(address))
                entry.push_back(Pair("account", theApp.walletMain()->mapAddressBook[address].name));

			if(scriptPubKey.IsPayToScriptHash())
			{
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (theApp.walletMain()->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }

        entry.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
        entry.push_back(Pair("amount", ValueFromAmount(out.tx->vout[out.i].nValue)));
        entry.push_back(Pair("confirmations", out.nDepth));

        entry.push_back(Pair("spendable", out.fSpendable));
        entry.push_back(Pair("solvable", out.fSolvable));

		if( out.tx->vout[out.i].issuerPubKey.size() > 0 )
		{
    		auto i = issuers.begin();
			while( i != e )
			{
				const CIssuer & issuer = i->second;

				if( issuer.pubKey_ == out.tx->vout[out.i].issuerPubKey )
				{
					entry.push_back(Pair("issuer", i->first ));
					break;
				}

				++i;
			}

			entry.push_back(Pair("issuerAddr", 
				CEDCBitcoinAddress(out.tx->vout[out.i].issuerAddr).ToString()));

			entry.push_back(Pair("issuerPubKey",  HexStr(out.tx->vout[out.i].issuerPubKey)));
			entry.push_back(Pair("wotLevel", 
				static_cast<uint64_t>(out.tx->vout[out.i].wotMinLevel)));
		}

        results.push_back(entry);
    }

    return results;
}

namespace
{
bool getPubKey( 
			   CPubKey & pubkey, 	// OUT
    CEDCBitcoinAddress & addr,		// IN
			CEDCWallet & wallet )	// IN
{
#ifndef ENABLE_WALLET
	return false;
#endif

	CKeyID keyID;
	if (!addr.GetKeyID(keyID))
		return false;

	CPubKey vchPubKey;
#ifndef USE_HSM
	if (!wallet.GetPubKey(keyID, pubkey))
#else
	if (!wallet.GetPubKey(keyID, pubkey) && !wallet.GetHSMPubKey(keyID, pubkey))
#endif
		return false;

	if (!pubkey.IsFullyValid())
		return false;

	return true;
}
}

UniValue edctrustedsend(const UniValue & params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

	// eb_trustedsend seller buyer issuer amount wot-level (min-confirm comment )
	//
	// level 0		No trust checking is done
	// level 1		trust chain from issuer to buyer of length of up to 2
	// level 2		trust chain from issuer to buyer
	// level 3		Issuer and buyer must both sign the transaction
	//
    if (fHelp || params.size() < 5 || params.size() > 7)
        throw runtime_error(
            "eb_trustedsend \"seller\" \"buyer\" \"issuer\" amount wot-level ( min-confirm \"comment\" )\n"
			"\nMoves equibits authorized equibits from seller account to buyer account.\n"
			"The wot-level parameter determines what level of trust is used as follows:\n\n"
			"1	Trust chain from issuer to buyer of length of up to 2\n"
			"2	Trust chain from issuer to buyer\n"
			"3	Either the buyer or seller must be the issuer\n"
			"\nArguments:\n"
			"1. \"seller\"     (string, required)  address of the seller.\n"
            "2. \"buyer\"      (string, required)  address of the buyer.\n"
			"3. \"issuer\"     (string, required)  address of the equibit issuer.\n"
			"4. amount         (numeric, required) amount of equibit to move.\n"
			"5. wot-level      (numeric, required) WoT security level.\n"
            "6. minconf        (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "7. \"comment\"    (string, optional) An optional comment, stored in the wallet only.\n"
            "\nResult:\n"
            "\"transactionid\" (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_trustedsend", "\"123bed..decf0de0\" \"1459d..fea0397c\" \"129dce865ce..987cdef\" 10.0 1 \"happy birthday!\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("eb_trustedsend", "\"1cd90s..decf0de0\", \"1459d..fea0397c\", \"129dce865ce..987cdef\" 80.50, 1, \"happy birthday!\"")
		);
    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);
    CEDCBitcoinAddress seller(params[0].get_str());
    if (!seller.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit seller address");

    CEDCBitcoinAddress buyer(params[1].get_str());
    if (!buyer.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit buyer address");

    CEDCBitcoinAddress issuer(params[2].get_str());
    if (!buyer.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Equibit issuer address");

    // Amount
    CAmount nAmount = AmountFromValue(params[3]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    int wotlvl = static_cast<int>(AmountFromValue(params[4]));
	if( wotlvl < 0 || wotlvl > 3 )
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid WoT level value. It must be between 0 and 3");

    int mincnf = ( params.size() > 5 ) ? params[5].get_int() : 1;
	if( mincnf < 1 )
        throw JSONRPCError(RPC_TYPE_ERROR, 
			"Invalid minimum confirmation value. It must be greater than 1");

    string  comment = ( params.size() > 6 ) ? params[6].get_str() : "";

    // Wallet comments
    CEDCWalletTx wtx;

    if (comment.size() > 0 )
        wtx.mapValue["comment"] = comment;

    edcEnsureWalletIsUnlocked();

    if (theApp.walletMain()->GetBroadcastTransactions() && !theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, 
			"Error: Peer-to-peer functionality missing or disabled");

	if( wotlvl > 0 )
	{
		CPubKey	epubkey;
		CPubKey	bpubkey;
		CPubKey	spubkey;

		if(getPubKey( epubkey, issuer, *theApp.walletMain() ) )
        	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No public key corresponds to issuer address ");
		if(getPubKey( bpubkey, buyer, *theApp.walletMain() ) )
        	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No public key corresponds to buyer address ");
		if(getPubKey( spubkey, seller, *theApp.walletMain() ) )
        	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No public key corresponds to seller address ");

		if(theApp.walletMain()->WoTchainExists( epubkey, bpubkey, spubkey, wotlvl ))
			throw JSONRPCError(RPC_TYPE_ERROR, "No trust chain could be found to buyer" );

		// If the WoT level is 3, then the issuer must be either the buyer or the seller
		if( wotlvl == 3 && ( epubkey != bpubkey ) && ( epubkey != spubkey ) )
			throw JSONRPCError(RPC_TYPE_ERROR, 
				"The issuer must be the buyer or seller in WoT level 3 transactions" );
	}

    // Parse Equibit address
    CScript scriptPubKey = GetScriptForDestination(buyer.Get());

    // Create and send the transaction
    CEDCReserveKey reservekey(theApp.walletMain());
    CAmount nFeeRequired;
    std::string strError;
    vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = { scriptPubKey, nAmount, false };

    vecSend.push_back(recipient);

    if (!theApp.walletMain()->CreateTrustedTransaction(
		issuer, wotlvl, vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError)) 
	{
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    if (!theApp.walletMain()->CommitTransaction(wtx, reservekey, theApp.connman().get()))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might "
			"happen if some of the coins in your wallet were already spent, such as if you used "
			"a copy of the wallet and coins were spent in the copy but not marked as spent here.");

    return wtx.GetHash().GetHex();
}

UniValue edcfundrawtransaction(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_fundrawtransaction \"hexstring\" ( options )\n"
            "\nAdd inputs to a transaction until it has enough in value to meet its out value.\n"
            "This will not modify existing inputs, and will add one change output to the outputs.\n"
            "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
            "The inputs added will not be signed, use signrawtransaction for that.\n"
            "Note that all existing inputs must have their previous output transaction be in the wallet.\n"
            "Note that all inputs selected must be of standard form and P2SH scripts must be\n"
            "in the wallet using eb_importaddress or eb_addmultisigaddress (to calculate fees).\n"
            "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
            "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n"
            "\nArguments:\n"
            "1. \"hexstring\"           (string, required) The hex string of the raw transaction\n"
            "2. options               (object, optional)\n"
            "   {\n"
            "     \"changeAddress\"     (string, optional, default pool address) The equibit address to receive the change\n"
            "     \"changePosition\"    (numeric, optional, default random) The index of the change output\n"
            "     \"includeWatching\"   (boolean, optional, default false) Also select inputs which are watch only\n"
            "     \"lockUnspents\"      (boolean, optional, default false) Lock selected unspent outputs\n"
			"     \"feeRate\"           (numeric, optional, default not set: makes wallet determine the fee) Set a specific feerate (" + CURRENCY_UNIT + " per KB)\n"
            "   }\n"
            "                         for backward compatibility: passing in a true instead of an object will result in {\"includeWatching\":true}\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\":       \"value\", (string)  The resulting raw transaction (hex-encoded string)\n"
			"  \"fee\":       n,         (numeric) Fee in " + CURRENCY_UNIT + " the resulting transaction pays\n"
            "  \"changepos\": n          (numeric) The position of the added change output, or -1\n"
            "}\n"
            "\"hex\"             \n"
            "\nExamples:\n"
            "\nCreate a transaction with no inputs\n"
            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
            "\nAdd sufficient unsigned inputs to meet the output value\n"
            + HelpExampleCli("eb_fundrawtransaction", "\"rawtransactionhex\"") +
            "\nSign the transaction\n"
            + HelpExampleCli("signrawtransaction", "\"fundedtransactionhex\"") +
            "\nSend the transaction\n"
            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

    CTxDestination changeAddress = CNoDestination();
    int changePosition = -1;
    bool includeWatching = false;
    bool lockUnspents = false;
	CFeeRate feeRate = CFeeRate(0);
	bool overrideEstimatedFeerate = false;

    if (params.size() > 1) 
	{
      	if (params[1].type() == UniValue::VBOOL) 
		{
       		// backward compatibility bool only fallback
        	includeWatching = params[1].get_bool();
      	}
      	else 
		{
        	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VOBJ));

        	UniValue options = params[1];

            RPCTypeCheckObj(options,
            {
                {"changeAddress", UniValueType(UniValue::VSTR)},
                {"changePosition", UniValueType(UniValue::VNUM)},
                {"includeWatching", UniValueType(UniValue::VBOOL)},
                {"lockUnspents", UniValueType(UniValue::VBOOL)},
                {"feeRate", UniValueType()}, // will be checked below
            },
            true, true);

        if (options.exists("changeAddress")) 
		{
            CEDCBitcoinAddress address(options["changeAddress"].get_str());

            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_PARAMETER, "changeAddress must be a valid equibit address");

            changeAddress = address.Get();
        }

        if (options.exists("changePosition"))
            changePosition = options["changePosition"].get_int();

        if (options.exists("includeWatching"))
            includeWatching = options["includeWatching"].get_bool();

        if (options.exists("lockUnspents"))
            lockUnspents = options["lockUnspents"].get_bool();

        if (options.exists("feeRate"))
		{
			feeRate = CFeeRate(AmountFromValue(options["feeRate"]));
			overrideEstimatedFeerate = true;
		}
      }
    }

    // parse hex string from parameter
    CEDCTransaction origTx;
    if (!DecodeHexTx(origTx, params[0].get_str(), true))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    if (origTx.vout.size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

	if (changePosition != -1 && (changePosition < 0 || 
	(unsigned int)changePosition > origTx.vout.size()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changePosition out of bounds");

    CEDCMutableTransaction tx(origTx);
    CAmount nFeeOut;
    string strFailReason;

	if(!theApp.walletMain()->FundTransaction(tx, nFeeOut, overrideEstimatedFeerate, feeRate, changePosition, strFailReason, includeWatching, lockUnspents, changeAddress))
        throw JSONRPCError(RPC_INTERNAL_ERROR, strFailReason);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(tx)));
    result.push_back(Pair("changepos", changePosition));
    result.push_back(Pair("fee", ValueFromAmount(nFeeOut)));

    return result;
}

UniValue edcdumpprivkey(const UniValue& params, bool fHelp);
UniValue edcimportprivkey(const UniValue& params, bool fHelp);
UniValue edcimportaddress(const UniValue& params, bool fHelp);
UniValue edcimportpubkey(const UniValue& params, bool fHelp);
UniValue edcdumpwallet(const UniValue& params, bool fHelp);
UniValue edcdumpwalletdb(const UniValue& params, bool fHelp);
UniValue edcimportwallet(const UniValue& params, bool fHelp);
UniValue edcimportprunedfunds(const UniValue& params, bool fHelp);
UniValue edcremoveprunedfunds(const UniValue& params, bool fHelp);


static const CRPCCommand edcCommands[] =
{ //  category              name                        actor (function)           okSafeMode
    //  --------------------- ------------------------    -----------------------    ----------
    { "rawtransactions",    "eb_fundrawtransaction",       &edcfundrawtransaction,       false },
    { "hidden",             "eb_resendwallettransactions", &edcresendwallettransactions, true  },
    { "wallet",             "eb_abandontransaction",       &edcabandontransaction,       false },
    { "wallet",             "eb_addmultisigaddress",       &edcaddmultisigaddress,       true  },
    { "wallet",             "eb_addwitnessaddress",        &edcaddwitnessaddress,        true  },
    { "wallet",             "eb_backupwallet",             &edcbackupwallet,             true  },
    { "wallet",             "eb_dumpprivkey",              &edcdumpprivkey,              true  },
    { "wallet",             "eb_dumpwallet",               &edcdumpwallet,               true  },
    { "equibit",            "eb_dumpwalletdb",             &edcdumpwalletdb,             false },
    { "wallet",             "eb_encryptwallet",            &edcencryptwallet,            true  },
    { "wallet",             "eb_getaccountaddress",        &edcgetaccountaddress,        true  },
    { "equibit",            "eb_gethsmaccountaddress",     &edcgethsmaccountaddress,     true  },
    { "wallet",             "eb_getaccount",               &edcgetaccount,               true  },
    { "wallet",             "eb_getaddressesbyaccount",    &edcgetaddressesbyaccount,    true  },
    { "wallet",             "eb_getbalance",               &edcgetbalance,               false },
    { "wallet",             "eb_getnewaddress",            &edcgetnewaddress,            true  },
    { "equibit",            "eb_getnewhsmaddress",         &edcgetnewhsmaddress,         true  },
    { "wallet",             "eb_getrawchangeaddress",      &edcgetrawchangeaddress,      true  },
    { "wallet",             "eb_getreceivedbyaccount",     &edcgetreceivedbyaccount,     false },
    { "wallet",             "eb_getreceivedbyaddress",     &edcgetreceivedbyaddress,     false },
    { "wallet",             "eb_gettransaction",           &edcgettransaction,           false },
    { "wallet",             "eb_getunconfirmedbalance",    &edcgetunconfirmedbalance,    false },
    { "wallet",             "eb_getwalletinfo",            &edcgetwalletinfo,            false },
    { "wallet",             "eb_importprivkey",            &edcimportprivkey,            true  },
    { "wallet",             "eb_importwallet",             &edcimportwallet,             true  },
    { "wallet",             "eb_importaddress",            &edcimportaddress,            true  },
    { "wallet",             "eb_importprunedfunds",        &edcimportprunedfunds,        true  },
    { "wallet",             "eb_importpubkey",             &edcimportpubkey,             true  },
    { "wallet",             "eb_keypoolrefill",            &edckeypoolrefill,            true  },
    { "equibit",            "eb_hsmkeypoolrefill",         &edchsmkeypoolrefill,         true  },
    { "wallet",             "eb_listaccounts",             &edclistaccounts,             false },
    { "wallet",             "eb_listaddressgroupings",     &edclistaddressgroupings,     false },
    { "wallet",             "eb_listlockunspent",          &edclistlockunspent,          false },
    { "wallet",             "eb_listreceivedbyaccount",    &edclistreceivedbyaccount,    false },
    { "wallet",             "eb_listreceivedbyaddress",    &edclistreceivedbyaddress,    false },
    { "wallet",             "eb_listsinceblock",           &edclistsinceblock,           false },
    { "wallet",             "eb_listtransactions",         &edclisttransactions,         false },
    { "wallet",             "eb_listunspent",              &edclistunspent,              false },
    { "wallet",             "eb_lockunspent",              &edclockunspent,              true  },
    { "wallet",             "eb_move",                     &edcmovecmd,                  false },
    { "wallet",             "eb_sendfrom",                 &edcsendfrom,                 false },
    { "wallet",             "eb_sendmany",                 &edcsendmany,                 false },
    { "wallet",             "eb_sendtoaddress",            &edcsendtoaddress,            false },
    { "wallet",             "eb_setaccount",               &edcsetaccount,               true  },
    { "wallet",             "eb_settxfee",                 &edcsettxfee,                 true  },
    { "wallet",             "eb_signmessage",              &edcsignmessage,              true  },
    { "wallet",             "eb_walletlock",               &edcwalletlock,               true  },
    { "wallet",             "eb_walletpassphrasechange",   &edcwalletpassphrasechange,   true  },
    { "wallet",             "eb_walletpassphrase",         &edcwalletpassphrase,         true  },
	{ "wallet",             "eb_trustedsend",              &edctrustedsend,              true  },
    { "wallet",             "eb_removeprunedfunds",        &edcremoveprunedfunds,        true  },
};

void edcRegisterWalletRPCCommands(CEDCRPCTable & t)
{
	EDCparams & params = EDCparams::singleton();
    if (params.disablewallet)
        return;

    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        t.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
