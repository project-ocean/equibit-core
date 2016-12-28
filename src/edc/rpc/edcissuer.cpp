// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include "edc/rpc/edcserver.h"
#include "edc/wallet/edcwallet.h"
#include "edc/edcapp.h"
#include "edc/edcbase58.h"
#include "edc/edcmain.h"
#include "../utilstrencodings.h"
#include "wallet/wallet.h"
#include "utilmoneystr.h"
#ifdef	USE_HSM
#include "edc/edcparams.h"
#endif


bool edcEnsureWalletIsAvailable(bool avoidException);

namespace
{

std::string edcIssuerFromValue(const UniValue& value)
{
    std::string issuer = value.get_str();
    if ( issuer == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");
    return issuer;
}

UniValue getNewIssuer( const UniValue & params, bool fHelp )
{
	EDCapp & theApp = EDCapp::singleton();

	if (!edcEnsureWalletIsAvailable(fHelp))
	    return NullUniValue;

	if( fHelp || params.size() < 4 )
		throw std::runtime_error(
			"eb_getnewissuer \"name\" \"location\" \"phone-number\" \"e-mail address\"\n"
			"\nCreates a new Issuer.\n"
			"\nArguments:\n"
			"1. \"Name\"            (string,required) The name of the Issuer.\n"
			"2. \"Location\"        (string,required) The geographic address of the Issuer.\n"
			"3. \"Phone number\"    (string,required) The phone number of the Issuer.\n"
			"4. \"E-mail address\"  (string,required) The e-mail address of the Issuer.\n"
			"\nResult:\n"
			"The address associated with the Issuer.\n"
			+ HelpExampleCli( "eb_getnewissuer", "\"Equibit Issuer\" \"100 University Ave, Toronto\" \"416 233-4753\" \"equibit-issuer.com\"" )
			+ HelpExampleRpc( "eb_getnewissuer", "\"Equibit Issuer\" \"100 University Ave, Toronto\" \"416 233-4753\" \"equibit-issuer.com\"" )
		);

	std::string name       = params[0].get_str();
	std::string location   = params[1].get_str();
	std::string phoneNumber= params[2].get_str();
	std::string emailAddr  = params[3].get_str();

	CIssuer	issuer(location, phoneNumber, emailAddr);

	LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

	if (!theApp.walletMain()->IsLocked())
	    theApp.walletMain()->TopUpKeyPool();

	if (!theApp.walletMain()->GetKeyFromPool(issuer.pubKey_))
		throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call eb_keypoolrefill first");

	CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

	walletdb.WriteIssuer( name, issuer );

	UniValue ret(UniValue::VSTR);

	CKeyID keyID = issuer.pubKey_.GetID();

	theApp.walletMain()->SetAddressBook(keyID, name, "receive");

	ret = CEDCBitcoinAddress(issuer.pubKey_.GetID()).ToString();

	return ret;
}

UniValue getNewHSMIssuer( const UniValue & params, bool fHelp )
{
	EDCapp & theApp = EDCapp::singleton();

	if (!edcEnsureWalletIsAvailable(fHelp))
	    return NullUniValue;

	if( fHelp || params.size() < 4 )
		throw std::runtime_error(
			"eb_getnewhsmissuer \"name\" \"location\" \"phone-number\" \"e-mail address\"\n"
			"\nCreates a new Issuer with an HSM key pair.\n"
			"\nResult:\n"
			"The address associated with the Issuer.\n"
			"\nArguments:\n"
			"1. \"Name\"            (string,required) The name of the Issuer.\n"
			"2. \"Location\"        (string,required) The geographic address of the Issuer.\n"
			"3. \"Phone number\"    (string,required) The phone number of the Issuer.\n"
			"4. \"E-mail address\"  (string,required) The e-mail address of the Issuer.\n"
			+ HelpExampleCli( "eb_getnewhsmissuer", "\"Equibit Issuer\" \"100 University Ave, Toronto\" \"416 233-4753\" \"equibit-issuer.com\"" )
			+ HelpExampleRpc( "eb_getnewhsmissuer", "\"Equibit Issuer\" \"100 University Ave, Toronto\" \"416 233-4753\" \"equibit-issuer.com\"" )
		);

#ifdef USE_HSM
	EDCparams & theParams = EDCparams::singleton();

	if( theParams.usehsm )
	{
		std::string name       = params[0].get_str();
		std::string location   = params[1].get_str();
		std::string phoneNumber= params[2].get_str();
		std::string emailAddr  = params[3].get_str();

		CIssuer	issuer(location, phoneNumber, emailAddr);

		LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

		if (!theApp.walletMain()->IsLocked())
		    theApp.walletMain()->TopUpHSMKeyPool();

		if (!theApp.walletMain()->GetHSMKeyFromPool(issuer.pubKey_))
			throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call eb_hsmkeypoolrefill first");

		CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

		walletdb.WriteIssuer( name, issuer );

		UniValue ret(UniValue::VSTR);

		CKeyID keyID = issuer.pubKey_.GetID();

		theApp.walletMain()->SetAddressBook(keyID, name, "receive");

		ret = CEDCBitcoinAddress(issuer.pubKey_.GetID()).ToString();

		return ret;
	}
	else
		throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM processing disabled. "
			"Use -eb_usehsm command line option to enable HSM processing" );
#else
	throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: HSM support is not included in the build");
#endif
}

UniValue listIssuers( const UniValue & params, bool fHelp )
{
	EDCapp & theApp = EDCapp::singleton();

	if( fHelp )
		throw std::runtime_error(
			"eb_getissuers\n"
			"\nLists all known Issuers.\n"
			"\nResult:\n"
			"[                                 (json object)\n"
			"  {                               (json object)\n"
			"    \"name\": name,               (string) name of the issuer\n"
			"    \"address\": address,         (string) equibit address of the issuer\n"
			"    \"pubKey\": pubkey,           (string) public key of the issuer\n"
			"    \"location\": location,       (string) geographic address of the issuer\n"
			"    \"e-mail\": e-mail-address,   (string) e-mail address of the issuer\n"
			"    \"phone\": phone-number,      (string) phone number of the issuer\n"
			"  }, ...\n"
			"]\n"
			+ HelpExampleCli( "eb_getissuers", "" )
			+ HelpExampleRpc( "eb_getissuers", "" )
		);

	CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

	std::vector<std::pair<std::string,CIssuer>>	issuers;
	walletdb.ListIssuers( issuers );

	std::vector<std::pair<std::string, CIssuer>>::iterator i = issuers.begin();
	std::vector<std::pair<std::string, CIssuer>>::iterator e = issuers.end();
	
	std::stringstream out;
	out << "[\n";

	bool first = true;
	while( i != e )
	{
		const std::string & name = i->first;
		const CIssuer & issuer = i->second;

		if(!first)
			out << ",\n";
		else
			first = false;

		CKeyID keyID = issuer.pubKey_.GetID();
		CEDCBitcoinAddress address(keyID);

		out << "  {"
            << "\"name\": \"" << name << "\""
			<< ", \"address\":\"" << address.ToString() << "\""
			<< ", \"pubKey\":\"" << HexStr(issuer.pubKey_) << "\""
            << ", \"location\":\"" << issuer.location_ << "\""
            << ", \"email\":\"" << issuer.emailAddress_ << "\""
            << ", \"phone_number\":\"" << issuer.phoneNumber_ << "\""
		    << "}";

		++i;
	}
	out << "\n]";

	UniValue ret(UniValue::VSTR, out.str());

	return ret;
}

UniValue authorizeEquibit( const UniValue & params, bool fHelp )
{
	EDCapp & theApp = EDCapp::singleton();

	if (!edcEnsureWalletIsAvailable(fHelp))
	    return NullUniValue;

	if( fHelp || params.size() < 3 || params.size() > 5 )
		throw std::runtime_error(
			"eb_authorizeequibit \"issuer\" amount wot-min-lvl ( \"comment\" subtractfeefromamount )\n"
			"\nAuthorizes (or labels) an eqibit.\n"
			"\nArguments:\n"
			"1. \"Issuer\"          (string,required) The issuer that will be authorizing the Equibit.\n"
			"2. amount              (numeric,required) The amount of coins to authorize.\n"
			"3. wot-min-lvl         (numeric,required) The minimum WoT level used when TXN is moved.\n"
            "4. \"comment\"         (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less equibits than you enter in the amount field.\n"



	        "\nResult:\n"
	        "\"transactionid\"        (string) The id of the generated transaction.\n"

			+ HelpExampleCli( "eb_authorizeequibit", "\"ABC Comp\" 1000 2" )
			+ HelpExampleRpc( "eb_authorizeequibit", "\"ABC Comp\", 1000, 2" )
		);

	LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

	std::string iName  = edcIssuerFromValue(params[0]);
	CAmount 	amount = AmountFromValue(params[1]);
	unsigned	WoTlvl = params[2].get_int();

    if (amount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for authorization");

	CEDCWalletTx wtxNew;

    // Wallet comments
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtxNew.mapValue["comment"] = params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (params.size() > 4)
        fSubtractFeeFromAmount = params[4].get_bool();

	edcEnsureWalletIsUnlocked();

   	CAmount curBalance = theApp.walletMain()->GetBalance();

    if (amount > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (theApp.walletMain()->GetBroadcastTransactions() && !theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

	CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

	// Get issuer address
	CIssuer issuer;
	if( !walletdb.ReadIssuer( iName, issuer ) )
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");
		
	CKeyID id = issuer.pubKey_.GetID();
	CTxDestination address = CEDCBitcoinAddress(id).Get();

    // Parse Equibit address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CEDCReserveKey reservekey(theApp.walletMain());
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, amount, fSubtractFeeFromAmount};

    vecSend.push_back(recipient);

    if (!theApp.walletMain()->CreateAuthorizingTransaction( issuer, WoTlvl, 
	vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError))
    {
        if (amount > theApp.walletMain()->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    if (!theApp.walletMain()->CommitTransaction(wtxNew, reservekey, theApp.connman().get()))
        throw JSONRPCError(RPC_WALLET_ERROR,
			"Error: The transaction was rejected! This might happen if some of the "
			"coins in your wallet were already spent, such as if you used a copy of "
			"the wallet and coins were spent in the copy but not marked as spent here.");

	return wtxNew.GetHash().GetHex();
}

UniValue blankEquibit( const UniValue & params, bool fHelp )
{
	EDCapp & theApp = EDCapp::singleton();

	if (!edcEnsureWalletIsAvailable(fHelp))
	    return NullUniValue;

	if( fHelp || params.size() < 2 || params.size() > 5)
		throw std::runtime_error(
			"eb_blankequibit \"issuer\" amount ( \"comment\" subtractfeefromamt feefromblank )\n"
			"\nAuthorizes (or labels) an eqibit.\n"
			"\nArguments:\n"
			"1. \"Issuer\"          (string,required) The issuer that will be authorizing the Equibit.\n"
			"2. amount              (numeric,required) The amount of coins to authorize.\n"
            "3. \"comment\"         (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "                             transaction, just kept in your wallet.\n"
            "4. subtractfeefromamt  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "5. feefromblank        (boolean, optional, default=true) The fee is paid from blank equitbits.\n"
	        "\nResult:\n"
	        "\"transactionid\"      (string) The id of the generated transaction.\n"

			+ HelpExampleCli( "eb_blankequibit", "\"ABC Comp\" 1000" )
			+ HelpExampleRpc( "eb_blankequibit", "\"ABC Comp\", 1000" )
		);
	LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

	std::string iName  = edcIssuerFromValue(params[0]);
	CAmount 	amount = AmountFromValue(params[1]);

    if (amount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for authorization");

	CEDCWalletTx wtxNew;

    // Wallet comments
    if (params.size() > 2 && !params[2].isNull() && !params[2].get_str().empty())
        wtxNew.mapValue["comment"] = params[2].get_str();

    bool fSubtractFeeFromAmount = false;
    if (params.size() > 3)
        fSubtractFeeFromAmount = params[3].get_bool();

    bool feeFromBlank = true;
    if (params.size() > 4)
        feeFromBlank = params[4].get_bool();

	edcEnsureWalletIsUnlocked();

   	CAmount curBalance = theApp.walletMain()->GetBalance();

    if (amount > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (theApp.walletMain()->GetBroadcastTransactions() && !theApp.connman())
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

	CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

	// Get issuer address
	CIssuer issuer;
	if( !walletdb.ReadIssuer( iName, issuer ) )
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");
		
	CKeyID id = issuer.pubKey_.GetID();
	CTxDestination address = CEDCBitcoinAddress(id).Get();

    // Parse Equibit address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CEDCReserveKey reservekey(theApp.walletMain());
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, amount, fSubtractFeeFromAmount};

    vecSend.push_back(recipient);

    if (!theApp.walletMain()->CreateBlankingTransaction( issuer, vecSend, wtxNew, reservekey, 
	feeFromBlank, nFeeRequired, nChangePosRet, strError))
    {
        if (amount > theApp.walletMain()->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    if (!theApp.walletMain()->CommitTransaction(wtxNew, reservekey, theApp.connman().get()))
        throw JSONRPCError(RPC_WALLET_ERROR,
			"Error: The transaction was rejected! This might happen if some of the "
			"coins in your wallet were already spent, such as if you used a copy of "
			"the wallet and coins were spent in the copy but not marked as spent here.");

	return wtxNew.GetHash().GetHex();
}

const CRPCCommand commands[] =
{ // category   name                actor (function)   okSafeMode
  // ---------- ------------------- ------------------ -------------

	{ "equibit", "eb_getnewissuer",		 &getNewIssuer,      true },
	{ "equibit", "eb_getnewhsmissuer",	 &getNewHSMIssuer,   true },
	{ "equibit", "eb_getissuers",		 &listIssuers,       true },
	{ "equibit", "eb_authorizeequibit",  &authorizeEquibit,  true },
	{ "equibit", "eb_blankequibit",      &blankEquibit,      true },
};

}

void edcRegisterIssuerRPCCommands( CEDCRPCTable & edcTableRPC)
{
	for( unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++ )
		edcTableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
