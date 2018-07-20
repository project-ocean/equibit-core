// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "base58.h"
#include "validation.h"
#include "consensus/validation.h"
#include "net.h"
#include "../utilstrencodings.h"
#include "wallet/wallet.h"
#include "utilmoneystr.h"


bool EnsureWalletIsAvailable(bool avoidException);

namespace
{

std::string IssuerFromValue(const UniValue& value)
{
    std::string issuer = value.get_str();
    if (issuer == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");
    return issuer;
}

UniValue getNewIssuer(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 4)
        throw std::runtime_error(
            "getnewissuer \"name\" \"location\" \"phone-number\" \"e-mail address\"\n"
            "\nCreates a new Issuer.\n"
            "\nArguments:\n"
            "1. \"Name\"            (string,required) The name of the Issuer.\n"
            "2. \"Location\"        (string,required) The geographic address of the Issuer.\n"
            "3. \"Phone number\"    (string,required) The phone number of the Issuer.\n"
            "4. \"E-mail address\"  (string,required) The e-mail address of the Issuer.\n"
            "\nResult:\n"
            "The address associated with the Issuer.\n"
            + HelpExampleCli("getnewissuer", "\"Equibit Issuer\" \"100 University Ave, Toronto\" \"416 233-4753\" \"equibit-issuer.com\"")
            + HelpExampleRpc("getnewissuer", "\"Equibit Issuer\" \"100 University Ave, Toronto\" \"416 233-4753\" \"equibit-issuer.com\"")
        );

    std::string name = request.params[0].get_str();
    std::string location = request.params[1].get_str();
    std::string phoneNumber = request.params[2].get_str();
    std::string emailAddr = request.params[3].get_str();

    CIssuer	issuer(location, phoneNumber, emailAddr);

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    if (!pwalletMain->GetKeyFromPool(issuer.pubKey_))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    CWalletDB walletdb(pwalletMain->strWalletFile);

    walletdb.WriteIssuer(name, issuer);

    UniValue ret(UniValue::VSTR);

    CKeyID keyID = issuer.pubKey_.GetID();

    pwalletMain->SetAddressBook(keyID, name, "receive");

    ret = CBitcoinAddress(issuer.pubKey_.GetID()).ToString();

    return ret;
}

UniValue listIssuers(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            "getissuers\n"
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
            + HelpExampleCli("getissuers", "")
            + HelpExampleRpc("getissuers", "")
        );

    CWalletDB walletdb(pwalletMain->strWalletFile);

    std::vector<std::pair<std::string, CIssuer>>	issuers;
    walletdb.ListIssuers(issuers);

    std::vector<std::pair<std::string, CIssuer>>::iterator i = issuers.begin();
    std::vector<std::pair<std::string, CIssuer>>::iterator e = issuers.end();

    std::stringstream out;
    out << "[\n";

    bool first = true;
    while (i != e)
    {
        const std::string & name = i->first;
        const CIssuer & issuer = i->second;

        if (!first)
            out << ",\n";
        else
            first = false;

        CKeyID keyID = issuer.pubKey_.GetID();
        CBitcoinAddress address(keyID);

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

UniValue authorizeEquibit(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
            "authorizeequibit \"issuer\" amount wot-min-lvl ( \"comment\" subtractfeefromamount )\n"
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

            + HelpExampleCli("authorizeequibit", "\"ABC Comp\" 1000 2")
            + HelpExampleRpc("authorizeequibit", "\"ABC Comp\", 1000, 2")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::string iName = IssuerFromValue(request.params[0]);
    CAmount 	amount = AmountFromValue(request.params[1]);
    unsigned	WoTlvl = request.params[2].get_int();

    if (amount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for authorization");

    CWalletTx wtxNew;

    // Wallet comments
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtxNew.mapValue["comment"] = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (request.params.size() > 4)
        fSubtractFeeFromAmount = request.params[4].get_bool();

    EnsureWalletIsUnlocked();

    CAmount curBalance = pwalletMain->GetBalance();

    if (amount > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (pwalletMain->GetBroadcastTransactions() && !g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    CWalletDB walletdb(pwalletMain->strWalletFile);

    // Get issuer address
    CIssuer issuer;
    if (!walletdb.ReadIssuer(iName, issuer))
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");

    CKeyID id = issuer.pubKey_.GetID();
    CTxDestination address = CBitcoinAddress(id).Get();

    // Parse Equibit address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = { scriptPubKey, amount, fSubtractFeeFromAmount };

    vecSend.push_back(recipient);

    if (!pwalletMain->CreateAuthorizingTransaction(issuer, WoTlvl,
                                                   vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError))
    {
        if (amount > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    CValidationState state;
    if (!pwalletMain->CommitTransaction(wtxNew, reservekey, g_connman.get(), state))
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: The transaction was rejected! This might happen if some of the "
                           "coins in your wallet were already spent, such as if you used a copy of "
                           "the wallet and coins were spent in the copy but not marked as spent here.");

    return wtxNew.GetHash().GetHex();
}

UniValue blankEquibit(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
            "blankequibit \"issuer\" amount ( \"comment\" subtractfeefromamt feefromblank )\n"
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

            + HelpExampleCli("blankequibit", "\"ABC Comp\" 1000")
            + HelpExampleRpc("blankequibit", "\"ABC Comp\", 1000")
        );
    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::string iName = IssuerFromValue(request.params[0]);
    CAmount 	amount = AmountFromValue(request.params[1]);

    if (amount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for authorization");

    CWalletTx wtxNew;

    // Wallet comments
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty())
        wtxNew.mapValue["comment"] = request.params[2].get_str();

    bool fSubtractFeeFromAmount = false;
    if (request.params.size() > 3)
        fSubtractFeeFromAmount = request.params[3].get_bool();

    bool feeFromBlank = true;
    if (request.params.size() > 4)
        feeFromBlank = request.params[4].get_bool();

    EnsureWalletIsUnlocked();

    CAmount curBalance = pwalletMain->GetBalance();

    if (amount > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (pwalletMain->GetBroadcastTransactions() && !g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    CWalletDB walletdb(pwalletMain->strWalletFile);

    // Get issuer address
    CIssuer issuer;
    if (!walletdb.ReadIssuer(iName, issuer))
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");

    CKeyID id = issuer.pubKey_.GetID();
    CTxDestination address = CBitcoinAddress(id).Get();

    // Parse Equibit address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = { scriptPubKey, amount, fSubtractFeeFromAmount };

    vecSend.push_back(recipient);

    if (!pwalletMain->CreateBlankingTransaction(issuer, vecSend, wtxNew, reservekey,
                                                feeFromBlank, nFeeRequired, nChangePosRet, strError))
    {
        if (amount > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    CValidationState state;
    if (!pwalletMain->CommitTransaction(wtxNew, reservekey, g_connman.get(), state))
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: The transaction was rejected! This might happen if some of the "
                           "coins in your wallet were already spent, such as if you used a copy of "
                           "the wallet and coins were spent in the copy but not marked as spent here.");

    return wtxNew.GetHash().GetHex();
}

const CRPCCommand commands[] =
{ // category   name                actor (function)   okSafeMode
  // ---------- ------------------- ------------------ -------------

    { "equibit", "getnewissuer",		 &getNewIssuer,      true },
    { "equibit", "getissuers",		 &listIssuers,       true },
    { "equibit", "authorizeequibit",  &authorizeEquibit,  true },
    { "equibit", "blankequibit",      &blankEquibit,      true },
};

}

void RegisterIssuerRPCCommands(CRPCTable & tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
