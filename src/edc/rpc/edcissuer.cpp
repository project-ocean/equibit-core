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
#include "edc/wallet/issuer.h"
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
    if (!EnsureWalletIsAvailable(request.fHelp)) return NullUniValue;

    if (request.fHelp || request.params.size() < 4)
        throw std::runtime_error(
            R"__(getnewissuer "name" "location" "phone_number" "email"

 Creates a new Issuer.

 Arguments:
 1. name            (string, required) The name of the Issuer.
 2. location        (string, required) The geographic address of the Issuer.
 3. phone_number    (string, required) The phone number of the Issuer.
 4. email           (string, required) The e-mail address of the Issuer.

 Result:
 The address associated with the Issuer.)__"
            + HelpExampleCli("getnewissuer", R"__("Equibit Issuer"  "100 University Ave, Toronto"  "416 233-4753"  "equibit-issuer.com")__")
            + HelpExampleRpc("getnewissuer", R"__("Equibit Issuer", "100 University Ave, Toronto", "416 233-4753", "equibit-issuer.com")__")
        );

    std::string name = request.params[0].get_str();
    std::string location = request.params[1].get_str();
    std::string phoneNumber = request.params[2].get_str();
    std::string emailAddr = request.params[3].get_str();

    CIssuer issuer(location, phoneNumber, emailAddr);

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsLocked()) pwalletMain->TopUpKeyPool();

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
            R"__(getissuers

 Lists all known Issuers.

 Result: (json object)
 [
   {
     "name":         name,           (string) name of the issuer
     "address":      address,        (string) Equibit address of the issuer
     "public_key":   public_key,     (string) public key of the issuer
     "location":     location,       (string) geographic address of the issuer
     "email":        email,          (string) e-mail address of the issuer
     "phone_number": phone_number,   (string) phone number of the issuer
   }, ...
 ])__"
            + HelpExampleCli("getissuers", "")
            + HelpExampleRpc("getissuers", "")
        );

    CWalletDB walletdb(pwalletMain->strWalletFile);

    std::vector<std::pair<std::string, CIssuer>> issuers;

    walletdb.ListIssuers(issuers);

    std::stringstream out;

    out << "[\n";

    bool first = true;

    for (auto &i : issuers)
    {
        const std::string & name = i.first;
        const CIssuer & issuer = i.second;

        if (!first) out << ",\n"; else first = false;

        CKeyID keyID = issuer.pubKey_.GetID();

        CBitcoinAddress address(keyID);

        out << "{"
            << "\"name\": \"" << name << "\""
            << ", \"address\":\"" << address.ToString() << "\""
            << ", \"public_key\":\"" << HexStr(issuer.pubKey_) << "\""
            << ", \"location\":\"" << issuer.location_ << "\""
            << ", \"email\":\"" << issuer.emailAddress_ << "\""
            << ", \"phone_number\":\"" << issuer.phoneNumber_ << "\""
            << "}";
    }
    out << "\n]";

    UniValue ret(UniValue::VSTR, out.str());

    return ret;
}

UniValue issue_equibits(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp)) return NullUniValue;

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
            R"__(issue_equibits "issuer" amount wot_min_level ("comment") (subtract_fee_from_amount)

 Authorizes or labels eqibits.

 Arguments:
 1. issuer                    (string,  required) The issuer that will be authorizing equibits.
 2. amount                    (numeric, required) The amount of equibits to authorize.
 3. issuing_payload           (string,  required) The issuing payload with a json containing an issuing information
 4. comment                   (string,  optional) A comment used to store what the transaction is for.
                                                  This is not part of the transaction, just kept in your wallet.
 5. subtract_fee_from_amount  (boolean, optional, default = false) The fee will be deducted from the amount being sent.
                                                  The recipient will receive less equibits than you enter in the amount field.
 Result:
 transactionid                (string) The id of the generated transaction.)__"
            + HelpExampleCli("authorizeequibit", R"__("ABC Comp"  1000  2  "comment"  true)__")
            + HelpExampleRpc("authorizeequibit", R"__("ABC Comp", 1000, 2, "comment", true)__")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::string iName = IssuerFromValue(request.params[0]);
    CAmount amount = AmountFromValue(request.params[1]);
    std::string payload = request.params[2].get_str();

    if (amount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for authorization");

    CWalletTx wtxNew;

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

    CIssuer issuer;
    if (!walletdb.ReadIssuer(iName, issuer))
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");

    CKeyID id = issuer.pubKey_.GetID();
    CTxDestination address = CBitcoinAddress(id).Get();

    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = { scriptPubKey, amount, fSubtractFeeFromAmount };

    vecSend.push_back(recipient);

    if (!pwalletMain->create_issuing_transaction(issuer, payload, vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError))
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

UniValue blank_equibits(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp)) return NullUniValue;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
            R"__(blankequibit "issuer" amount ("comment") (subtract_fee_from_amount) (fee_from_blank)
 Authorizes or labels equibits
 Arguments:
 1. issuer                    (string,  required) The issuer that will be authorizing equibits.
 2. amount                    (numeric, required) The amount of equibits to authorize.
 3. comment                   (string,  optional) A comment used to store what the transaction is for.
                                                  This is not part of the transaction, just kept in your wallet.\n"
 4. subtract_fee_from_amount  (boolean, optional, default = false) The fee will be deducted from the amount being sent.\n"
 5. fee_from_blank            (boolean, optional, default = true)  The fee is paid from blank equibits.\n"

 Result:
 transactionid                (string) The id of the generated transaction.)__"
            + HelpExampleCli("blankequibit", R"__("ABC Comp"  1000  "comment"  true  false)__")
            + HelpExampleRpc("blankequibit", R"__("ABC Comp", 1000, "comment", true, false)__")
        );
    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::string iName = IssuerFromValue(request.params[0]);
    CAmount amount = AmountFromValue(request.params[1]);

    if (amount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for authorization");

    CWalletTx wtxNew;

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

    CIssuer issuer;
    if (!walletdb.ReadIssuer(iName, issuer))
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");

    CKeyID id = issuer.pubKey_.GetID();
    CTxDestination address = CBitcoinAddress(id).Get();

    CScript scriptPubKey = GetScriptForDestination(address);

    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = { scriptPubKey, amount, fSubtractFeeFromAmount };

    vecSend.push_back(recipient);

    if (!pwalletMain->create_blanking_transaction(issuer, vecSend, wtxNew, reservekey, feeFromBlank, nFeeRequired, nChangePosRet, strError))
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
{
    { "equibit", "getnewissuer",     &getNewIssuer,      true, { "name", "location", "phone_number", "email" } },
    { "equibit", "getissuers",       &listIssuers,       true, {} },
    { "equibit", "issueequibits",    &issue_equibits,    true, { "issuer", "amount", "issuing_payload", "comment", "subtract_fee_from_amount" } },
    { "equibit", "blankequibits",    &blank_equibits,    true, { "issuer", "amount", "comment", "subtract_fee_from_amount", "fee_from_blank" } },
};

}

void RegisterIssuerRPCCommands(CRPCTable& tableRPC)
{
    for (size_t vcidx = 0; vcidx < std::extent<decltype(commands)>::value; vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
