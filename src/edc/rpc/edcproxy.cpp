// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "univalue.h"
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "net.h"
#include "base58.h"
#include "validation.h"
#include "edc/message/edcmessage.h"


namespace
{

void packIDs(std::vector<unsigned char> & data, const CKeyID & addr, const CKeyID & paddr)
{
    data.resize(addr.size() + paddr.size());
    std::copy(addr.begin(), addr.end(), data.begin());
    std::copy(paddr.begin(), paddr.end(), data.begin() + addr.size());
}

void packIDs(
    std::vector<unsigned char> & data,
    const CKeyID & addr,
    const CKeyID & paddr,
    const CKeyID & iaddr)
{
    data.resize(addr.size() + paddr.size() + iaddr.size());
    std::copy(addr.begin(), addr.end(), data.begin());
    std::copy(paddr.begin(), paddr.end(), data.begin() + addr.size());
    std::copy(iaddr.begin(), iaddr.end(), data.begin() + addr.size() + paddr.size());
}

void pack(
    std::vector<unsigned char> & data,
    const CKeyID & addr,
    const CKeyID & paddr,
    const std::string & pollid)
{
    data.resize(addr.size() + paddr.size() + pollid.size() + 1);
    std::copy(addr.begin(), addr.end(), data.begin());
    std::copy(paddr.begin(), paddr.end(), data.begin() + addr.size());

    auto p = data.begin() + addr.size() + paddr.size();

    *p++ = static_cast<unsigned char>(pollid.size());

    auto i = pollid.begin();
    auto e = pollid.end();
    while (i != e)
        *p++ = *i++;
}

}

UniValue assigngeneralproxy(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "assigngeneralproxy \"address\" \"proxy-address\"\n"
            "\nAssign proxy voting privileges to specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "\nResult: ID of the general proxy\n"
            "\nExamples:\n"
            + HelpExampleCli("assigngeneralproxy", "\"139...301\" \"1xcc...adfv\"")
            + HelpExampleRpc("assigngeneralproxy", "\"139...301\", \"1vj4...adfv\"")
        );

    std::string addrStr = request.params[0].get_str();
    std::string paddrStr = request.params[1].get_str();

    CBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    CKeyID addrID;
    if (!addr.GetKeyID(addrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");
    CKeyID paddrID;
    if (!paddr.GetKeyID(paddrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    // Save data to wallet
    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->AddGeneralProxy(addrID, paddrID, errStr);
    }

    if (rc)
    {
        CBitcoinAddress sender(addrStr);
        CKeyID senderID;
        sender.GetKeyID(senderID);

        std::vector<unsigned char> data;
        packIDs(data, addrID, paddrID);

        CBroadcast * msg = CBroadcast::create(CGeneralProxy::tag, senderID, data);

        g_connman->RelayUserMessage(msg, true);

        UniValue result(msg->GetHash().ToString());
        return result;
    }
    else
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);
}

UniValue revokegeneralproxy(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "revokegeneralproxy \"address\" \"proxy-address\"\n"
            "\nRevoke proxy voting privileges from specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "\nResult: ID of the revoke\n"
            "\nExamples:\n"
            + HelpExampleCli("revokegeneralproxy", "\"139...301\" \"1xcc...adfv\"")
            + HelpExampleRpc("revokegeneralproxy", "\"139...301\", \"1vj4...adfv\"")
        );

    std::string addrStr = request.params[0].get_str();
    std::string paddrStr = request.params[1].get_str();

    CBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    CKeyID addrID;
    if (!addr.GetKeyID(addrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");
    CKeyID paddrID;
    if (!paddr.GetKeyID(paddrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    // Save data to wallet
    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->AddGeneralProxyRevoke(addrID, paddrID, errStr);
    }
    if (rc)
    {
        CBitcoinAddress sender(addrStr);
        CKeyID senderID;
        sender.GetKeyID(senderID);

        std::vector<unsigned char> data;
        packIDs(data, addrID, paddrID);

        CBroadcast * msg = CBroadcast::create(CRevokeGeneralProxy::tag, senderID, data);

        g_connman->RelayUserMessage(msg, true);

        UniValue result(msg->GetHash().ToString());
        return result;
    }
    else
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);
}

UniValue assignissuerproxy(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "assignissuerproxy \"address\" \"proxy-address\" \"Issuer-address\"\n"
            "\nAssign proxy privilege on all polls from specified issuer.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "3. \"issuer-address\" (string, required) The address of the issuer\n"
            "\nResult: ID of the proxy\n"
            "\nExamples:\n"
            + HelpExampleCli("assignissuerproxy", "\"139...301\" \"1xcc...adfv\"")
            + HelpExampleRpc("assignissuerproxy", "\"139...301\", \"1vj4...adfv\"")
        );

    std::string addrStr = request.params[0].get_str();
    std::string paddrStr = request.params[1].get_str();
    std::string iaddrStr = request.params[2].get_str();

    CBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    CKeyID addrID;
    if (!addr.GetKeyID(addrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");
    CKeyID paddrID;
    if (!paddr.GetKeyID(paddrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    CBitcoinAddress iaddr(iaddrStr);
    if (!iaddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    CKeyID iaddrID;
    if (!iaddr.GetKeyID(iaddrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    // Save data to wallet
    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->AddIssuerProxy(addrID, paddrID, iaddrID, errStr);
    }
    if (rc)
    {
        CBitcoinAddress sender(addrStr);
        CKeyID senderID;
        sender.GetKeyID(senderID);

        std::vector<unsigned char> data;
        packIDs(data, addrID, paddrID, iaddrID);

        CBroadcast * msg = CBroadcast::create(CIssuerProxy::tag, senderID, data);

        g_connman->RelayUserMessage(msg, true);

        UniValue result(msg->GetHash().ToString());
        return result;
    }
    else
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);
}

UniValue revokeissuerproxy(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "revokeissuerproxy \"address\" \"proxy-address\" \"Issuer-address\"\n"
            "\nRevoke proxy privilege on all polls from specified issuer.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "3. \"issuer-address\" (string, required) The address of the issuer\n"
            "\nResult: ID of the revoke\n"
            "\nExamples:\n"
            + HelpExampleCli("revokeissuerproxy", "\"139...301\" \"1xcc...adfv\"")
            + HelpExampleRpc("revokeissuerproxy", "\"139...301\", \"1vj4...adfv\"")
        );


    std::string addrStr = request.params[0].get_str();
    std::string paddrStr = request.params[1].get_str();
    std::string iaddrStr = request.params[2].get_str();

    CBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    CKeyID addrID;
    if (!addr.GetKeyID(addrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");
    CKeyID paddrID;
    if (!paddr.GetKeyID(paddrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    CBitcoinAddress iaddr(iaddrStr);
    if (!iaddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    CKeyID iaddrID;
    if (!iaddr.GetKeyID(iaddrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    // Save data to wallet
    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->AddIssuerProxyRevoke(addrID, paddrID, iaddrID, errStr);
    }
    if (rc)
    {
        CBitcoinAddress sender(addrStr);
        CKeyID senderID;
        sender.GetKeyID(senderID);

        std::vector<unsigned char> data;
        packIDs(data, addrID, paddrID, iaddrID);

        CBroadcast * msg = CBroadcast::create(CRevokeIssuerProxy::tag, senderID, data);

        g_connman->RelayUserMessage(msg, true);

        UniValue result(msg->GetHash().ToString());
        return result;
    }
    else
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);
}

UniValue assignpollproxy(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "assignpollproxy \"address\" \"proxy-address\" \"poll-ID\"\n"
            "\nAssign proxy privilege to specific poll.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "3. \"poll-ID\"        (string, required) ID of the poll\n"
            "\nResult: ID of the proxy\n"
            "\nExamples:\n"
            + HelpExampleCli("assignpollproxy", "\"139...301\" \"1xcc...adfv\"")
            + HelpExampleRpc("assignpollproxy", "\"139...301\", \"1vj4...adfv\"")
        );

    std::string addrStr = request.params[0].get_str();
    std::string paddrStr = request.params[1].get_str();
    std::string pollID = request.params[2].get_str();

    CBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    CKeyID addrID;
    if (!addr.GetKeyID(addrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");
    CKeyID paddrID;
    if (!paddr.GetKeyID(paddrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    // Save data to wallet
    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->AddPollProxy(addrID, paddrID, pollID, errStr);
    }
    if (rc)
    {
        CBitcoinAddress sender(addrStr);
        CKeyID senderID;
        sender.GetKeyID(senderID);

        std::vector<unsigned char> data;
        pack(data, addrID, paddrID, pollID);

        CBroadcast * msg = CBroadcast::create(CPollProxy::tag, senderID, data);

        g_connman->RelayUserMessage(msg, true);

        UniValue result(msg->GetHash().ToString());
        return result;
    }
    else
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);
}

UniValue revokepollproxy(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "revokepollproxy \"address\" \"proxy-address\" \"poll-ID\"\n"
            "\nRevoke proxying privilege for specific poll.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "3. \"poll-ID\"        (string, required) ID of the poll\n"
            "\nResult: ID of the revoke\n"
            "\nExamples:\n"
            + HelpExampleCli("revokepollproxy", "\"139...301\" \"1xcc...adfv\"")
            + HelpExampleRpc("revokepollproxy", "\"139...301\", \"1vj4...adfv\"")
        );


    std::string addrStr = request.params[0].get_str();
    std::string paddrStr = request.params[1].get_str();
    std::string pollID = request.params[2].get_str();

    CBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    CKeyID addrID;
    if (!addr.GetKeyID(addrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");
    CKeyID paddrID;
    if (!paddr.GetKeyID(paddrID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

    // Save data to wallet
    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->AddPollProxyRevoke(addrID, paddrID, pollID, errStr);
    }
    if (rc)
    {
        CBitcoinAddress sender(addrStr);
        CKeyID senderID;
        sender.GetKeyID(senderID);

        std::vector<unsigned char> data;
        pack(data, addrID, paddrID, pollID);

        CBroadcast * msg = CBroadcast::create(CRevokePollProxy::tag, senderID, data);

        g_connman->RelayUserMessage(msg, true);

        UniValue result(msg->GetHash().ToString());
        return result;
    }
    else
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);
}


namespace
{

const CRPCCommand Commands[] =
{ //  category        name                     actor (function)        okSafeMode
  //  --------------- ------------------------ ----------------------  ----------
    { "equibit",      "assigngeneralproxy", &assigngeneralproxy, true },
    { "equibit",      "revokegeneralproxy", &revokegeneralproxy, true },
    { "equibit",      "assignissuerproxy",  &assignissuerproxy,  true },
    { "equibit",      "revokeissuerproxy",  &revokeissuerproxy,  true },
    { "equibit",      "assignpollproxy",    &assignpollproxy,    true },
    { "equibit",      "revokepollproxy",    &revokepollproxy,    true },
};

}

void RegisterProxyRPCCommands(CRPCTable & tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(Commands); vcidx++)
        tableRPC.appendCommand(Commands[vcidx].name, &Commands[vcidx]);
}
