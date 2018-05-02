// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include <vector>
#include "rpc/server.h"
#include "utilstrencodings.h"
#include "edc/message/edcmessage.h"
#include "net.h"
#include "base58.h"
#include "wallet/wallet.h"


namespace
{
UniValue broadcastMessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "broadcastmessage \"type\" \"send-address\" \"message\"\n"
            "\nBroadcasts a message to all equibit nodes on the network.\n"
            "\nReturns the hash of the message.\n"
            "\nArguments:\n"
            "1. \"type\" (string, required) Type of message. Type must be one of:\n"
            "      Acquisition\n"
            "      Ask\n"
            "      Assimilation\n"
            "      Bankruptcy\n"
            "      Bid\n"
            "      BonusIssue\n"
            "      BonusRights\n"
            "      BuyBackProgram\n"
            "      CashDividend\n"
            "      CashStockOption\n"
            "      ClassAction\n"
            "      ConversionOfConvertibleBonds\n"
            "      CouponPayment\n"
            "      Delisting\n"
            "      DeMerger\n"
            "      DividendReinvestmentPlan\n"
            "      DutchAuction\n"
            "      EarlyRedemption\n"
            "      FinalRedemption\n"
            "      GeneralAnnouncement\n"
            "      InitialPublicOffering\n"
            "      Liquidation\n"
            "      Lottery\n"
            "      MandatoryExchange\n"
            "      Merger\n"
            "      MergerWithElections\n"
            "      NameChange\n"
            "      OddLotTender\n"
            "      OptionalPut\n"
            "      OtherEvent\n"
            "      PartialRedemption\n"
            "      ParValueChange\n"
            "      ReturnOfCapital\n"
            "      ReverseStockSplit\n"
            "      RightsAuction\n"
            "      RightsIssue\n"
            "      SchemeofArrangement\n"
            "      ScripDividend\n"
            "      ScripIssue\n"
            "      Spinoff\n"
            "      SpinOffWithElections\n"
            "      StockDividend\n"
            "      StockSplit\n"
            "      SubscriptionOffer\n"
            "      Takeover\n"
            "      TenderOffer\n"
            "      VoluntaryExchange\n"
            "      WarrantExercise\n"
            "      WarrantExpiry\n"
            "      WarrantIssue\n"
            "2. \"send-address\"   (string, required) The sender address\n"
            "3. \"message\"  (string, required) The message to be sent to the all addresses\n"
            "\nResult:: fqe43143q....3fsfbs\n"
            + HelpExampleCli("broadcastmessage", "ACME StockDividend \"A dividend of 0.032 equibits will be issued on March 15th\"")
            + HelpExampleRpc("broadcastmessage", "ACME StockDividend \"A dividend of 0.032 equibits will be issued on March 15th\"")
        );

    std::string	type = request.params[0].get_str();

    CBitcoinAddress sender(request.params[1].get_str());

    if (!sender.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID senderID;

    if (!sender.GetKeyID(senderID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    std::string	data = request.params[2].get_str();

    CBroadcast * msg = CBroadcast::create(type, senderID, data);

    g_connman->RelayUserMessage(msg, false);

    UniValue hash(msg->GetHash().ToString());

    return hash;
}

UniValue multicastMessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "multicastmessage \"type\" \"send-address\" \"asset\" \"message\"\n"
            "\nMulti-casts a message to all owners of an equibit asset.\n"
            "\nReturns the hash of the message.\n"
            "\nArguments:\n"
            "1. \"type\" (string,required) Type of message. Type must be one of:\n"
            "        AssetPrivate\n"
            "2. \"issuer-address\"   (string,required) The issuer address\n"
            "3. \"message\"  (string,required) The message to be sent to the multiple addresses\n"
            "\nResult:: fqe43143q....3fsfbs\n"
            + HelpExampleCli("multicastmessage", "ACME Poll \"Board of directors Vote. Choose 1 for John Smith, 2 for Doug Brown\"")
            + HelpExampleRpc("multicastmessage", "ACME Poll \"Board of directors Vote. Choose 1 for John Smith, 2 for Doug Brown\"")
        );

    std::string	type = request.params[0].get_str();

    if (type != "AssetPrivate")
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid message type specified");

    CBitcoinAddress sender(request.params[1].get_str());

    if (!sender.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID senderID;

    if (!sender.GetKeyID(senderID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    std::string	data = request.params[2].get_str();

    CMulticast* msg = CMulticast::create(type, senderID, data);

    g_connman->RelayUserMessage(msg, true);

    UniValue hash(msg->GetHash().ToString());

    return hash;
}

UniValue p2pmessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4)
        throw std::runtime_error(
            "p2pmessage \"type\" \"send-address\" \"recv-address\" \"message\"\n"
            "\nSends a peer-to-peer message.\n"
            "\nReturns the hash of the message.\n"
            "\nArguments:\n"
            "1. \"type\" (string,required) Type of message. Type must be one of:\n"
            "        Private\n"
            "2. \"send-address\"   (string,required) The sender address\n"
            "3. \"recv-address\"   (string,required) The receiver address\n"
            "4. \"message\"   (string,required) The message to be sent to the specified address\n"
            "\nResult:: fqe43143q....3fsfbs\n"
            + HelpExampleCli("p2pmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" Private "
                             "\"What is your position WRT the upcomming merger?\"")
            + HelpExampleRpc("p2pmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" Vote 1")
        );

    std::string	type = request.params[0].get_str();

    if (type != "Private")
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid message type specified");

    CBitcoinAddress sender(request.params[1].get_str());

    if (!sender.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID senderID;

    if (!sender.GetKeyID(senderID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid sender address");

    CBitcoinAddress receiver(request.params[2].get_str());
    CKeyID receiverID;

    if (!receiver.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid receiver address");

    if (!receiver.GetKeyID(receiverID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid receiver address");

    std::string data = request.params[3].get_str();

    CPeerToPeer* msg = CPeerToPeer::create(type, senderID, receiverID, data);

    g_connman->RelayUserMessage(msg, true);

    UniValue hash(msg->GetHash().ToString());

    return hash;
}

inline int D(char c) { return c - '0'; }

bool getTime(const std::string& param, time_t& t)
{
    for (size_t i = 0; i < param.size(); ++i)
    {
        // Find the first number.
        if (isdigit(param[i]))
        {
            const char* cp = param.c_str() + i;

            // The required syntax is:
            // YYYY-MM-DD[:HH:mm:SS]
            if (isdigit(cp[0]) && isdigit(cp[1]) && isdigit(cp[2]) && isdigit(cp[3]) &&
                isdigit(cp[5]) && isdigit(cp[6]) &&
                isdigit(cp[8]) && isdigit(cp[9]))
            {
                int yr = D(cp[0]) * 1000 + D(cp[1]) * 100 + D(cp[2]) * 10 + D(cp[3]);
                int mn = D(cp[5]) * 10 + D(cp[6]);
                int dy = D(cp[8]) * 10 + D(cp[9]);

                int h;
                int m;
                int s;

                if (isdigit(cp[11]) && isdigit(cp[12]) &&
                    isdigit(cp[14]) && isdigit(cp[15]) &&
                    isdigit(cp[17]) && isdigit(cp[18]))
                {
                    h = D(cp[11]) * 10 + D(cp[12]);
                    m = D(cp[14]) * 10 + D(cp[15]);
                    s = D(cp[17]) * 10 + D(cp[18]);
                }
                else
                {
                    h = 0;
                    m = 0;
                    s = 0;
                }

                struct tm tm;
                tm.tm_year = yr - 1900;
                tm.tm_mon = mn - 1;
                tm.tm_mday = dy;
                tm.tm_hour = h;
                tm.tm_min = m;
                tm.tm_sec = s;

                t = mktime(&tm);

                return true;
            }
        }
    }

    return false;
}

inline std::string trim(const std::string& s)
{
    auto wsfront = std::find_if_not(s.begin(), s.end(), [](int c) { return std::isspace(c); });
    auto wsback = std::find_if_not(s.rbegin(), s.rend(), [](int c) { return std::isspace(c); }).base();
    return (wsback <= wsfront ? std::string() : std::string(wsfront, wsback));
}

// Expected input syntax:
// (name1,name2,...)
bool getSet(const std::string & param, std::set<std::string> & l)
{
    size_t bPos = param.find("(");
    size_t ePos = param.find(")");

    if (bPos == std::string::npos || ePos == std::string::npos) return false;

    std::string inner = param.substr(bPos + 1, ePos - bPos - 1);

    while (true)
    {
        size_t cPos = inner.find(",");

        // last one
        if (cPos == std::string::npos)
        {
            if (inner.size() > 0) l.insert(trim(inner));

            break;
        }
        else if (cPos > 0)
        {
            // ... , ...
            std::string p = trim(inner.substr(0, cPos));

            l.insert(p);

            inner = inner.substr(cPos + 1);
        }
        else //,...
        {
            inner = inner.substr(1);
        }
    }

    return true;
}

void getParamValues(
    const UniValue& params,          // IN
    time_t& from,                    // OUT
    time_t& to,                      // OUT
    std::set<std::string>& assets,   // OUT
    std::set<std::string>& types,    // OUT
    std::set<std::string>& senders,  // OUT
    std::set<std::string>& receivers // OUT
)
{
    for (size_t i = 0; i < params.size(); ++i)
    {
        std::string param = params[i].get_str();

        bool rc = false;

        if (param.substr(0, 4) == "from")
        {
            rc = getTime(param.substr(4), from);
        }
        else if (param.substr(0, 2) == "to")
        {
            rc = getTime(param.substr(2), to);
        }
        else if (param.substr(0, 5) == "asset")
        {
            rc = getSet(param.substr(5), assets);
        }
        else if (param.substr(0, 4) == "type")
        {
            rc = getSet(param.substr(4), types);
        }
        else if (param.substr(0, 6) == "sender")
        {
            rc = getSet(param.substr(6), senders);
        }
        else if (param.substr(0, 8) == "receiver")
        {
            rc = getSet(param.substr(8), receivers);
        }

        if (!rc)
        {
            std::string msg = "Unrecognized parameter [";
            msg += param;
            msg += "]";

            throw std::runtime_error(msg);
        }
    }
}

UniValue getMessages(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            "getmessages ( \"from(date[:time])\" \"to(date[:time])\" \"type(name[,...])\" \"asset(name[,...])\" \"sender(hash[,...])\" \"receiver(hash[,...])\" )\n"
            "\nGets all messages whose attributes match the specified filtering conditions.\n"
            "\nArguments:\n"
            "\nAll arguments are optional and can be specified in any order. The date format is of the form YYYY-MM-DD.\n"
            "The optional time format is of the form HH:MM:SS.\n"
            "\n1. from(date[:time]) (string,optional) Filters messages whose time stamp is less than the specified date/time.\n"
            "2. to(date[:time]) (string,optional) Filters messages whose time stamp is greater than the specified date/time.\n"
            "3. type(name[,...]) (string,optional) Filters messages which have the specified types.\n"
            "4. asset(name[,..]) (string,optional) Filters messages which are not associated with the specified assets. This filter has no\n"
            "effect on peer-to-peer messages.\n"
            "5. sender(hash[,...]) (string,optional) Filters messages which are sent by the specified senders.\n"
            "6. receiver(hash[,...]) (string,optional) Filters peer-to-peer messages which are sent to the specified receivers.\n"
            "\nResult:"
            "\n["
            "\n  {"
            "\n    \"type\":\"Poll\","
            "\n    \"hash\":\"ced192a...ced192ad\","
            "\n    \"sender\":\"ab320ac...2098aced\","
            "\n    \"timestamp\":\"2016-09-13:12:20:02\","
            "\n    \"nonce\":121344792,"
            "\n    \"data\":\"Vote for board member positions\","
            "\n    \"signature\":\"c03deb50...2498ade\","
            "\n    \"asset\":\"ACME Co.\""
            "\n  },"
            "\n  {"
            "\n    \"type\":\"Poll\","
            "\n    \"hash\":\"4ad192a...ce4a92ad\","
            "\n    \"sender\":\"ab320ac...2098aced\","
            "\n    \"timestamp\":\"2016-09-13:12:20:02\","
            "\n    \"nonce\":121344792,"
            "\n    \"data\":\"Vote for board member positions\","
            "\n    \"signature\":\"c03deb50...2498ade\","
            "\n    \"receiver\":\"432b0...d0e029ae\""
            "\n  },"
            "\n  ..."
            "\n]\n"
            + HelpExampleCli("getmessages", "\"from(2016-01-01:10:10:10)\" \"asset(ACME,MSXY)\"")
            + HelpExampleRpc("getmessages", "\"from(2016-02-01)\", \"asset(ACME,MSYZ)\"")
        );

    time_t from = 0;
    time_t to = 0;

    std::set<std::string> assets;
    std::set<std::string> types;
    std::set<std::string> senders;
    std::set<std::string> receivers;

    getParamValues(request.params, from, to, assets, types, senders, receivers);

    UniValue result(UniValue::VSTR);
    std::vector<CUserMessage*> messages;

    pwalletMain->GetMessages(from, to, assets, types, senders, receivers, messages);

    std::string json = "[";

    std::vector<CUserMessage *>::iterator i = messages.begin();
    std::vector<CUserMessage *>::iterator e = messages.end();

    bool first = true;

    while (i != e)
    {
        if (!first) json += ","; else first = false;
        json += (*i)->ToJSON();

        ++i;
    }

    json += "]";
    result.setStr(json);

    return result;
}

UniValue getMessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getmessage \"hash\"\n"
            "\nGets the message with the specified hash value.\n"
            "\nArguments:\n"
            "\n1. hash (string,required) the hash of the message to be loaded\n"
            "\nResult: (for Broadcast and Multicast messages)"
            "\n{"
            "\n  \"type\":\"Poll\","
            "\n  \"hash\":\"4ad192a...ce4a92ad\","
            "\n  \"sender\":\"ab320ac...2098aced\","
            "\n  \"timestamp\":\"2016-09-13:12:20:02\","
            "\n  \"nonce\":121344792,"
            "\n  \"data\":\"Vote for board member positions\","
            "\n  \"signature\":\"c03deb50...2498ade\","
            "\n  \"asset\":\"ACME Co.\""
            "\n}"
            "\nResult: (for Peer-to-Peer messages)"
            "\n{"
            "\n  \"type\":\"Poll\","
            "\n  \"hash\":\"4ad1efa...ce4a9efd\","
            "\n  \"sender\":\"ab320ac...2098aced\","
            "\n  \"timestamp\":\"2016-09-13:12:20:02\","
            "\n  \"nonce\":121344792,"
            "\n  \"data\":\"Vote for board member positions\","
            "\n  \"signature\":\"c03deb50...2498ade\","
            "\n  \"receiver\":\"432b0...d0e029ae\""
            "\n}\n"
            + HelpExampleCli("getmessage", "\"c1c1d256...0983fed\"")
            + HelpExampleRpc("getmessage", "\"70292cde...a890192\"")
        );

    uint256 hash = uint256S(request.params[0].get_str());

    UniValue obj(UniValue::VSTR);
    CUserMessage* message;

    pwalletMain->GetMessage(hash, message);

    if (message)
    {
        obj.setStr(message->ToJSON());
        delete message;
    }

    return obj;
}

UniValue deleteMessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "deletemessage \"hash\"\n"
            "\nDeletes the message with the specified hash value.\n"
            "\nArguments:\n"
            "\n1. hash (string,required) the hash of the message to be deleted\n"
            + HelpExampleCli("deletemessage", "\"c1c1d256...0983fed\"")
            + HelpExampleRpc("deletemessage", "\"70292cde...a890192\"")
        );

    uint256 hash = uint256S(request.params[0].get_str());

    pwalletMain->DeleteMessage(hash);

    return NullUniValue;
}

UniValue deleteMessages(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            "deletemessages ( \"from(date[:time])\" \"to(date[:time])\" \"type(name[,...])\" \"asset(name[,...])\" \"sender(hash[,...])\" \"receiver(hash[,...])\" )\n"
            "\nDeletes the messages whose attributes match the specified conditions.\n"
            "\nArguments:\n"
            "\nAll arguments are optional and can be specified in any order. The date format is of the form YYYY-MM-DD.\n"
            "The optional time format is of the form HH:MM:SS.\n"
            "\n1. from(date[:time]) (string,optional) Deletes messages whose time stamp is greater than or equal to the specified date/time.\n"
            "2. to(date[:time]) (string,optional) Deletes messages whose time stamp is less than the specified date/time.\n"
            "3. type(name[,...]) (string,optional) Deletes messages which have the specified types.\n"
            "4. asset(name[,..]) (string,optional) Deletes messages which are not associated with the specified assets. This filter has no effect on peer-to-peer messages.\n"
            "5. sender(hash[,...]) (string,optional) Deletes messages which are sent by the specified senders.\n"
            "6. receiver(hash[,...]) (string,optional) Deletes peer-to-peer messages which are sent to the specified receivers. This filter has no effect on broadcast and multicast messages.\n"
            + HelpExampleCli("deletemessages", "\"from(2016-01-01:10:10:10)\" \"asset(ACME,MSXY)\"")
            + HelpExampleRpc("deletemessages", "\"from(2016-02-01)\", \"asset(ACME,MSYZ)\"")
        );

    time_t from = 0;
    time_t to = 0;

    std::set<std::string> assets;
    std::set<std::string> types;
    std::set<std::string> senders;
    std::set<std::string> receivers;

    getParamValues(request.params, from, to, assets, types, senders, receivers);

    // The default behavior is to delete no messages
    if (from == 0 && to == 0 && assets.size() == 0 && types.size() == 0 && senders.size() == 0 && receivers.size() == 0) return NullUniValue;

    pwalletMain->DeleteMessages(from, to, assets, types, senders, receivers);

    return NullUniValue;
}

const CRPCCommand commands[] =
{   // category   name                  actor (function)  okSafeMode
    // ---------- --------------------- ----------------- ----------
    { "equibit", "p2pmessage", 	 	&p2pmessage,      true },
    { "equibit", "multicastmessage",	&multicastMessage,true },
    { "equibit", "broadcastmessage", &broadcastMessage,true },
    { "equibit", "getmessage",       &getMessage,      true },
    { "equibit", "getmessages",      &getMessages,     true },
    { "equibit", "deletemessage",    &deleteMessage,   true },
    { "equibit", "deletemessages",   &deleteMessages,  true },
};

}

void RegisterMessagingRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
