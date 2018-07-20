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
#include "edc/rpc/edcpolling.h"
#include "edc/json.h"


namespace
{

std::string trim(const std::string & a)
{
    std::string out;

    size_t b = 0;
    size_t e = a.size() - 1;

    while (b < e && isspace(a[b]))
        ++b;
    while (e > b && isspace(a[e]))
        --e;

    return std::string(a, b, e - b + 1);
}

// 0) answers.size() > 0
// 1) It must contain at least one comma 
// 2) The first character cannot be a comma
// 3) The last character cannot be a comma
// 4) No two commas are adjacent (ie. no value is empty)
//
bool validAnswers(
    const std::string & answers,
    std::vector<std::string> & ansVec)
{
    if (answers.size() == 0 ||
        answers[0] == ',' ||
        answers[answers.size() - 1] == ',' ||
        answers.find(',') == std::string::npos)
        return false;

    auto i = answers.begin();
    auto e = answers.end();

    std::string ans;

    while (i != e)
    {
        if (*i == ',')
        {
            ans = trim(ans);
            if (ans.size() == 0)
                return false;

            ansVec.push_back(ans);
            ans.clear();
        }
        else
            ans += *i;

        ++i;
    }

    ans = trim(ans);
    if (ans.size() == 0)
        return false;

    ansVec.push_back(ans);
    return true;
}

bool validDate(const std::string & date)
{
    // 0123456789
    // YYYY-MM-DD
    return 	isdigit(date[0]) && isdigit(date[1]) && isdigit(date[2]) && isdigit(date[3]) &&
        isdigit(date[5]) && isdigit(date[6]) &&
        isdigit(date[8]) && isdigit(date[9]);
}

}

UniValue poll(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
            "poll \"address\" \"poll-question\" \"list-of-responses\" \"end-date\" (\"start-date\")\n"
            "\nAssign proxy voting privileges to specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"               (string, required) The address of issuer creating the poll\n"
            "2. \"polling question\"   (string, required) The poll question\n"
            "3. \"list-of-responses\"  (string, required) Comma separated list of valid responses\n"
            "4. \"end-date\"           (string, required) Date on which the poll ends\n"
            "5. \"start-date\"         (string, optional) Date on which the poll starts\n"
            "\nResult: ID of the poll\n"
            "\nExamples:\n"
            + HelpExampleCli("poll", "\"139...301\" \"Please vote for the new board member\" \"Mary Smith,John Black\" \"2017-02-28\"")
            + HelpExampleRpc("poll", "\"139...301\", \"Please vote for the new board member\", \"Mary Smyth,John Black\" \"2017-02-28\"")
        );

    std::string address = request.params[0].get_str();
    std::string question = request.params[1].get_str();
    std::string answers = request.params[2].get_str();
    std::string endDate = request.params[3].get_str();
    std::string startDate;
    if (request.params.size() > 4)
    {
        startDate = request.params[4].get_str();
    }

    CBitcoinAddress  addr(address);

    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID issuerID;
    if (!addr.GetKeyID(issuerID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    std::vector<std::string> ansVec;
    if (!validAnswers(answers, ansVec))
        throw JSONRPCError(RPC_TYPE_ERROR, "Valid poll answers parameter should be a comma separated list of at least two values");

    if (!validDate(endDate))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid end date. It should be of the form YYYY-MM-DD");

    if (startDate.size())
    {
        if (!validDate(startDate))
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid start date. It should be of the form YYYY-MM-DD");
    }
    else
    {
        time_t t;
        struct tm ts;
        time(&t);
        localtime_r(&t, &ts);

        char buff[16];
        sprintf(buff, "%4.4d-%2.2d-%2.2d", ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday);

        startDate = buff;
    }

    Poll poll(issuerID, question, ansVec, startDate, endDate);

    auto * msg = new CPoll(issuerID, poll.toJSON());
    auto hash = msg->GetHash();

    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->AddPoll(poll, hash, errStr);
    }
    if (!rc)
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);

    g_connman->RelayUserMessage(msg, true);

    UniValue result(hash.ToString());
    return result;
}

UniValue vote(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 5)
        throw std::runtime_error(
            "vote \"address\" \"issuer-address\" \"pollid\" \"response\" ( \"proxied-addr\" )\n"
            "\nRevoke proxy voting privileges from specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"          (string, required) The address of sender\n"
            "2. \"iaddr\"         (string, required) The address of issuer of poll\n"
            "3. \"pollid\"        (string, required) The id of the poll\n"
            "3. \"response\"      (string, required) The poll response value\n"
            "4. \"proxied-addr\"  (string, optional) The proxied address\n"
            "\nResult: ID of the vote\n"
            "\nExamples:\n"
            + HelpExampleCli("vote", "\"139...301\" \"1xcc...adfv\" \"John Black\" \"1zswdc...209sf\"")
            + HelpExampleRpc("vote", "\"139...301\", \"1vj4...adfv\" \"Mary Smyth\"")
        );

    std::string address = request.params[0].get_str();
    std::string iAddress = request.params[1].get_str();
    std::string pollid = request.params[2].get_str();
    std::string response = request.params[3].get_str();

    CBitcoinAddress sender(request.params[0].get_str());
    CKeyID senderID;
    if (!sender.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    if (!sender.GetKeyID(senderID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CBitcoinAddress issuer(request.params[1].get_str());
    CKeyID issuerID;
    if (!issuer.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid issuer address");

    if (!issuer.GetKeyID(issuerID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid issuer address");

    uint256 pollID;
    pollID.SetHex(pollid);

    CKeyID pAddrID;
    if (request.params.size() > 4)
    {
        std::string proxiedAddr = request.params[4].get_str();
        CBitcoinAddress pAddr(proxiedAddr);

        if (!pAddr.IsValid())
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxied address");

        if (!pAddr.GetKeyID(pAddrID))
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxied address");
    }

    Vote vote(pollID, response, pAddrID);

    CPeerToPeer * msg = CPeerToPeer::create(CVote::tag, senderID, issuerID, vote.toJSON());
    auto hash = msg->GetHash();

    g_connman->RelayUserMessage(msg, true);

    UniValue result(hash.ToString());
    return result;
}

UniValue pollresults(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "pollresults \"pollid\" (\"type\")\n"
            "\nReturns the results of the poll.\n"
            "\nArguments:\n"
            "1. \"pollid\"         (string, required) The id of the poll\n"
            "2. \"type\"           (string, optional) Type of output. Default: summary\n"
            "\nThe types are \"summary\", \"response\" or \"all\". If \"summary\" is specified\n"
            "then only a summary of the results is output. This is the number of votes for each\n"
            "possible response value. If \"response\" is specified, then for each response, the\n"
            "list of addresses that voted for the given value are listed. If \"all\" is specified\n"
            "then all details are returned.\n"
            "\nResult: JSON encoding of poll results, based on type.\n"
            "\nExamples:\n"
            + HelpExampleCli("pollresults", "\"139...301\" \"1xcc...adfv\" \"John Black\"")
            + HelpExampleRpc("pollresults", "\"139...301\", \"1vj4...adfv\" \"Mary Smyth\"")
        );

    std::string pollidStr = request.params[0].get_str();

    uint256 pollid;
    pollid.SetHex(pollidStr);

    LOCK2(cs_main, pwalletMain->cs_wallet);

    const PollResult * result;
    bool rc = pwalletMain->pollResult(pollid, result);
    if (!rc)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid poll ID");

    std::string type = "summary";

    if (request.params.size() > 1)
        type = request.params[1].get_str();

    std::string ans;

    if (type == "summary")
        result->summary(ans);
    else if (type == "response")
        result->response(ans);
    else if (type == "all")
        result->all(ans);
    else
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid result type");

    UniValue value(ans);
    return value;
}

namespace
{

const CRPCCommand Commands[] =
{ //  category     name              actor (function) okSafeMode
  //  ------------ ----------------- ---------------- ----------
    { "equibit",   "poll",        &poll,        true },
    { "equibit",   "vote",        &vote,        true },
    { "equibit",   "pollresults", &pollresults, true },
};

}

void RegisterPollingRPCCommands(CRPCTable & tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(Commands); vcidx++)
        tableRPC.appendCommand(Commands[vcidx].name, &Commands[vcidx]);
}

//////////////////////////////////////////////////////////////////////

namespace
{

// 0123456789
// yyyy-mm-dd
time_t toTime(const std::string & date)
{
    int y = (date[0] - '0') * 1000 +
        (date[1] - '0') * 100 +
        (date[2] - '0') * 10 +
        (date[3] - '0');
    int m = (date[5] - '0') * 10 + (date[6] - '0');
    int d = (date[8] - '0') * 10 + (date[9] - '0');

    struct tm ts;
    memset(&ts, 0, sizeof(struct tm));

    ts.tm_year = y - 1900;
    ts.tm_mon = m - 1;
    ts.tm_mday = d;

    return mktime(&ts);
}

}

Poll::Poll(
    const CKeyID 	  & issuerID,
    const std::string & question,
    const std::vector<std::string> & ans,
    const std::string & start,
    const std::string & end) :
    issuerID_(issuerID),
    question_(question),
    answers_(ans),
    start_(toTime(start)),
    end_(toTime(end))
{
}

namespace
{

time_t strToTime(const std::string & s)
{
    struct tm t;
    memset(&t, 0, sizeof(t));

    int y = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + s[3] - '0';
    int m = (s[5] - '0') * 10 + s[6] - '0';
    int d = (s[8] - '0') * 10 + s[9] - '0';

    t.tm_year = y - 1900;
    t.tm_mon = m - 1;
    t.tm_mday = d;

    return mktime(&t);
}

};

Poll::Poll(const std::vector<unsigned char> & data)
{
    JSONnode * node = JSONnode::parse(data);
    assert(node->type() == JSONnode::JOBJECT);

    JSONobject * obj = static_cast<JSONobject *>(node);

    const auto & elements = obj->value();

    auto i = elements.begin();
    auto e = elements.end();
    while (i != e)
    {
        auto node = i->second.get();
        if (i->first == "issuer")
        {
            assert(node->type() == JSONnode::JSTRING);
            const std::string & issuer = static_cast<JSONstring *>(node)->value();

            issuerID_.SetHex(issuer);
        }
        else if (i->first == "question")
        {
            assert(node->type() == JSONnode::JSTRING);
            question_ = static_cast<JSONstring *>(node)->value();
        }
        else if (i->first == "answers")
        {
            assert(node->type() == JSONnode::JARRAY);
            auto j = static_cast<JSONarray *>(node)->value().begin();
            auto f = static_cast<JSONarray *>(node)->value().end();

            while (j != f)
            {
                assert((*j)->type() == JSONnode::JSTRING);
                JSONstring * ans = static_cast<JSONstring *>(j->get());

                answers_.push_back(ans->value());
                ++j;
            }
        }
        else if (i->first == "start")
        {
            assert(node->type() == JSONnode::JSTRING);
            const std::string & start = static_cast<JSONstring *>(node)->value();

            start_ = strToTime(start);
        }
        else if (i->first == "end")
        {
            assert(node->type() == JSONnode::JSTRING);
            const std::string & end = static_cast<JSONstring *>(node)->value();

            end_ = strToTime(end);
        }
        else
            assert(false);

        ++i;
    }
}

bool Poll::validAnswer(const std::string & ans) const
{
    return std::find(answers_.begin(), answers_.end(), ans) != answers_.end();
}

bool Poll::validDate(time_t d) const
{
    return d >= start_ && d <= end_;
}

std::string Poll::toJSON() const
{
    std::string ans = "{\"issuer\":\"";
    ans += CBitcoinAddress(issuerID_).ToString();
    ans += "\"";

    ans += ",\"question\":\"";
    ans += question_;
    ans += "\"";

    ans += ",\"answers\": [";

    auto i = answers_.begin();
    auto e = answers_.end();
    bool first = true;

    while (i != e)
    {
        if (!first)
            ans += ",";
        else
            first = false;

        ans += "\"" + *i + "\"";
        ++i;
    }
    ans += "]";

    ans += ",\"start\":";
    char buff[16];
    strftime(buff, 16, "\"%Y-%m-%d\"", localtime(&start_));
    ans += buff;

    ans += ",\"end\":";
    strftime(buff, 16, "\"%Y-%m-%d\"", localtime(&end_));
    ans += buff;

    ans += "}";

    return ans;
}

std::string Vote::toJSON() const
{
    std::string ans = "{\"pollid\":\"";
    ans += pollID_.ToString();
    ans += "\"";

    ans += ",\"response\":\"";
    ans += response_;
    ans += "\"";

    if (!proxiedAddr_.IsNull())
    {
        ans += ",\"proxiedaddr\":";
        ans += CBitcoinAddress(proxiedAddr_).ToString();
        ans += "\"";
    }

    ans += "}";

    return ans;
}

void PollResult::addVote(
    const std::string & ans,
    const CKeyID & id,
    Type ty)
{
    auto rc = results_.insert(std::make_pair(id, std::pair<std::string, int>()));

    if (rc.first->second.first.size() == 0)
    {
        rc.first->second.first = ans;
        rc.first->second.second = ty;
    }
    else if (rc.first->second.first == ans)
    {
        // If the same vote has already be entered for this address, then
        // make sure the type is the maximum of the two
        if (rc.first->second.second < ty)
            rc.first->second.second = ty;
    }
    else
    {
        // If a different answer has been entered for this address, then
        // only do an update if the type is greater then the previous one
        if (rc.first->second.second < ty)
        {
            rc.first->second.first = ans;
            rc.first->second.second = ty;
        }
    }
}

void PollResult::summary(std::string & ans) const
{
    std::map<std::string, unsigned> result;

    auto i = results_.begin();
    auto e = results_.end();
    while (i != e)
    {
        auto rc = result.insert(std::make_pair(i->second.first, 0));

        ++rc.first->second;

        ++i;
    }

    ans = "[";
    bool first = true;

    auto ri = result.begin();
    auto re = result.end();
    while (ri != re)
    {
        if (!first)
            ans += ",";
        else
            first = false;

        ans += "{\"response\":\"" + ri->first + "\"";

        ans += ",\"count\":";
        char buff[10];
        sprintf(buff, "%u", ri->second);
        ans += buff;

        ans += "}";
        ++ri;
    }

    ans += "]";
}

void PollResult::response(std::string & ans) const
{
    std::map<std::string, std::string> result;

    auto i = results_.begin();
    auto e = results_.end();
    while (i != e)
    {
        auto rc = result.insert(std::make_pair(i->second.first, std::string()));

        if (rc.first->second.size())
            rc.first->second += ",\"" + i->first.ToString() + "\"";
        else
            rc.first->second = "\"" + i->first.ToString() + "\"";

        ++i;
    }

    ans = "[";
    bool first = true;

    auto ri = result.begin();
    auto re = result.end();
    while (ri != re)
    {
        if (!first)
            ans += ",";
        else
            first = false;

        ans += "{\"response\":\"" + ri->first + "\"";

        ans += ",\"addresses\":[" + ri->second + "]";

        ans += "}";
        ++ri;
    }

    ans += "]";
}

namespace
{

const std::string & toString(int t)
{
    static const std::string	invalid = "invalid";
    static const std::string	general = "general";
    static const std::string	issuer = "issuer";
    static const std::string	poll = "poll";
    static const std::string	owner = "owner";

    switch (t)
    {
        default:					return invalid;
        case PollResult::GENERAL:	return general;
        case PollResult::ISSUER:	return issuer;
        case PollResult::POLL:		return poll;
        case PollResult::OWNER:		return owner;
    }
}

}

void PollResult::all(std::string & ans) const
{
    ans = "[";

    bool first = true;

    auto i = results_.begin();
    auto e = results_.end();

    while (i != e)
    {
        if (!first)
            ans += ",";
        else
            first = false;

        ans += "{";
        ans += "\"response\":\"" + i->second.first + "\",";
        ans += "\"address\":\"" + i->first.ToString() + "\",";
        ans += "\"proxy_type\":\"" + toString(i->second.second);
        ans += "\"}";

        ++i;
    }

    ans += "]";
}
