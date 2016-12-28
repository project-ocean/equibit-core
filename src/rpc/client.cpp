// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util.h"

#include <set>
#include <stdint.h>

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <univalue.h>

using namespace std;

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
};

static const CRPCConvertParam vRPCConvertParams[] =
{
    { "stop", 0 },
    { "setmocktime", 0 },
    { "generate", 0 },
    { "generate", 1 },
    { "generatetoaddress", 0 },
    { "generatetoaddress", 2 },
    { "getnetworkhashps", 0 },
    { "getnetworkhashps", 1 },
    { "sendtoaddress", 1 },
    { "sendtoaddress", 4 },
    { "settxfee", 0 },
    { "getreceivedbyaddress", 1 },
    { "getreceivedbyaccount", 1 },
    { "listreceivedbyaddress", 0 },
    { "listreceivedbyaddress", 1 },
    { "listreceivedbyaddress", 2 },
    { "listreceivedbyaccount", 0 },
    { "listreceivedbyaccount", 1 },
    { "listreceivedbyaccount", 2 },
    { "getbalance", 1 },
    { "getbalance", 2 },
    { "getblockhash", 0 },
    { "waitforblockheight", 0 },
    { "waitforblockheight", 1 },
    { "waitforblock", 1 },
    { "waitforblock", 2 },
    { "waitfornewblock", 0 },
    { "waitfornewblock", 1 },
    { "move", 2 },
    { "move", 3 },
    { "sendfrom", 2 },
    { "sendfrom", 3 },
    { "listtransactions", 1 },
    { "listtransactions", 2 },
    { "listtransactions", 3 },
    { "listaccounts", 0 },
    { "listaccounts", 1 },
    { "walletpassphrase", 1 },
    { "getblocktemplate", 0 },
    { "listsinceblock", 1 },
    { "listsinceblock", 2 },
    { "sendmany", 1 },
    { "sendmany", 2 },
    { "sendmany", 4 },
    { "addmultisigaddress", 0 },
    { "addmultisigaddress", 1 },
    { "createmultisig", 0 },
    { "createmultisig", 1 },
    { "listunspent", 0 },
    { "listunspent", 1 },
    { "listunspent", 2 },
    { "getblock", 1 },
    { "getblockheader", 1 },
    { "gettransaction", 1 },
    { "getrawtransaction", 1 },
    { "createrawtransaction", 0 },
    { "createrawtransaction", 1 },
    { "createrawtransaction", 2 },
    { "signrawtransaction", 1 },
    { "signrawtransaction", 2 },
    { "sendrawtransaction", 1 },
    { "fundrawtransaction", 1 },
    { "gettxout", 1 },
    { "gettxout", 2 },
    { "gettxoutproof", 0 },
    { "lockunspent", 0 },
    { "lockunspent", 1 },
    { "importprivkey", 2 },
    { "importaddress", 2 },
    { "importaddress", 3 },
    { "importpubkey", 2 },
    { "verifychain", 0 },
    { "verifychain", 1 },
    { "keypoolrefill", 0 },
    { "getrawmempool", 0 },
    { "estimatefee", 0 },
    { "estimatepriority", 0 },
    { "estimatesmartfee", 0 },
    { "estimatesmartpriority", 0 },
    { "prioritisetransaction", 1 },
    { "prioritisetransaction", 2 },
    { "setban", 2 },
    { "setban", 3 },
	{ "getmempoolancestors", 1 },
	{ "getmempooldescendants", 1 },
// EDC BEGIN
    { "eb_stop", 0 },
    { "eb_setmocktime", 0 },
    { "eb_getaddednodeinfo", 0 },
    { "eb_generate", 0 },
    { "eb_generate", 1 },
    { "eb_generatetoaddress", 0 },
    { "eb_generatetoaddress", 2 },
    { "eb_getnetworkhashps", 0 },
    { "eb_getnetworkhashps", 1 },
    { "eb_sendtoaddress", 1 },
    { "eb_sendtoaddress", 4 },
    { "eb_settxfee", 0 },
    { "eb_getreceivedbyaddress", 1 },
    { "eb_getreceivedbyaccount", 1 },
    { "eb_listreceivedbyaddress", 0 },
    { "eb_listreceivedbyaddress", 1 },
    { "eb_listreceivedbyaddress", 2 },
    { "eb_listreceivedbyaccount", 0 },
    { "eb_listreceivedbyaccount", 1 },
    { "eb_listreceivedbyaccount", 2 },
    { "eb_getbalance", 1 },
    { "eb_getbalance", 2 },
    { "eb_getblockhash", 0 },
    { "eb_move", 2 },
    { "eb_move", 3 },
    { "eb_sendfrom", 2 },
    { "eb_sendfrom", 3 },
    { "eb_listtransactions", 1 },
    { "eb_listtransactions", 2 },
    { "eb_listtransactions", 3 },
    { "eb_listaccounts", 0 },
    { "eb_listaccounts", 1 },
    { "eb_walletpassphrase", 1 },
    { "eb_getblocktemplate", 0 },
    { "eb_listsinceblock", 1 },
    { "eb_listsinceblock", 2 },
    { "eb_sendmany", 1 },
    { "eb_sendmany", 2 },
    { "eb_sendmany", 4 },
    { "eb_addmultisigaddress", 0 },
    { "eb_addmultisigaddress", 1 },
    { "eb_createmultisig", 0 },
    { "eb_createmultisig", 1 },
    { "eb_listunspent", 0 },
    { "eb_listunspent", 1 },
    { "eb_listunspent", 2 },
    { "eb_getblock", 1 },
    { "eb_getblockheader", 1 },
    { "eb_gettransaction", 1 },
    { "eb_getrawtransaction", 1 },
    { "eb_createrawtransaction", 0 },
    { "eb_createrawtransaction", 1 },
    { "eb_createrawtransaction", 2 },
    { "eb_signrawtransaction", 1 },
    { "eb_signrawtransaction", 2 },
    { "eb_sendrawtransaction", 1 },
    { "eb_fundrawtransaction", 1 },
    { "eb_gettxout", 1 },
    { "eb_gettxout", 2 },
    { "eb_gettxoutproof", 0 },
    { "eb_lockunspent", 0 },
    { "eb_lockunspent", 1 },
    { "eb_importprivkey", 2 },
    { "eb_importaddress", 2 },
    { "eb_importaddress", 3 },
    { "eb_importpubkey", 2 },
    { "eb_verifychain", 0 },
    { "eb_verifychain", 1 },
    { "eb_keypoolrefill", 0 },
    { "eb_getrawmempool", 0 },
    { "eb_estimatefee", 0 },
    { "eb_estimatepriority", 0 },
    { "eb_estimatesmartfee", 0 },
    { "eb_estimatesmartpriority", 0 },
    { "eb_prioritisetransaction", 1 },
    { "eb_prioritisetransaction", 2 },
    { "eb_setban", 2 },
    { "eb_setban", 3 },
	{ "eb_authorizeequibit", 2 },
	{ "eb_getmempoolancestors", 1 },
	{ "eb_getmempooldescendants", 1 },
// EDC END
};

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int> > members;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw runtime_error(string("Error parsing JSON:")+strVal);
    return jVal[0];
}

/** Convert strings to command-specific RPC representation */
UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}
