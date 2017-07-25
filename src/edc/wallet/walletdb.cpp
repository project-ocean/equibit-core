// Copyright (c) 2016-2017 The Equibit Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/walletdb.h"
#include "wallet/wallet.h"
#include "issuer.h"


using namespace std;

namespace
{

// Wallet DB Keys:
const std::string ISSUER = "issuer";       // ISSUER:issuer-name/issuer
}

extern std::atomic<unsigned int> nWalletDBUpdateCounter;

bool CWalletDB::ReadIssuer(const string& strIssuer, CIssuer& issuer)
{
    issuer.SetNull();

    return Read(make_pair(ISSUER, strIssuer), issuer);
}

bool CWalletDB::WriteIssuer(const string& strIssuer, const CIssuer& issuer)
{
    nWalletDBUpdateCounter++;

    return Write(make_pair(ISSUER, strIssuer), issuer);
}

void CWalletDB::ListIssuers(vector<pair<string, CIssuer>>& issuers)
{
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__) + ": cannot create DB cursor");

    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue);

        if (ret == DB_NOTFOUND) break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__) + ": error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;

        if (strType == ISSUER)
        {
            string name;
            ssKey >> name;

            CIssuer issuer;
            ssValue >> issuer;

            issuers.push_back(make_pair(name, issuer));
        }
    }

    pcursor->close();
}
