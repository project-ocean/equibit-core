// Copyright (c) 2014-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcbase58.h"

#include "hash.h"
#include "uint256.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <string>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>


CEDCBase58Data::CEDCBase58Data()
{
    vchVersion.clear();
    vchData.clear();
}

void CEDCBase58Data::SetData(
	const std::vector<unsigned char> & vchVersionIn, 
						  const void * pdata, 
								size_t nSize)
{
    vchVersion = vchVersionIn;
    vchData.resize(nSize);

    if (!vchData.empty())
        memcpy(&vchData[0], pdata, nSize);
}

void CEDCBase58Data::SetData(
	const std::vector<unsigned char> & vchVersionIn, 
				 const unsigned char * pbegin, 
				 const unsigned char * pend)
{
    SetData(vchVersionIn, (void*)pbegin, pend - pbegin);
}

bool CEDCBase58Data::SetString(const char* psz, unsigned int nVersionBytes)
{
    std::vector<unsigned char> vchTemp;
    bool rc58 = DecodeBase58Check(psz, vchTemp);

    if ((!rc58) || (vchTemp.size() < nVersionBytes)) 
	{
        vchData.clear();
        vchVersion.clear();
        return false;
    }

    vchVersion.assign(vchTemp.begin(), vchTemp.begin() + nVersionBytes);
    vchData.resize(vchTemp.size() - nVersionBytes);

    if (!vchData.empty())
        memcpy(&vchData[0], &vchTemp[nVersionBytes], vchData.size());

    memory_cleanse(&vchTemp[0], vchTemp.size());
    return true;
}

bool CEDCBase58Data::SetString(const std::string& str)
{
    return SetString(str.c_str());
}

std::string CEDCBase58Data::ToString() const
{
    std::vector<unsigned char> vch = vchVersion;
    vch.insert(vch.end(), vchData.begin(), vchData.end());
    return EncodeBase58Check(vch);
}

int CEDCBase58Data::CompareTo(const CEDCBase58Data& b58) const
{
    if (vchVersion < b58.vchVersion)
        return -1;
    if (vchVersion > b58.vchVersion)
        return 1;
    if (vchData < b58.vchData)
        return -1;
    if (vchData > b58.vchData)
        return 1;
    return 0;
}

namespace
{

class CEquibitAddressVisitor : public boost::static_visitor<bool>
{
private:
    CEDCBitcoinAddress* addr;

public:
    CEquibitAddressVisitor(CEDCBitcoinAddress* addrIn) : addr(addrIn) {}

    bool operator()(const CKeyID& id) const { return addr->Set(id); }
    bool operator()(const CScriptID& id) const { return addr->Set(id); }
    bool operator()(const CNoDestination& no) const { return false; }
};

}

bool CEDCBitcoinAddress::Set(const CKeyID& id)
{
    SetData(edcParams().Base58Prefix(CEDCChainParams::PUBKEY_ADDRESS), &id, 20);
    return true;
}

bool CEDCBitcoinAddress::Set(const CScriptID& id)
{
    SetData(edcParams().Base58Prefix(CEDCChainParams::SCRIPT_ADDRESS), &id, 20);
    return true;
}

bool CEDCBitcoinAddress::Set(const CTxDestination& dest)
{
    return boost::apply_visitor(CEquibitAddressVisitor(this), dest);
}

bool CEDCBitcoinAddress::IsValid() const
{
    return IsValid(edcParams());
}

bool CEDCBitcoinAddress::IsValid(const CEDCChainParams& params) const
{
    bool fCorrectSize = vchData.size() == 20;

    bool fKnownVersion = 
		vchVersion == params.Base58Prefix(CEDCChainParams::PUBKEY_ADDRESS) ||
        vchVersion == params.Base58Prefix(CEDCChainParams::SCRIPT_ADDRESS);

    return fCorrectSize && fKnownVersion;
}

CTxDestination CEDCBitcoinAddress::Get() const
{
    if (!IsValid())
        return CNoDestination();
    uint160 id;
    memcpy(&id, &vchData[0], 20);
    if (vchVersion == edcParams().Base58Prefix(CEDCChainParams::PUBKEY_ADDRESS))
        return CKeyID(id);
    else if (vchVersion == 
	edcParams().Base58Prefix(CEDCChainParams::SCRIPT_ADDRESS))
        return CScriptID(id);
    else
        return CNoDestination();
}

bool CEDCBitcoinAddress::GetKeyID(CKeyID& keyID) const
{
    if (!IsValid() || 
	vchVersion != edcParams().Base58Prefix(CEDCChainParams::PUBKEY_ADDRESS))
        return false;

    uint160 id;
    memcpy(&id, &vchData[0], 20);
    keyID = CKeyID(id);

    return true;
}

bool CEDCBitcoinAddress::IsScript() const
{
    return IsValid() && 
		vchVersion == edcParams().Base58Prefix(CEDCChainParams::SCRIPT_ADDRESS);
}

void CEDCBitcoinSecret::SetKey(const CKey& vchSecret)
{
    assert(vchSecret.IsValid());
    SetData(edcParams().Base58Prefix(CEDCChainParams::SECRET_KEY), 
		vchSecret.begin(), vchSecret.size());

    if (vchSecret.IsCompressed())
        vchData.push_back(1);
}

CKey CEDCBitcoinSecret::GetKey()
{
    CKey ret;
    assert(vchData.size() >= 32);
    ret.Set(vchData.begin(), vchData.begin() + 32, 
			vchData.size() > 32 && vchData[32] == 1);
    return ret;
}

bool CEDCBitcoinSecret::IsValid() const
{
    bool fExpectedFormat = vchData.size() == 32 || 
		(vchData.size() == 33 && vchData[32] == 1);

    bool fCorrectVersion = 
		vchVersion == edcParams().Base58Prefix(CEDCChainParams::SECRET_KEY);
    return fExpectedFormat && fCorrectVersion;
}

bool CEDCBitcoinSecret::SetString(const char* pszSecret)
{
    return CEDCBase58Data::SetString(pszSecret) && IsValid();
}

bool CEDCBitcoinSecret::SetString(const std::string& strSecret)
{
    return SetString(strSecret.c_str());
}
