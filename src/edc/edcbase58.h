// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Why base-58 instead of standard base-64 encoding?
 * - Don't want 0OIl characters that look the same in some fonts and
 *      could be used to create visually identical looking data.
 * - A string with non-alphanumeric characters is not as easily accepted as input.
 * - E-mail usually won't line-break if there's no punctuation to break at.
 * - Double-clicking selects the whole string as one word if it's all alphanumeric.
 */
#pragma once

#include "base58.h"
#include "edcchainparams.h"
#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "support/allocators/zeroafterfree.h"

#include <string>
#include <vector>


/**
 * Base class for all base58-encoded data
 */
class CEDCBase58Data
{
protected:
    //! the version byte(s)
    std::vector<unsigned char> vchVersion;

    //! the actually encoded data
    typedef std::vector<unsigned char, zero_after_free_allocator<unsigned char> > vector_uchar;
    vector_uchar vchData;

    CEDCBase58Data();
    void SetData(const std::vector<unsigned char> &vchVersionIn, const void* pdata, size_t nSize);
    void SetData(const std::vector<unsigned char> &vchVersionIn, const unsigned char *pbegin, const unsigned char *pend);

public:
    bool SetString(const char* psz, unsigned int nVersionBytes = 1);
    bool SetString(const std::string& str);
    std::string ToString() const;
    int CompareTo(const CEDCBase58Data& b58) const;

    bool operator==(const CEDCBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const CEDCBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CEDCBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CEDCBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CEDCBase58Data& b58) const { return CompareTo(b58) >  0; }
};

/** base58-encoded Equibit addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 */
class CEDCBitcoinAddress : public CEDCBase58Data 
{
public:
    bool Set(const CKeyID &id);
    bool Set(const CScriptID &id);
    bool Set(const CTxDestination &dest);
    bool IsValid() const;
    bool IsValid(const CEDCChainParams &params) const;

    CEDCBitcoinAddress() {}
    CEDCBitcoinAddress(const CTxDestination &dest) { Set(dest); }
    CEDCBitcoinAddress(const std::string& strAddress) { SetString(strAddress); }
    CEDCBitcoinAddress(const char* pszAddress) { SetString(pszAddress); }

    CTxDestination Get() const;
    bool GetKeyID(CKeyID &keyID) const;
    bool IsScript() const;
};

/**
 * A base58-encoded secret key
 */
class CEDCBitcoinSecret : public CEDCBase58Data
{
public:
    void SetKey(const CKey& vchSecret);
    CKey GetKey();
    bool IsValid() const;
    bool SetString(const char* pszSecret);
    bool SetString(const std::string& strSecret);

    CEDCBitcoinSecret(const CKey& vchSecret) { SetKey(vchSecret); }
    CEDCBitcoinSecret() {}
};

template<typename K, int Size, CEDCChainParams::Base58Type Type> class CEDCBitcoinExtKeyBase : public CEDCBase58Data
{
public:
    void SetKey(const K &key) 
	{
        unsigned char vch[Size];
        key.Encode(vch);
        SetData(edcParams().Base58Prefix(Type), vch, vch+Size);
    }

    K GetKey() 
	{
        K ret;
        if (vchData.size() == Size) 
		{
            //if base58 encouded data not holds a ext key, return a !IsValid() key
            ret.Decode(&vchData[0]);
        }
        return ret;
    }

    CEDCBitcoinExtKeyBase(const K &key) 
	{
        SetKey(key);
    }

    CEDCBitcoinExtKeyBase(const std::string& strBase58c) 
	{
        SetString(strBase58c.c_str(), edcParams().Base58Prefix(Type).size());
    }

    CEDCBitcoinExtKeyBase() {}
};

typedef CEDCBitcoinExtKeyBase<CExtKey, BIP32_EXTKEY_SIZE, CEDCChainParams::EXT_SECRET_KEY> CEDCBitcoinExtKey;
typedef CEDCBitcoinExtKeyBase<CExtPubKey,BIP32_EXTKEY_SIZE,CEDCChainParams::EXT_PUBLIC_KEY> CEDCBitcoinExtPubKey;

