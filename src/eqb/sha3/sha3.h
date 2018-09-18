// Copyright (c) 2018 Equibit Group AG
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#ifndef BUILD_BTC

#include "SimpleFIPS202.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"
#include <iostream>
#include <string>

#include <vector>

class SHA3
{
private:
    std::vector<char> m_serialization;

    const int m_type;
    const int m_version;

public:
    static const size_t OUTPUT_SIZE = 32;

    SHA3() : m_type(0), m_version(0)
    {
        m_serialization.reserve(OUTPUT_SIZE);
    }
    SHA3(int type, int version) : m_type(type), m_version(version)
    {
        m_serialization.reserve(OUTPUT_SIZE);
    }

    int GetType() const { return m_type; }
    int GetVersion() const { return m_version; }
   
    SHA3& Write(const unsigned char* pch, size_t size)
    {
        while (size--)
            m_serialization.push_back(*pch++);

        return *this;
    }

    void Finalize(unsigned char hash[OUTPUT_SIZE])
    {
        uint256 hashresult = GetHash();
        memcpy(hash, (unsigned char*) &hashresult, OUTPUT_SIZE);
    }

    uint256 GetHash()
    {
        uint256 hash;
        SHA3_256((unsigned char*)&hash, (unsigned char *) m_serialization.data(), m_serialization.size());
        return hash;
    }

    template <typename T>
    SHA3& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return (*this);
    }

    template <typename T>
    static uint256 SerializeHash(const T& obj, int type = SER_GETHASH, int version = PROTOCOL_VERSION)
    {
    	SHA3 sha3(type, version);

        sha3 << obj;

        return sha3.GetHash();
    }
};
#endif // END_BUILD
