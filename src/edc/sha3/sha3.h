// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "serialize.h"
#include "uint256.h"
#include "version.h"
#include "SimpleFIPS202.h"

#include <vector>


class Sha3
{
private:

    std::vector<char> m_serialization;

    const int m_type;
    const int m_version;

public:

    Sha3(int type, int version) : m_type(type), m_version(version)
    {
        m_serialization.reserve(128);
    }

    int GetType() const { return m_type; }
    int GetVersion() const { return m_version; }

    void write(const char *pch, size_t size)
    {
        while (size--) m_serialization.push_back(*pch++);
    }

    uint256 GetHash()
    {
        uint256 hash;

        SHA3_256((unsigned char*)&hash, (unsigned char*)&m_serialization[0], m_serialization.size());

        return hash;
    }

    template<typename T> Sha3& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return (*this);
    }

    template<typename T> static uint256 SerializeHash(const T& obj, int type = SER_GETHASH, int version = PROTOCOL_VERSION)
    {
        Sha3 sha3(type, version);

        sha3 << obj;

        return sha3.GetHash();
    }
};
