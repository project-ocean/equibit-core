// Copyright (c) 2014-2017 The Bitcoin Core developers
// Copyright (c) 2019 The OCEAN Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_HMAC_SHA3_H
#define BITCOIN_CRYPTO_HMAC_SHA3_H

#include <eqb/sha3/sha3.h>

#include <stdint.h>
#include <stdlib.h>

/** A hasher class for HMAC-SHA-3. */
class CHMAC_SHA3
{
private:
    CSHA3 outer;
    CSHA3 inner;

public:
    static const size_t OUTPUT_SIZE = 32;

    CHMAC_SHA3(const unsigned char* key, size_t keylen);
    CHMAC_SHA3& Write(const unsigned char* data, size_t len)
    {
        inner.Write(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};

#endif // BITCOIN_CRYPTO_HMAC_SHA3_H
