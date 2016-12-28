// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "undo.h"
#include "edc/edccompressor.h" 
#include "edc/primitives/edctransaction.h"
#include "serialize.h"

/** Undo information for a CEDCTxIn
 *
 *  Contains the prevout's CEDCTxOut being spent, and if this was the
 *  last output of the affected transaction, its metadata as well
 *  (coinbase or not, height, transaction version)
 */
class CEDCTxInUndo
{
public:
    CEDCTxOut txout;         // the txout data before being spent
    bool fCoinBase;       // if the outpoint was the last unspent: whether it belonged to a coinbase
    unsigned int nHeight; // if the outpoint was the last unspent: its height
    int nVersion;         // if the outpoint was the last unspent: its version

    CEDCTxInUndo() : txout(), fCoinBase(false), nHeight(0), nVersion(0) {}
    CEDCTxInUndo(const CEDCTxOut &txoutIn, bool fCoinBaseIn = false, unsigned int nHeightIn = 0, int nVersionIn = 0) : txout(txoutIn), fCoinBase(fCoinBaseIn), nHeight(nHeightIn), nVersion(nVersionIn) { }

    unsigned int GetSerializeSize(int nType, int nVersion) const 
	{
        return ::GetSerializeSize(VARINT(nHeight*2+(fCoinBase ? 1 : 0)), nType, nVersion) +
               (nHeight > 0 ? ::GetSerializeSize(VARINT(this->nVersion), nType, nVersion) : 0) +
               ::GetSerializeSize(CEDCTxOutCompressor(REF(txout)), nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream &s, int nType, int nVersion) const 
	{
        ::Serialize(s, VARINT(nHeight*2+(fCoinBase ? 1 : 0)), nType, nVersion);
        if (nHeight > 0)
            ::Serialize(s, VARINT(this->nVersion), nType, nVersion);
        ::Serialize(s, CEDCTxOutCompressor(REF(txout)), nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream &s, int nType, int nVersion) 
	{
        unsigned int nCode = 0;
        ::Unserialize(s, VARINT(nCode), nType, nVersion);
        nHeight = nCode / 2;
        fCoinBase = nCode & 1;
        if (nHeight > 0)
            ::Unserialize(s, VARINT(this->nVersion), nType, nVersion);
        ::Unserialize(s, REF(CEDCTxOutCompressor(REF(txout))), nType, nVersion);
    }
};

/** Undo information for a CTransaction */
class CEDCTxUndo
{
public:
    // undo information for all txins
    std::vector<CEDCTxInUndo> vprevout;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(vprevout);
    }
};

/** Undo information for a CEDCBlock */
class CEDCBlockUndo
{
public:
    std::vector<CEDCTxUndo> vtxundo; // for all but the coinbase

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(vtxundo);
    }
};

