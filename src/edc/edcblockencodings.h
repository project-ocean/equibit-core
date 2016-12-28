// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_ENCODINGS_H
#define BITCOIN_BLOCK_ENCODINGS_H

#include "edc/primitives/edcblock.h"

#include <memory>

class CEDCTxMemPool;

// Dumb helper to handle CEDCTransaction compression at serialize-time
struct EDCTransactionCompressor 
{
private:
    CEDCTransaction& tx;
public:
    EDCTransactionCompressor(CEDCTransaction& txIn) : tx(txIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(tx); //TODO: Compress tx encoding
    }
};

class EDCBlockTransactionsRequest 
{
public:
    // A BlockTransactionsRequest message
    uint256 blockhash;
    std::vector<uint16_t> indexes;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(blockhash);
        uint64_t indexes_size = (uint64_t)indexes.size();
        READWRITE(COMPACTSIZE(indexes_size));

        if (ser_action.ForRead()) 
		{
            size_t i = 0;
            while (indexes.size() < indexes_size) 
			{
                indexes.resize(std::min((uint64_t)(1000 + indexes.size()), indexes_size));
                for (; i < indexes.size(); i++) 
				{
                    uint64_t index = 0;
                    READWRITE(COMPACTSIZE(index));
                    if (index > std::numeric_limits<uint16_t>::max())
                        throw std::ios_base::failure("index overflowed 16 bits");
                    indexes[i] = index;
                }
            }

            uint16_t offset = 0;
            for (size_t j = 0; j < indexes.size(); j++) 
			{
                if (uint64_t(indexes[j]) + uint64_t(offset) > std::numeric_limits<uint16_t>::max())
                    throw std::ios_base::failure("indexes overflowed 16 bits");
                indexes[j] = indexes[j] + offset;
                offset = indexes[j] + 1;
            }
        } 
		else 
		{
            for (size_t i = 0; i < indexes.size(); i++) 
			{
                uint64_t index = indexes[i] - (i == 0 ? 0 : (indexes[i - 1] + 1));
                READWRITE(COMPACTSIZE(index));
            }
        }
    }
};

class EDCBlockTransactions 
{
public:
    // A EDCBlockTransactions message
    uint256 blockhash;
    std::vector<CEDCTransaction> txn;

    EDCBlockTransactions() {}
    EDCBlockTransactions(const EDCBlockTransactionsRequest & req) :
        blockhash(req.blockhash), txn(req.indexes.size()) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(blockhash);
        uint64_t txn_size = (uint64_t)txn.size();
        READWRITE(COMPACTSIZE(txn_size));

        if (ser_action.ForRead()) 
		{
            size_t i = 0;
            while (txn.size() < txn_size) 
			{
                txn.resize(std::min((uint64_t)(1000 + txn.size()), txn_size));
                for (; i < txn.size(); i++)
                    READWRITE(REF(EDCTransactionCompressor(txn[i])));
            }
        } 
		else 
		{
            for (size_t i = 0; i < txn.size(); i++)
                READWRITE(REF(EDCTransactionCompressor(txn[i])));
        }
    }
};

// Dumb serialization/storage-helper for CBlockHeaderAndShortTxIDs and EDCPartiallyDownlaodedBlock
struct EDCPrefilledTransaction 
{
    // Used as an offset since last prefilled tx in CBlockHeaderAndShortTxIDs,
    // as a proper transaction-in-block-index in EDCPartiallyDownloadedBlock
    uint16_t index;
    CEDCTransaction tx;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        uint64_t idx = index;
        READWRITE(COMPACTSIZE(idx));
        if (idx > std::numeric_limits<uint16_t>::max())
            throw std::ios_base::failure("index overflowed 16-bits");
        index = idx;
        READWRITE(REF(EDCTransactionCompressor(tx)));
    }
};

typedef enum EDCReadStatus_t
{
    READ_STATUS_OK,
    READ_STATUS_INVALID, // Invalid object, peer is sending bogus crap
    READ_STATUS_FAILED, // Failed to process object
} EDCReadStatus;

class CEDCBlockHeaderAndShortTxIDs 
{
private:
    mutable uint64_t shorttxidk0, shorttxidk1;
    uint64_t nonce;

    void FillShortTxIDSelector() const;

    friend class EDCPartiallyDownloadedBlock;

    static const int SHORTTXIDS_LENGTH = 6;
protected:
    std::vector<uint64_t> shorttxids;
    std::vector<EDCPrefilledTransaction> prefilledtxn;

public:
    CBlockHeader header;

    // Dummy for deserialization
    CEDCBlockHeaderAndShortTxIDs() {}

    CEDCBlockHeaderAndShortTxIDs(const CEDCBlock& block);

    uint64_t GetShortID(const uint256& txhash) const;

    size_t BlockTxCount() const { return shorttxids.size() + prefilledtxn.size(); }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(header);
        READWRITE(nonce);

        uint64_t shorttxids_size = (uint64_t)shorttxids.size();
        READWRITE(COMPACTSIZE(shorttxids_size));

        if (ser_action.ForRead()) 
		{
            size_t i = 0;
            while (shorttxids.size() < shorttxids_size) 
			{
                shorttxids.resize(std::min((uint64_t)(1000 + shorttxids.size()), shorttxids_size));
                for (; i < shorttxids.size(); i++) 
				{
                    uint32_t lsb = 0; uint16_t msb = 0;
                    READWRITE(lsb);
                    READWRITE(msb);
                    shorttxids[i] = (uint64_t(msb) << 32) | uint64_t(lsb);
                    static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids serialization assumes 6-byte shorttxids");
                }
            }
        } 
		else 
		{
            for (size_t i = 0; i < shorttxids.size(); i++) 
			{
                uint32_t lsb = shorttxids[i] & 0xffffffff;
                uint16_t msb = (shorttxids[i] >> 32) & 0xffff;
                READWRITE(lsb);
                READWRITE(msb);
            }
        }

        READWRITE(prefilledtxn);

        if (ser_action.ForRead())
            FillShortTxIDSelector();
    }
};

class EDCPartiallyDownloadedBlock 
{
protected:
    std::vector<std::shared_ptr<const CEDCTransaction> > txn_available;
	size_t prefilled_count = 0;
	size_t mempool_count = 0;
    CEDCTxMemPool * pool;
public:
    CBlockHeader header;
    EDCPartiallyDownloadedBlock(CEDCTxMemPool* poolIn) : pool(poolIn) {}

    EDCReadStatus InitData(const CEDCBlockHeaderAndShortTxIDs& cmpctblock);
    bool IsTxAvailable(size_t index) const;
    EDCReadStatus FillBlock(CEDCBlock& block, const std::vector<CEDCTransaction>& vtx_missing) const;
};

#endif
