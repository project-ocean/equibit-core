// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "edc/primitives/edcblock.h"
#include "edctxmempool.h"

#include <stdint.h>
#include <memory>
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/ordered_index.hpp"

class CBlockIndex;
class CEDCChainParams;
class CEDCReserveKey;
class CScript;
class CEDCWallet;

namespace Consensus { struct Params; };

static const bool EDC_DEFAULT_PRINTPRIORITY = false;

struct CEDCBlockTemplate
{
    CEDCBlock block;
    std::vector<CAmount> vTxFees;
	std::vector<int64_t> vTxSigOpsCost;
	std::vector<unsigned char> vchCoinbaseCommitment;
};

// Container for tracking updates to ancestor feerate as we include (parent)
// transactions in a block
struct CEDCTxMemPoolModifiedEntry 
{
    CEDCTxMemPoolModifiedEntry(CEDCTxMemPool::txiter entry)
    {
        iter = entry;
        nSizeWithAncestors = entry->GetSizeWithAncestors();
        nModFeesWithAncestors = entry->GetModFeesWithAncestors();
		nSigOpCostWithAncestors = entry->GetSigOpCostWithAncestors();
    }

    CEDCTxMemPool::txiter iter;
    uint64_t nSizeWithAncestors;
    CAmount nModFeesWithAncestors;
	int64_t nSigOpCostWithAncestors;
};

/** Comparator for CTxMemPool::txiter objects.
 *  It simply compares the internal memory address of the CTxMemPoolEntry object
 *  pointed to. This means it has no meaning, and is only useful for using them
 *  as key in other indexes.
 */
struct EDCCompareCTxMemPoolIter 
{
    bool operator()(const CEDCTxMemPool::txiter& a, const CEDCTxMemPool::txiter& b) const
    {
        return &(*a) < &(*b);
    }
};

struct EDCmodifiedentry_iter 
{
    typedef CEDCTxMemPool::txiter result_type;
    result_type operator() (const CEDCTxMemPoolModifiedEntry &entry) const
    {
        return entry.iter;
    }
};

// This matches the calculation in CompareTxMemPoolEntryByAncestorFee,
// except operating on CTxMemPoolModifiedEntry.
// TODO: refactor to avoid duplication of this logic.
struct EDCCompareModifiedEntry 
{
    bool operator()(const CEDCTxMemPoolModifiedEntry &a, const CEDCTxMemPoolModifiedEntry &b)
    {
        double f1 = (double)a.nModFeesWithAncestors * b.nSizeWithAncestors;
        double f2 = (double)b.nModFeesWithAncestors * a.nSizeWithAncestors;
        if (f1 == f2) {
            return CEDCTxMemPool::CompareIteratorByHash()(a.iter, b.iter);
        }
        return f1 > f2;
    }
};

// A comparator that sorts transactions based on number of ancestors.
// This is sufficient to sort an ancestor package in an order that is valid
// to appear in a block.
struct EDCCompareTxIterByAncestorCount 
{
    bool operator()(const CEDCTxMemPool::txiter &a, const CEDCTxMemPool::txiter &b)
    {
        if (a->GetCountWithAncestors() != b->GetCountWithAncestors())
            return a->GetCountWithAncestors() < b->GetCountWithAncestors();
        return CEDCTxMemPool::CompareIteratorByHash()(a, b);
    }
};

typedef boost::multi_index_container<
    CEDCTxMemPoolModifiedEntry,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<
            EDCmodifiedentry_iter,
            EDCCompareCTxMemPoolIter
        >,
        // sorted by modified ancestor fee rate
        boost::multi_index::ordered_non_unique<
            // Reuse same tag from CTxMemPool's similar index
            boost::multi_index::tag<ancestor_score>,
            boost::multi_index::identity<CEDCTxMemPoolModifiedEntry>,
            EDCCompareModifiedEntry
        >
    >
> EDCindexed_modified_transaction_set;

typedef EDCindexed_modified_transaction_set::nth_index<0>::type::iterator EDCmodtxiter;
typedef EDCindexed_modified_transaction_set::index<ancestor_score>::type::iterator EDCmodtxscoreiter;

struct EDCupdate_for_parent_inclusion
{
    EDCupdate_for_parent_inclusion(CEDCTxMemPool::txiter it) : iter(it) {}

    void operator() (CEDCTxMemPoolModifiedEntry &e)
    {
        e.nModFeesWithAncestors -= iter->GetFee();
        e.nSizeWithAncestors -= iter->GetTxSize();
		e.nSigOpCostWithAncestors -= iter->GetSigOpCost();
    }

    CEDCTxMemPool::txiter iter;
};

/** Generate a new block, without valid proof-of-work */
class EDCBlockAssembler
{
private:
    // The constructed block template
    std::unique_ptr<CEDCBlockTemplate> pblocktemplate;

    // A convenience pointer that always refers to the CBlock in pblocktemplate
    CEDCBlock* pblock;

    // Configuration parameters for the block size
	bool fIncludeWitness;
    unsigned int nBlockMaxWeight, nBlockMaxSize;
    bool fNeedSizeAccounting;

    // Information on the current status of the block
	uint64_t nBlockWeight;
    uint64_t nBlockSize;
    uint64_t nBlockTx;
	uint64_t nBlockSigOpsCost;
    CAmount nFees;
    CEDCTxMemPool::setEntries inBlock;

    // Chain context for the block
    int nHeight;
    int64_t nLockTimeCutoff;
    const CEDCChainParams& chainparams;

    // Variables used for addPriorityTxs
    int lastFewTxs;
    bool blockFinished;

public:
    EDCBlockAssembler(const CEDCChainParams& chainparams);

    /** Construct a new block template with coinbase to scriptPubKeyIn */
    CEDCBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn);

private:
    // utility functions

    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();

    /** Add a tx to the block */
    void AddToBlock(CEDCTxMemPool::txiter iter);

    // Methods for how to add transactions to a block.

    /** Add transactions based on tx "priority" */
    void addPriorityTxs();

    /** Add transactions based on feerate including unconfirmed ancestors */
    void addPackageTxs();

    // helper function for addPriorityTxs

    /** Test if tx will still "fit" in the block */
    bool TestForBlock(CEDCTxMemPool::txiter iter);

    /** Test if tx still has unconfirmed parents not yet in block */
    bool isStillDependent(CEDCTxMemPool::txiter iter);

    // helper functions for addPackageTxs()
    /** Remove confirmed (inBlock) entries from given set */
    void onlyUnconfirmed(CEDCTxMemPool::setEntries& testSet);

    /** Test if a new package would "fit" in the block */
    bool TestPackage(uint64_t packageSize, int64_t packageSigOpsCost);

    /** Perform checks on each transaction in a package:
      * locktime, premature-witness, serialized size (if necessary)
      * These checks should always succeed, and they're here
      * only as an extra check in case of suboptimal node configuration */
    bool TestPackageTransactions(const CEDCTxMemPool::setEntries& package);

    /** Return true if given transaction from mapTx has already been evaluated,
      * or if the transaction's cached data in mapTx is incorrect. */
    bool SkipMapTxEntry(CEDCTxMemPool::txiter it, EDCindexed_modified_transaction_set &mapModifiedTx, CEDCTxMemPool::setEntries &failedTx);

    /** Sort the package in an order that is valid to appear in a block */
    void SortForBlock(const CEDCTxMemPool::setEntries& package, CEDCTxMemPool::txiter entry, std::vector<CEDCTxMemPool::txiter>& sortedEntries);

    /** Add descendants of given transactions to mapModifiedTx with ancestor
      * state updated assuming given transactions are inBlock. */
    void UpdatePackagesForAdded(const CEDCTxMemPool::setEntries& alreadyAdded, EDCindexed_modified_transaction_set &mapModifiedTx);
};

/** Modify the extranonce in a block */
void IncrementExtraNonce(CEDCBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
int64_t UpdateTime( CBlockHeader * pblock, const Consensus::Params & consensusParams, const CBlockIndex* pindexPrev);
