// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "policy/fees.h"
#include "amount.h"
#include "uint256.h"

#include <map>
#include <string>
#include <vector>

class CAutoFile;
class CFeeRate;
class CEDCTxMemPoolEntry;
class CEDCTxMemPool;

/** \class CEDCBlockPolicyEstimator
 * The BlockPolicyEstimator is used for estimating the fee or priority needed
 * for a transaction to be included in a block within a certain number of
 * blocks.
 *
 * At a high level the algorithm works by grouping transactions into buckets
 * based on having similar priorities or fees and then tracking how long it
 * takes transactions in the various buckets to be mined.  It operates under
 * the assumption that in general transactions of higher fee/priority will be
 * included in blocks before transactions of lower fee/priority.   So for
 * example if you wanted to know what fee you should put on a transaction to
 * be included in a block within the next 5 blocks, you would start by looking
 * at the bucket with the highest fee transactions and verifying that a
 * sufficiently high percentage of them were confirmed within 5 blocks and
 * then you would look at the next highest fee bucket, and so on, stopping at
 * the last bucket to pass the test.   The average fee of transactions in this
 * bucket will give you an indication of the lowest fee you can put on a
 * transaction and still have a sufficiently high chance of being confirmed
 * within your desired 5 blocks.
 *
 * When a transaction enters the mempool or is included within a block we
 * decide whether it can be used as a data point for fee estimation, priority
 * estimation or neither.  If the value of exactly one of those properties was
 * below the required minimum it can be used to estimate the other.  In
 * addition, if a priori our estimation code would indicate that the
 * transaction would be much more quickly included in a block because of one
 * of the properties compared to the other, we can also decide to use it as
 * an estimate for that property.
 *
 * Here is a brief description of the implementation for fee estimation.
 * When a transaction that counts for fee estimation enters the mempool, we
 * track the height of the block chain at entry.  Whenever a block comes in,
 * we count the number of transactions in each bucket and the total amount of fee
 * paid in each bucket. Then we calculate how many blocks Y it took each
 * transaction to be mined and we track an array of counters in each bucket
 * for how long it to took transactions to get confirmed from 1 to a max of 25
 * and we increment all the counters from Y up to 25. This is because for any
 * number Z>=Y the transaction was successfully mined within Z blocks.  We
 * want to save a history of this information, so at any time we have a
 * counter of the total number of transactions that happened in a given fee
 * bucket and the total number that were confirmed in each number 1-25 blocks
 * or less for any bucket.   We save this history by keeping an exponentially
 * decaying moving average of each one of these stats.  Furthermore we also
 * keep track of the number unmined (in mempool) transactions in each bucket
 * and for how many blocks they have been outstanding and use that to increase
 * the number of transactions we've seen in that fee bucket when calculating
 * an estimate for any number of confirmations below the number of blocks
 * they've been outstanding.
 */

/**
 *  We want to be able to estimate fees or priorities that are needed on tx's to be included in
 * a certain number of blocks.  Every time a block is added to the best chain, this class records
 * stats on the transactions included in that block
 */
class CEDCBlockPolicyEstimator
{
public:
    /** Create new BlockPolicyEstimator and initialize stats tracking classes with default values */
    CEDCBlockPolicyEstimator(const CFeeRate& minRelayFee);

    /** Process all the transactions that have been included in a block */
    void processBlock(unsigned int nBlockHeight,
                      std::vector<CEDCTxMemPoolEntry>& entries, bool fCurrentEstimate);

    /** Process a transaction confirmed in a block*/
    void processBlockTx(unsigned int nBlockHeight, const CEDCTxMemPoolEntry& entry);

    /** Process a transaction accepted to the mempool*/
    void processTransaction(const CEDCTxMemPoolEntry& entry, bool fCurrentEstimate);

    /** Remove a transaction from the mempool tracking stats*/
    void removeTx(uint256 hash);

    /** Is this transaction likely included in a block because of its fee?*/
    bool isFeeDataPoint(const CFeeRate &fee, double pri);

    /** Is this transaction likely included in a block because of its priority?*/
    bool isPriDataPoint(const CFeeRate &fee, double pri);

    /** Return a fee estimate */
    CFeeRate estimateFee(int confTarget);

    /** Estimate fee rate needed to get be included in a block within
     *  confTarget blocks. If no answer can be given at confTarget, return an
     *  estimate at the lowest target where one can be given.
     */
    CFeeRate estimateSmartFee(int confTarget, int *answerFoundAtTarget, const CEDCTxMemPool& pool);

    /** Return a priority estimate */
    double estimatePriority(int confTarget);

    /** Estimate priority needed to get be included in a block within
     *  confTarget blocks. If no answer can be given at confTarget, return an
     *  estimate at the lowest target where one can be given.
     */
    double estimateSmartPriority(int confTarget, int *answerFoundAtTarget, const CEDCTxMemPool& pool);

    /** Write estimation data to a file */
    void Write(CAutoFile& fileout);

    /** Read estimation data from a file */
    void Read(CAutoFile& filein);

private:
    CFeeRate minTrackedFee;    //!< Passed to constructor to avoid dependency on main
    double minTrackedPriority; //!< Set to AllowFreeThreshold
    unsigned int nBestSeenHeight;
    struct TxStatsInfo
    {
        TxConfirmStats *stats;
        unsigned int blockHeight;
        unsigned int bucketIndex;
        TxStatsInfo() : stats(NULL), blockHeight(0), bucketIndex(0) {}
    };

    // map of txids to information about that transaction
    std::map<uint256, TxStatsInfo> mapMemPoolTxs;

    /** Classes to track historical data on transaction confirmations */
    TxConfirmStats feeStats, priStats;

    /** Breakpoints to help determine whether a transaction was confirmed by priority or Fee */
    CFeeRate feeLikely, feeUnlikely;
    double priLikely, priUnlikely;
};

