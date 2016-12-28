// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/policy/edcfees.h"
#include "edc/policy/edcpolicy.h"

#include "amount.h"
#include "edc/primitives/edctransaction.h"
#include "random.h"
#include "streams.h"
#include "edc/edctxmempool.h"
#include "edc/edcutil.h"
#include "edc/edcparams.h"


void CEDCBlockPolicyEstimator::removeTx(uint256 hash)
{
    std::map<uint256, TxStatsInfo>::iterator pos = mapMemPoolTxs.find(hash);
    if (pos == mapMemPoolTxs.end()) 
	{
        edcLogPrint("estimatefee", "Blockpolicy error mempool tx %s not found for removeTx\n",
                 hash.ToString().c_str());
        return;
    }
    TxConfirmStats *stats = pos->second.stats;
    unsigned int entryHeight = pos->second.blockHeight;
    unsigned int bucketIndex = pos->second.bucketIndex;

    if (stats != NULL)
        stats->removeTx(entryHeight, nBestSeenHeight, bucketIndex);
    mapMemPoolTxs.erase(hash);
}

CEDCBlockPolicyEstimator::CEDCBlockPolicyEstimator(const CFeeRate& _minRelayFee)
    : nBestSeenHeight(0)
{
    minTrackedFee = _minRelayFee < CFeeRate(MIN_FEERATE) ? CFeeRate(MIN_FEERATE) : _minRelayFee;
    std::vector<double> vfeelist;
    for (double bucketBoundary = minTrackedFee.GetFeePerK(); bucketBoundary <= MAX_FEERATE; bucketBoundary *= FEE_SPACING) {
        vfeelist.push_back(bucketBoundary);
    }

    vfeelist.push_back(INF_FEERATE);
    feeStats.Initialize(vfeelist, MAX_BLOCK_CONFIRMS, DEFAULT_DECAY, "FeeRate");

    minTrackedPriority = AllowFreeThreshold() < MIN_PRIORITY ? MIN_PRIORITY : AllowFreeThreshold();
    std::vector<double> vprilist;

    for (double bucketBoundary = minTrackedPriority; bucketBoundary <= MAX_PRIORITY; bucketBoundary *= PRI_SPACING) 
	{
        vprilist.push_back(bucketBoundary);
    }
    vprilist.push_back(INF_PRIORITY);
    priStats.Initialize(vprilist, MAX_BLOCK_CONFIRMS, DEFAULT_DECAY, "Priority");

    feeUnlikely = CFeeRate(0);
    feeLikely = CFeeRate(INF_FEERATE);
    priUnlikely = 0;
    priLikely = INF_PRIORITY;
}

bool CEDCBlockPolicyEstimator::isFeeDataPoint(const CFeeRate &fee, double pri)
{
    if ((pri < minTrackedPriority && fee >= minTrackedFee) ||
        (pri < priUnlikely && fee > feeLikely)) 
	{
        return true;
    }
    return false;
}

bool CEDCBlockPolicyEstimator::isPriDataPoint(const CFeeRate &fee, double pri)
{
    if ((fee < minTrackedFee && pri >= minTrackedPriority) ||
        (fee < feeUnlikely && pri > priLikely)) 
	{
        return true;
    }
    return false;
}

void CEDCBlockPolicyEstimator::processTransaction(const CEDCTxMemPoolEntry& entry, bool fCurrentEstimate)
{
    unsigned int txHeight = entry.GetHeight();
    uint256 hash = entry.GetTx().GetHash();

    if (mapMemPoolTxs[hash].stats != NULL) 
	{
        edcLogPrint("estimatefee", "Blockpolicy error mempool tx %s already being tracked\n",
                 hash.ToString().c_str());
	return;
    }

    if (txHeight < nBestSeenHeight) 
	{
        // Ignore side chains and re-orgs; assuming they are random they don't
        // affect the estimate.  We'll potentially double count transactions in 1-block reorgs.
        return;
    }

    // Only want to be updating estimates when our blockchain is synced,
    // otherwise we'll miscalculate how many blocks its taking to get included.
    if (!fCurrentEstimate)
        return;

    if (!entry.WasClearAtEntry()) 
	{
        // This transaction depends on other transactions in the mempool to
        // be included in a block before it will be able to be included, so
        // we shouldn't include it in our calculations
        return;
    }

    // Fees are stored and reported as BTC-per-kb:
    CFeeRate feeRate(entry.GetFee(), entry.GetTxSize());

    // Want the priority of the tx at confirmation. However we don't know
    // what that will be and its too hard to continue updating it
    // so use starting priority as a proxy
    double curPri = entry.GetPriority(txHeight);
    mapMemPoolTxs[hash].blockHeight = txHeight;

    edcLogPrint("estimatefee", "Blockpolicy mempool tx %s ", hash.ToString().substr(0,10));
    // Record this as a priority estimate
    if (entry.GetFee() == 0 || isPriDataPoint(feeRate, curPri)) 
	{
        mapMemPoolTxs[hash].stats = &priStats;
        mapMemPoolTxs[hash].bucketIndex =  priStats.NewTx(txHeight, curPri);
    }
    // Record this as a fee estimate
    else if (isFeeDataPoint(feeRate, curPri)) 
	{
        mapMemPoolTxs[hash].stats = &feeStats;
        mapMemPoolTxs[hash].bucketIndex = feeStats.NewTx(txHeight, (double)feeRate.GetFeePerK());
    }
    else 
	{
        edcLogPrint("estimatefee", "not adding");
    }
    edcLogPrint("estimatefee", "\n");
}

void CEDCBlockPolicyEstimator::processBlockTx(unsigned int nBlockHeight, const CEDCTxMemPoolEntry& entry)
{
    if (!entry.WasClearAtEntry()) 
	{
        // This transaction depended on other transactions in the mempool to
        // be included in a block before it was able to be included, so
        // we shouldn't include it in our calculations
        return;
    }

    // How many blocks did it take for miners to include this transaction?
    // blocksToConfirm is 1-based, so a transaction included in the earliest
    // possible block has confirmation count of 1
    int blocksToConfirm = nBlockHeight - entry.GetHeight();
    if (blocksToConfirm <= 0) 
	{
        // This can't happen because we don't process transactions from a block with a height
        // lower than our greatest seen height
        edcLogPrint("estimatefee", "Blockpolicy error Transaction had negative blocksToConfirm\n");
        return;
    }

    // Fees are stored and reported as BTC-per-kb:
    CFeeRate feeRate(entry.GetFee(), entry.GetTxSize());

    // Want the priority of the tx at confirmation.  The priority when it
    // entered the mempool could easily be very small and change quickly
    double curPri = entry.GetPriority(nBlockHeight);

    // Record this as a priority estimate
    if (entry.GetFee() == 0 || isPriDataPoint(feeRate, curPri)) 
	{
        priStats.Record(blocksToConfirm, curPri);
    }
    // Record this as a fee estimate
    else if (isFeeDataPoint(feeRate, curPri)) 
	{
        feeStats.Record(blocksToConfirm, (double)feeRate.GetFeePerK());
    }
}

void CEDCBlockPolicyEstimator::processBlock(
						 unsigned int nBlockHeight,
	std::vector<CEDCTxMemPoolEntry> & entries, 
								 bool fCurrentEstimate)
{
    if (nBlockHeight <= nBestSeenHeight) 
	{
        // Ignore side chains and re-orgs; assuming they are random
        // they don't affect the estimate.
        // And if an attacker can re-org the chain at will, then
        // you've got much bigger problems than "attacker can influence
        // transaction fees."
        return;
    }
    nBestSeenHeight = nBlockHeight;

    // Only want to be updating estimates when our blockchain is synced,
    // otherwise we'll miscalculate how many blocks its taking to get included.
    if (!fCurrentEstimate)
        return;

    // Update the dynamic cutoffs
    // a fee/priority is "likely" the reason your tx was included in a block if >85% of such tx's
    // were confirmed in 2 blocks and is "unlikely" if <50% were confirmed in 10 blocks
    edcLogPrint("estimatefee", "Blockpolicy recalculating dynamic cutoffs:\n");
    priLikely = priStats.EstimateMedianVal(2, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT, true, nBlockHeight);
    if (priLikely == -1)
        priLikely = INF_PRIORITY;

    double feeLikelyEst = feeStats.EstimateMedianVal(2, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT, true, nBlockHeight);
    if (feeLikelyEst == -1)
        feeLikely = CFeeRate(INF_FEERATE);
    else
        feeLikely = CFeeRate(feeLikelyEst);

    priUnlikely = priStats.EstimateMedianVal(10, SUFFICIENT_PRITXS, UNLIKELY_PCT, false, nBlockHeight);
    if (priUnlikely == -1)
        priUnlikely = 0;

    double feeUnlikelyEst = feeStats.EstimateMedianVal(10, SUFFICIENT_FEETXS, UNLIKELY_PCT, false, nBlockHeight);
    if (feeUnlikelyEst == -1)
        feeUnlikely = CFeeRate(0);
    else
        feeUnlikely = CFeeRate(feeUnlikelyEst);

    // Clear the current block states
    feeStats.ClearCurrent(nBlockHeight);
    priStats.ClearCurrent(nBlockHeight);

    // Repopulate the current block states
    for (unsigned int i = 0; i < entries.size(); i++)
        processBlockTx(nBlockHeight, entries[i]);

    // Update all exponential averages with the current block states
    feeStats.UpdateMovingAverages();
    priStats.UpdateMovingAverages();

    edcLogPrint("estimatefee", "Blockpolicy after updating estimates for %u confirmed entries, new mempool map size %u\n",
             entries.size(), mapMemPoolTxs.size());
}

CFeeRate CEDCBlockPolicyEstimator::estimateFee(int confTarget)
{
    // Return failure if trying to analyze a target we're not tracking
    if (confTarget <= 0 || (unsigned int)confTarget > feeStats.GetMaxConfirms())
        return CFeeRate(0);

    double median = feeStats.EstimateMedianVal(confTarget, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT, true, nBestSeenHeight);

    if (median < 0)
        return CFeeRate(0);

    return CFeeRate(median);
}

CFeeRate CEDCBlockPolicyEstimator::estimateSmartFee(
	  				  int confTarget, 
					int * answerFoundAtTarget, 
	const CEDCTxMemPool & pool)
{
    if (answerFoundAtTarget)
        *answerFoundAtTarget = confTarget;
    // Return failure if trying to analyze a target we're not tracking
    if (confTarget <= 0 || (unsigned int)confTarget > feeStats.GetMaxConfirms())
        return CFeeRate(0);

    double median = -1;
    while (median < 0 && (unsigned int)confTarget <= feeStats.GetMaxConfirms()) 
	{
        median = feeStats.EstimateMedianVal(confTarget++, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT, true, nBestSeenHeight);
    }

    if (answerFoundAtTarget)
        *answerFoundAtTarget = confTarget - 1;

	EDCparams & params = EDCparams::singleton();
    // If mempool is limiting txs , return at least the min fee from the mempool
    CAmount minPoolFee = pool.GetMinFee(params.maxmempool * 1000000).GetFeePerK();
    if (minPoolFee > 0 && minPoolFee > median)
        return CFeeRate(minPoolFee);

    if (median < 0)
        return CFeeRate(0);

    return CFeeRate(median);
}

double CEDCBlockPolicyEstimator::estimatePriority(int confTarget)
{
    // Return failure if trying to analyze a target we're not tracking
    if (confTarget <= 0 || (unsigned int)confTarget > priStats.GetMaxConfirms())
        return -1;

    return priStats.EstimateMedianVal(confTarget, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT, true, nBestSeenHeight);
}

double CEDCBlockPolicyEstimator::estimateSmartPriority(
					  int confTarget, 
					int * answerFoundAtTarget, 
	const CEDCTxMemPool & pool)
{
    if (answerFoundAtTarget)
        *answerFoundAtTarget = confTarget;
    // Return failure if trying to analyze a target we're not tracking
    if (confTarget <= 0 || (unsigned int)confTarget > priStats.GetMaxConfirms())
        return -1;

    // If mempool is limiting txs, no priority txs are allowed
	EDCparams & params = EDCparams::singleton();
    CAmount minPoolFee = pool.GetMinFee(params.maxmempool * 1000000).GetFeePerK();
    if (minPoolFee > 0)
        return INF_PRIORITY;

    double median = -1;
    while (median < 0 && (unsigned int)confTarget <= priStats.GetMaxConfirms()) 
	{
        median = priStats.EstimateMedianVal(confTarget++, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT, true, nBestSeenHeight);
    }

    if (answerFoundAtTarget)
        *answerFoundAtTarget = confTarget - 1;

    return median;
}

void CEDCBlockPolicyEstimator::Write(CAutoFile& fileout)
{
    fileout << nBestSeenHeight;
    feeStats.Write(fileout);
    priStats.Write(fileout);
}

void CEDCBlockPolicyEstimator::Read(CAutoFile& filein)
{
    int nFileBestSeenHeight;
    filein >> nFileBestSeenHeight;
    feeStats.Read(filein);
    priStats.Read(filein);
    nBestSeenHeight = nFileBestSeenHeight;
}
