// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/edcminer.h"

#include "amount.h"
#include "chain.h"
#include "edcchainparams.h"
#include "edc/edccoins.h"
#include "edc/consensus/edcconsensus.h"
#include "edc/consensus/edcmerkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "edc/edcmain.h"
#include "edc/edcnet.h"
#include "edc/policy/edcpolicy.h"
#include "pow.h"
#include "edc/primitives/edctransaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "edctxmempool.h"
#include "edcutil.h"
#include "utilmoneystr.h"
#include "edcvalidationinterface.h"
#include "edcapp.h"
#include "edcparams.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// EquibitMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CEDCTxMemPool::txiter a, const CEDCTxMemPool::txiter b)
    {
        return CompareEDCTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

int64_t edcGetAdjustedTime();

int64_t edcUpdateTime(
			   CBlockHeader * pblock, 
	const Consensus::Params & consensusParams, 
		  const CBlockIndex * pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, edcGetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

EDCBlockAssembler::EDCBlockAssembler(const CEDCChainParams& _chainparams)
    : chainparams(_chainparams)
{
	EDCparams & params = EDCparams::singleton();

    // Block resource limits
    // If neither -eb_blockmaxsize or -eb_blockmaxweigt is given, limit to 
	// EDC_DEFAULT_BLOCK_MAX_*
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    nBlockMaxWeight = EDC_DEFAULT_BLOCK_MAX_WEIGHT;
    nBlockMaxSize = DEFAULT_BLOCK_MAX_SIZE;
	bool fWeightSet = false;
	if(mapArgs.count("-eb_blockmaxweight"))
	{
		nBlockMaxWeight = params.blockmaxweight;
		nBlockMaxSize = EDC_MAX_BLOCK_SERIALIZED_SIZE;
		fWeightSet = true;
	}
    if (mapArgs.count("-eb_blockmaxsize")) 
	{
        nBlockMaxSize = params.blockmaxsize;
        if (!fWeightSet) 
		{
            nBlockMaxWeight = nBlockMaxSize * WITNESS_SCALE_FACTOR;
        }
    }

    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max((unsigned int)4000, std::min((unsigned int)(EDC_MAX_BLOCK_WEIGHT-4000), nBlockMaxWeight));

    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(EDC_MAX_BLOCK_SERIALIZED_SIZE-1000), nBlockMaxSize));

    // Whether we need to account for byte usage (in addition to weight usage)
    fNeedSizeAccounting = (nBlockMaxSize < EDC_MAX_BLOCK_SERIALIZED_SIZE-1000);
}

void EDCBlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockSize = 1000;
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
	fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;

    lastFewTxs = 0;
    blockFinished = false;
}

CAmount edcGetBlockSubsidy(
                          int nHeight,
    const Consensus::Params & consensusParams )
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;

    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 50 * COIN;

    // Subsidy is cut in half every 210,000 blocks which will occur
    // approximately every 4 years.
    nSubsidy >>= halvings;

	// The subsidy for the first mined block is 1,000,000 EDC
	if( nHeight == 1 )
		nSubsidy = 1000000 * COIN;

    return nSubsidy;
}

CEDCBlockTemplate* EDCBlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn)
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    resetBlock();

    pblocktemplate.reset(new CEDCBlockTemplate());

    if(!pblocktemplate.get())
        return NULL;

    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CEDCTransaction());
    pblocktemplate->vTxFees.push_back(-1); // updated at end
	pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(EDC_cs_main, theApp.mempool().cs);
    CBlockIndex* pindexPrev = theApp.chainActive().Tip();
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = edcComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = params.blockversion;

    pblock->nTime = edcGetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & EDC_LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus());

    addPriorityTxs();
    addPackageTxs();

	theApp.lastBlockTx( nBlockTx );
	theApp.lastBlockSize( nBlockSize );
	theApp.lastBlockWeight( nBlockWeight );

    edcLogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOpsCost);

    // Create coinbase transaction.
    CEDCMutableTransaction coinbaseTx;

    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue = nFees + edcGetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;

    pblock->vtx[0] = coinbaseTx;
    pblocktemplate->vchCoinbaseCommitment = edcGenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
    pblocktemplate->vTxFees[0] = -nFees;

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    edcUpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
	pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * edcGetLegacySigOpCount(pblock->vtx[0]);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }

    return pblocktemplate.release();
}

bool EDCBlockAssembler::isStillDependent(CEDCTxMemPool::txiter iter)
{
	EDCapp & theApp = EDCapp::singleton();
    BOOST_FOREACH(CEDCTxMemPool::txiter parent, theApp.mempool().GetMemPoolParents(iter))
    {
        if (!inBlock.count(parent)) 
		{
            return true;
        }
    }
    return false;
}

void EDCBlockAssembler::onlyUnconfirmed(CEDCTxMemPool::setEntries& testSet)
{
    for (CEDCTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) 
	{
        // Only test txs not already in the block
        if (inBlock.count(*iit)) 
		{
            testSet.erase(iit++);
        }
        else 
		{
            iit++;
        }
    }
}

bool EDCBlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost)
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
	if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
// - serialized size (in case -blockmaxsize is in use)
bool EDCBlockAssembler::TestPackageTransactions(const CEDCTxMemPool::setEntries& package)
{
	uint64_t nPotentialBlockSize = nBlockSize; // only used with fNeedSizeAccounting
    BOOST_FOREACH (const CEDCTxMemPool::txiter it, package) 
	{
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && !it->GetTx().wit.IsNull())
            return false;
        if (fNeedSizeAccounting) 
		{
            uint64_t nTxSize = ::GetSerializeSize(it->GetTx(), SER_NETWORK, PROTOCOL_VERSION);
            if (nPotentialBlockSize + nTxSize >= nBlockMaxSize) 
			{
                return false;
            }
            nPotentialBlockSize += nTxSize;
        }
    }
    return true;
}

bool EDCBlockAssembler::TestForBlock(CEDCTxMemPool::txiter iter)
{
	if (nBlockWeight + iter->GetTxWeight() >= nBlockMaxWeight)
	{
        // If the block is so close to full that no more txs will fit
        // or if we've tried more than 50 times to fill remaining space
        // then flag that the block is finished
		if (nBlockWeight >  nBlockMaxWeight - 400 || lastFewTxs > 50)
		{
             blockFinished = true;
             return false;
        }

		// Once we're within 4000 weight of a full block, only look at 50 more txs
        // to try to fill the remaining space.
		if (nBlockWeight > nBlockMaxWeight - 4000)
		{
            lastFewTxs++;
        }
        return false;
    }

    if (fNeedSizeAccounting) 
	{
        if (nBlockSize + GetSerializeSize(iter->GetTx(), SER_NETWORK, PROTOCOL_VERSION) >= 
		nBlockMaxSize) 
		{
            if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) 
			{
                 blockFinished = true;
                 return false;
            }
            if (nBlockSize > nBlockMaxSize - 1000) 
			{
                lastFewTxs++;
            }
            return false;
        }
    }

    if (nBlockSigOpsCost + iter->GetSigOpCost() >= EDC_MAX_BLOCK_SIGOPS_COST)
	{
        // If the block has room for no more sig ops then
        // flag that the block is finished
		if (nBlockSigOpsCost > EDC_MAX_BLOCK_SIGOPS_COST - 8)
		{
            blockFinished = true;
            return false;
        }
        // Otherwise attempt to find another tx with fewer sigops
        // to put in the block.
        return false;
    }

    // Must check that lock times are still valid
    // This can be removed once MTP is always enforced
    // as long as reorgs keep the mempool consistent.
    if (!IsFinalTx(iter->GetTx(), nHeight, nLockTimeCutoff))
        return false;

    return true;
}

void EDCBlockAssembler::UpdatePackagesForAdded(
		const CEDCTxMemPool::setEntries & alreadyAdded,
	EDCindexed_modified_transaction_set & mapModifiedTx)
{
	EDCapp & theApp = EDCapp::singleton();

    BOOST_FOREACH(const CEDCTxMemPool::txiter it, alreadyAdded) 
	{
        CEDCTxMemPool::setEntries descendants;
        theApp.mempool().CalculateDescendants(it, descendants);

        // Insert all descendants (not yet in block) into the modified set
        BOOST_FOREACH(CEDCTxMemPool::txiter desc, descendants) 
		{
            if (alreadyAdded.count(desc))
                continue;

            EDCmodtxiter mit = mapModifiedTx.find(desc);

            if (mit == mapModifiedTx.end()) 
			{
                CEDCTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
				modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } 
			else 
			{
                mapModifiedTx.modify(mit, EDCupdate_for_parent_inclusion(it));
            }
        }
    }
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool EDCBlockAssembler::SkipMapTxEntry(
					CEDCTxMemPool::txiter it, 
	EDCindexed_modified_transaction_set & mapModifiedTx, 
			  CEDCTxMemPool::setEntries & failedTx)
{
	EDCapp & theApp = EDCapp::singleton();

    assert (it != theApp.mempool().mapTx.end());
    if (mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it))
        return true;
    return false;
}

void EDCBlockAssembler::SortForBlock(
	const CEDCTxMemPool::setEntries & package, 
				CEDCTxMemPool::txiter entry, 
 std::vector<CEDCTxMemPool::txiter> & sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), EDCCompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void EDCBlockAssembler::addPackageTxs()
{
	EDCapp & theApp = EDCapp::singleton();

    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    EDCindexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CEDCTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CEDCTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = 
		theApp.mempool().mapTx.get<ancestor_score>().begin();
    CEDCTxMemPool::txiter iter;

    while (mi != theApp.mempool().mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != theApp.mempool().mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(theApp.mempool().mapTx.project<0>(mi), mapModifiedTx, failedTx)) 
		{
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        EDCmodtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == theApp.mempool().mapTx.get<ancestor_score>().end()) 
		{
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } 
		else 
		{

            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = theApp.mempool().mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    EDCCompareModifiedEntry()(*modit, CEDCTxMemPoolModifiedEntry(iter))) 
			{
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } 
			else 
			{
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
		int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();

        if (fUsingModified) 
		{
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
			packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

		if (packageFees < theApp.minRelayTxFee().GetFee(packageSize))
		{
            // Everything else we might consider has a lower fee rate
            return;
        }

		if (!TestPackage(packageSize, packageSigOpsCost))
		{
            if (fUsingModified) 
			{
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        CEDCTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        theApp.mempool().CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, 
			nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
		if (!TestPackageTransactions(ancestors))
		{
            if (fUsingModified) 
			{
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // Package can be added. Sort the entries in a valid order.
        vector<CEDCTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, iter, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) 
		{
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        // Update transactions that depend on each of these
        UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void EDCBlockAssembler::AddToBlock(CEDCTxMemPool::txiter iter)
{
    pblock->vtx.push_back(iter->GetTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());

    if (fNeedSizeAccounting) 
	{
        nBlockSize += ::GetSerializeSize(iter->GetTx(), SER_NETWORK, PROTOCOL_VERSION);
    }

    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
	nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

	EDCparams & params = EDCparams::singleton();
    bool fPrintPriority = params.printpriority;

	EDCapp & theApp = EDCapp::singleton();

    if (fPrintPriority) 
	{
        double dPriority = iter->GetPriority(nHeight);
        CAmount dummy;
        theApp.mempool().ApplyDeltas(iter->GetTx().GetHash(), dPriority, dummy);

        edcLogPrintf("priority %.1f fee %s txid %s\n",
                  dPriority,
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

void EDCBlockAssembler::addPriorityTxs()
{
	EDCparams & params = EDCparams::singleton();

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = params.blockprioritysize;
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    if (nBlockPrioritySize == 0) 
	{
        return;
    }

	EDCapp & theApp = EDCapp::singleton();

	bool fSizeAccounting = fNeedSizeAccounting;
    fNeedSizeAccounting = true;

    // This vector will be sorted into a priority queue:
    vector<EDCTxCoinAgePriority> vecPriority;
    EDCTxCoinAgePriorityCompare pricomparer;

    std::map<CEDCTxMemPool::txiter, double, CEDCTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CEDCTxMemPool::txiter, double, 
					CEDCTxMemPool::CompareIteratorByHash>::iterator waitPriIter;

    double actualPriority = -1;

    vecPriority.reserve(theApp.mempool().mapTx.size());

    for (CEDCTxMemPool::indexed_transaction_set::iterator mi = theApp.mempool().mapTx.begin();
         mi != theApp.mempool().mapTx.end(); ++mi)
    {
        double dPriority = mi->GetPriority(nHeight);
        CAmount dummy;
        theApp.mempool().ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
        vecPriority.push_back(EDCTxCoinAgePriority(dPriority, mi));
    }
    std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);

    CEDCTxMemPool::txiter iter;
    while (!vecPriority.empty() && !blockFinished) 
	{ 
		// add a tx from priority queue to fill the blockprioritysize
        iter = vecPriority.front().second;
        actualPriority = vecPriority.front().first;

        std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        vecPriority.pop_back();

        // If tx already in block, skip
        if (inBlock.count(iter)) 
		{
            assert(false); // shouldn't happen for priority txs
            continue;
        }

        // cannot accept witness transactions into a non-witness block
        if (!fIncludeWitness && !iter->GetTx().wit.IsNull())
            continue;

        // If tx is dependent on other mempool txs which haven't yet been included
        // then put it in the waitSet
        if (isStillDependent(iter)) 
		{
            waitPriMap.insert(std::make_pair(iter, actualPriority));
            continue;
        }

        // If this tx fits in the block add it, otherwise keep looping
        if (TestForBlock(iter)) 
		{
            AddToBlock(iter);

            // If now that this txs is added we've surpassed our desired priority size
            // or have dropped below the AllowFreeThreshold, then we're done adding priority txs
			if (nBlockSize >= nBlockPrioritySize || !AllowFree(actualPriority))
			{
                break;
            }

            // This tx was successfully added, so
            // add transactions that depend on this one to the priority queue to try again
            BOOST_FOREACH(CEDCTxMemPool::txiter child,theApp.mempool().GetMemPoolChildren(iter))
            {
                waitPriIter wpiter = waitPriMap.find(child);

                if (wpiter != waitPriMap.end()) 
				{
                    vecPriority.push_back(EDCTxCoinAgePriority(wpiter->second,child));
                    std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                    waitPriMap.erase(wpiter);
                }
            }
        }
    }
	fNeedSizeAccounting = fSizeAccounting;
}

void IncrementExtraNonce(
	CEDCBlock* pblock, 
	const CBlockIndex* pindexPrev, 
	unsigned int& nExtraNonce )
{
	EDCapp & theApp = EDCapp::singleton();

    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CEDCMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + theApp.coinbaseFlags();
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = edcBlockMerkleRoot(*pblock);
}
