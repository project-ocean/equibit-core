// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/edccoins.h"

#include "memusage.h"
#include "random.h"

#include <assert.h>

/**
 * calculate number of bytes for the bitmask, and its number of non-zero bytes
 * each bit in the bitmask represents the availability of one output, but the
 * availabilities of the first two outputs are encoded separately
 */
void CEDCCoins::CalcMaskSize(unsigned int &nBytes, unsigned int &nNonzeroBytes) const 
{
    unsigned int nLastUsedByte = 0;
    for (unsigned int b = 0; 2+b*8 < vout.size(); b++) 
	{
        bool fZero = true;
        for (unsigned int i = 0; i < 8 && 2+b*8+i < vout.size(); i++) 
		{
            if (!vout[2+b*8+i].IsNull()) 
			{
                fZero = false;
                continue;
            }
        }
        if (!fZero) 
		{
            nLastUsedByte = b + 1;
            nNonzeroBytes++;
        }
    }
    nBytes += nLastUsedByte;
}

bool CEDCCoins::Spend(uint32_t nPos) 
{
    if (nPos >= vout.size() || vout[nPos].IsNull())
        return false;
    vout[nPos].SetNull();
    Cleanup();
    return true;
}

bool CEDCCoinsView::GetCoins(const uint256 &txid, CEDCCoins &coins) const 
{ 
	return false; 
}

bool CEDCCoinsView::HaveCoins(const uint256 &txid) const 
{ 
	return false; 
}

uint256 CEDCCoinsView::GetBestBlock() const 
{ 
	return uint256(); 
}

bool CEDCCoinsView::BatchWrite(CEDCCoinsMap &mapCoins, const uint256 &hashBlock)
{ 
	return false; 
}

CEDCCoinsViewCursor *CEDCCoinsView::Cursor() const 
{ 
	return 0; 
}


CEDCCoinsViewBacked::CEDCCoinsViewBacked(CEDCCoinsView *viewIn) : base(viewIn) 
{ }

bool CEDCCoinsViewBacked::GetCoins(const uint256 &txid, CEDCCoins &coins) const
{
	return base->GetCoins(txid, coins); 
}

bool CEDCCoinsViewBacked::HaveCoins(const uint256 &txid) const 
{ 
	return base->HaveCoins(txid); 
}

uint256 CEDCCoinsViewBacked::GetBestBlock() const 
{ 
	return base->GetBestBlock(); 
}

void CEDCCoinsViewBacked::SetBackend(CEDCCoinsView &viewIn) 
{ 
	base = &viewIn; 
}

bool CEDCCoinsViewBacked::BatchWrite(
	CEDCCoinsMap & mapCoins, 
	const uint256 & hashBlock) 
{ 
	return base->BatchWrite(mapCoins, hashBlock); 
}

CEDCCoinsViewCursor *CEDCCoinsViewBacked::Cursor() const 
{ 
	return base->Cursor(); 
}

CEDCCoinsViewCache::CEDCCoinsViewCache(CEDCCoinsView *baseIn) : 
	CEDCCoinsViewBacked(baseIn), hasModifier(false), cachedCoinsUsage(0) 
{ }

CEDCCoinsViewCache::~CEDCCoinsViewCache()
{
    assert(!hasModifier);
}

size_t CEDCCoinsViewCache::DynamicMemoryUsage() const 
{
    return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage;
}

CEDCCoinsMap::const_iterator CEDCCoinsViewCache::FetchCoins(const uint256 &txid) const 
{
    CEDCCoinsMap::iterator it = cacheCoins.find(txid);
    if (it != cacheCoins.end())
        return it;
    CEDCCoins tmp;
    if (!base->GetCoins(txid, tmp))
        return cacheCoins.end();

    CEDCCoinsMap::iterator ret = cacheCoins.
		insert(std::make_pair(txid, CEDCCoinsCacheEntry())).first;
    tmp.swap(ret->second.coins);

    if (ret->second.coins.IsPruned()) 
	{
        // The parent only has an empty entry for this txid; we can consider our
        // version as fresh.
        ret->second.flags = CEDCCoinsCacheEntry::FRESH;
    }
    cachedCoinsUsage += ret->second.coins.DynamicMemoryUsage();

    return ret;
}

bool CEDCCoinsViewCache::GetCoins(const uint256 &txid, CEDCCoins &coins) const 
{
    CEDCCoinsMap::const_iterator it = FetchCoins(txid);
    if (it != cacheCoins.end()) 
	{
        coins = it->second.coins;
        return true;
    }
    return false;
}

CEDCCoinsModifier CEDCCoinsViewCache::ModifyCoins(const uint256 &txid) 
{
    assert(!hasModifier);
    std::pair<CEDCCoinsMap::iterator, bool> ret = 
		cacheCoins.insert(std::make_pair(txid, CEDCCoinsCacheEntry()));
    size_t cachedCoinUsage = 0;

    if (ret.second) 
	{
        if (!base->GetCoins(txid, ret.first->second.coins)) 
		{
            // The parent view does not have this entry; mark it as fresh.
            ret.first->second.coins.Clear();
            ret.first->second.flags = CEDCCoinsCacheEntry::FRESH;
        } 
		else if (ret.first->second.coins.IsPruned()) 
		{
            // The parent view only has a pruned entry for this; mark it as fresh.
            ret.first->second.flags = CEDCCoinsCacheEntry::FRESH;
        }
    } 
	else 
	{
        cachedCoinUsage = ret.first->second.coins.DynamicMemoryUsage();
    }

    // Assume that whenever ModifyCoins is called, the entry will be modified.
    ret.first->second.flags |= CEDCCoinsCacheEntry::DIRTY;

    return CEDCCoinsModifier(*this, ret.first, cachedCoinUsage);
}

// ModifyNewCoins has to know whether the new outputs its creating are for a
// coinbase or not.  If they are for a coinbase, it can not mark them as fresh.
// This is to ensure that the historical duplicate coinbases before BIP30 was
// in effect will still be properly overwritten when spent.
CEDCCoinsModifier CEDCCoinsViewCache::ModifyNewCoins(const uint256 &txid, bool coinbase) 
{
    assert(!hasModifier);
    std::pair<CEDCCoinsMap::iterator, bool> ret = 
		cacheCoins.insert(std::make_pair(txid, CEDCCoinsCacheEntry()));
    ret.first->second.coins.Clear();

    if (!coinbase) 
	{
        ret.first->second.flags = CEDCCoinsCacheEntry::FRESH;
    }
    ret.first->second.flags |= CEDCCoinsCacheEntry::DIRTY;

    return CEDCCoinsModifier(*this, ret.first, 0);
}

const CEDCCoins* CEDCCoinsViewCache::AccessCoins(const uint256 &txid) const 
{
    CEDCCoinsMap::const_iterator it = FetchCoins(txid);

    if (it == cacheCoins.end()) 
	{
        return NULL;
    } 
	else 
	{
        return &it->second.coins;
    }
}

bool CEDCCoinsViewCache::HaveCoins(const uint256 &txid) const 
{
    CEDCCoinsMap::const_iterator it = FetchCoins(txid);
    // We're using vtx.empty() instead of IsPruned here for performance reasons,
    // as we only care about the case where a transaction was replaced entirely
    // in a reorganization (which wipes vout entirely, as opposed to spending
    // which just cleans individual outputs).
    return (it != cacheCoins.end() && !it->second.coins.vout.empty());
}

bool CEDCCoinsViewCache::HaveCoinsInCache(const uint256 &txid) const 
{
    CEDCCoinsMap::const_iterator it = cacheCoins.find(txid);
    return it != cacheCoins.end();
}

uint256 CEDCCoinsViewCache::GetBestBlock() const 
{
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CEDCCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn) 
{
    hashBlock = hashBlockIn;
}

bool CEDCCoinsViewCache::BatchWrite(CEDCCoinsMap &mapCoins, const uint256 &hashBlockIn) 
{
    assert(!hasModifier);
    for (CEDCCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) 
	{
        if (it->second.flags & CEDCCoinsCacheEntry::DIRTY) 
		{ // Ignore non-dirty entries (optimization).
            CEDCCoinsMap::iterator itUs = cacheCoins.find(it->first);
            if (itUs == cacheCoins.end()) 
			{
                // The parent cache does not have an entry, while the child does
                // We can ignore it if it's both FRESH and pruned in the child
                if (!(it->second.flags & CEDCCoinsCacheEntry::FRESH && it->second.coins.IsPruned())) 
				{
                    // Otherwise we will need to create it in the parent
                    // and move the data up and mark it as dirty
                    CEDCCoinsCacheEntry& entry = cacheCoins[it->first];
                    entry.coins.swap(it->second.coins);
                    cachedCoinsUsage += entry.coins.DynamicMemoryUsage();
                    entry.flags = CEDCCoinsCacheEntry::DIRTY;
                    // We can mark it FRESH in the parent if it was FRESH in the child
                    // Otherwise it might have just been flushed from the parent's cache
                    // and already exist in the grandparent
                    if (it->second.flags & CEDCCoinsCacheEntry::FRESH)
                        entry.flags |= CEDCCoinsCacheEntry::FRESH;
                }
            } 
			else 
			{
                // Found the entry in the parent cache
                if ((itUs->second.flags & CEDCCoinsCacheEntry::FRESH) && it->second.coins.IsPruned()) 
				{
                    // The grandparent does not have an entry, and the child is
                    // modified and being pruned. This means we can just delete
                    // it from the parent.
                    cachedCoinsUsage -= itUs->second.coins.DynamicMemoryUsage();
                    cacheCoins.erase(itUs);
                } 
				else 
				{
                    // A normal modification.
                    cachedCoinsUsage -= itUs->second.coins.DynamicMemoryUsage();
                    itUs->second.coins.swap(it->second.coins);
                    cachedCoinsUsage += itUs->second.coins.DynamicMemoryUsage();
                    itUs->second.flags |= CEDCCoinsCacheEntry::DIRTY;
                }
            }
        }
        CEDCCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }
    hashBlock = hashBlockIn;
    return true;
}

bool CEDCCoinsViewCache::Flush() 
{
    bool fOk = base->BatchWrite(cacheCoins, hashBlock);
    cacheCoins.clear();
    cachedCoinsUsage = 0;
    return fOk;
}

void CEDCCoinsViewCache::Uncache(const uint256& hash)
{
    CEDCCoinsMap::iterator it = cacheCoins.find(hash);
    if (it != cacheCoins.end() && it->second.flags == 0) 
	{
        cachedCoinsUsage -= it->second.coins.DynamicMemoryUsage();
        cacheCoins.erase(it);
    }
}

unsigned int CEDCCoinsViewCache::GetCacheSize() const 
{
    return cacheCoins.size();
}

const CEDCTxOut &CEDCCoinsViewCache::GetOutputFor(const CEDCTxIn& input) const
{
    const CEDCCoins* coins = AccessCoins(input.prevout.hash);
    assert(coins && coins->IsAvailable(input.prevout.n));
    return coins->vout[input.prevout.n];
}

CAmount CEDCCoinsViewCache::GetValueIn(const CEDCTransaction& tx) const
{
    if (tx.IsCoinBase())
        return 0;

    CAmount nResult = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        nResult += GetOutputFor(tx.vin[i]).nValue;

    return nResult;
}

bool CEDCCoinsViewCache::HaveInputs(const CEDCTransaction& tx) const
{
    if (!tx.IsCoinBase()) 
	{
        for (unsigned int i = 0; i < tx.vin.size(); i++) 
		{
            const COutPoint &prevout = tx.vin[i].prevout;
            const CEDCCoins* coins = AccessCoins(prevout.hash);
            if (!coins || !coins->IsAvailable(prevout.n)) 
			{
                return false;
            }
        }
    }
    return true;
}

double CEDCCoinsViewCache::GetPriority(
	const CEDCTransaction & tx, 
						int nHeight, 
				  CAmount & inChainInputValue) const
{
    inChainInputValue = 0;
    if (tx.IsCoinBase())
        return 0.0;
    double dResult = 0.0;
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin)
    {
        const CEDCCoins* coins = AccessCoins(txin.prevout.hash);
        assert(coins);

        if (!coins->IsAvailable(txin.prevout.n)) 
			continue;
        if (coins->nHeight <= nHeight) 
		{
            dResult += coins->vout[txin.prevout.n].nValue * (nHeight-coins->nHeight);
            inChainInputValue += coins->vout[txin.prevout.n].nValue;
        }
    }
    return tx.ComputePriority(dResult);
}

CEDCCoinsModifier::CEDCCoinsModifier(
	  CEDCCoinsViewCache & cache_, 
	CEDCCoinsMap::iterator it_, 
					size_t usage) : cache(cache_), it(it_), cachedCoinUsage(usage) 
{
    assert(!cache.hasModifier);
    cache.hasModifier = true;
}

CEDCCoinsModifier::~CEDCCoinsModifier()
{
    assert(cache.hasModifier);
    cache.hasModifier = false;
    it->second.coins.Cleanup();
    cache.cachedCoinsUsage -= cachedCoinUsage; // Subtract the old usage

    if ((it->second.flags & CEDCCoinsCacheEntry::FRESH) && it->second.coins.IsPruned()) 
	{
        cache.cacheCoins.erase(it);
    } 
	else 
	{
        // If the coin still exists after the modification, add the new usage
        cache.cachedCoinsUsage += it->second.coins.DynamicMemoryUsage();
    }
}

CEDCCoinsViewCursor::~CEDCCoinsViewCursor()
{
}
