// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "coins.h"
#include "edc/edccompressor.h"
#include "edc/edccore_memusage.h"
#include "memusage.h"
#include "serialize.h"
#include "uint256.h"

#include <assert.h>
#include <stdint.h>

#include <boost/foreach.hpp>
#include <boost/unordered_map.hpp>

/** 
 * Pruned version of CEDCTransaction: only retains metadata and unspent transaction outputs
 *
 * Serialized format:
 * - VARINT(nVersion)
 * - VARINT(nCode)
 * - unspentness bitvector, for vout[2] and further; least significant byte first
 * - the non-spent CEDCTxOuts (via CEDCTxOutCompressor)
 * - VARINT(nHeight)
 *
 * The nCode value consists of:
 * - bit 0: IsCoinBase()
 * - bit 1: vout[0] is not spent
 * - bit 2: vout[1] is not spent
 * - The higher bits encode N, the number of non-zero bytes in the following bitvector.
 *   - In case both bit 1 and bit 2 are unset, they encode N-1, as there must be at
 *     least one non-spent output).
 *
 * Example: 0104835800816115944e077fe7c803cfa57f29b36bf87c1d358bb85e
 *          <><><--------------------------------------------><---->
 *          |  \                  |                             /
 *    version   code             vout[1]                  height
 *
 *    - version = 1
 *    - code = 4 (vout[1] is not spent, and 0 non-zero bytes of bitvector follow)
 *    - unspentness bitvector: as 0 non-zero bytes follow, it has length 0
 *    - vout[1]: 835800816115944e077fe7c803cfa57f29b36bf87c1d35
 *               * 8358: compact amount representation for 60000000000 (600 BTC)
 *               * 00: special txout type pay-to-pubkey-hash
 *               * 816115944e077fe7c803cfa57f29b36bf87c1d35: address uint160
 *    - height = 203998
 *
 *
 * Example: 0109044086ef97d5790061b01caab50f1b8e9c50a5057eb43c2d9563a4eebbd123008c988f1a4a4de2161e0f50aac7f17e7f9555caa486af3b
 *          <><><--><--------------------------------------------------><----------------------------------------------><---->
 *         /  \   \                     |                                                           |                     /
 *  version  code  unspentness       vout[4]                                                     vout[16]           height
 *
 *  - version = 1
 *  - code = 9 (coinbase, neither vout[0] or vout[1] are unspent,
 *                2 (1, +1 because both bit 1 and bit 2 are unset) non-zero bitvector bytes follow)
 *  - unspentness bitvector: bits 2 (0x04) and 14 (0x4000) are set, so vout[2+2] and vout[14+2] are unspent
 *  - vout[4]: 86ef97d5790061b01caab50f1b8e9c50a5057eb43c2d9563a4ee
 *             * 86ef97d579: compact amount representation for 234925952 (2.35 BTC)
 *             * 00: special txout type pay-to-pubkey-hash
 *             * 61b01caab50f1b8e9c50a5057eb43c2d9563a4ee: address uint160
 *  - vout[16]: bbd123008c988f1a4a4de2161e0f50aac7f17e7f9555caa4
 *              * bbd123: compact amount representation for 110397 (0.001 BTC)
 *              * 00: special txout type pay-to-pubkey-hash
 *              * 8c988f1a4a4de2161e0f50aac7f17e7f9555caa4: address uint160
 *  - height = 120891
 */
class CEDCCoins
{
public:
    //! whether transaction is a coinbase
    bool fCoinBase;

    //! unspent transaction outputs; spent outputs are .IsNull(); spent outputs at the end of the array are dropped
    std::vector<CEDCTxOut> vout;

    //! at which height this transaction was included in the active block chain
    int nHeight;

    //! version of the CEDCTransaction; accesses to this value should probably check for nHeight as well,
    //! as new tx version will probably only be introduced at certain heights
    int nVersion;

    void FromTx(const CEDCTransaction &tx, int nHeightIn) 
	{
        fCoinBase = tx.IsCoinBase();
        vout = tx.vout;
        nHeight = nHeightIn;
        nVersion = tx.nVersion;
        ClearUnspendable();
    }

    //! construct a CEDCCoins from a CEDCTransaction, at a given height
    CEDCCoins(const CEDCTransaction &tx, int nHeightIn) 
	{
        FromTx(tx, nHeightIn);
    }

    void Clear() 
	{
        fCoinBase = false;
        std::vector<CEDCTxOut>().swap(vout);
        nHeight = 0;
        nVersion = 0;
    }

    //! empty constructor
    CEDCCoins() : fCoinBase(false), vout(0), nHeight(0), nVersion(0) { }

    //!remove spent outputs at the end of vout
    void Cleanup() 
	{
        while (vout.size() > 0 && vout.back().IsNull())
            vout.pop_back();
        if (vout.empty())
            std::vector<CEDCTxOut>().swap(vout);
    }

    void ClearUnspendable() 
	{
        BOOST_FOREACH(CEDCTxOut &txout, vout) 
		{
            if (txout.scriptPubKey.IsUnspendable())
                txout.SetNull();
        }
        Cleanup();
    }

    void swap(CEDCCoins &to) 
	{
        std::swap(to.fCoinBase, fCoinBase);
        to.vout.swap(vout);
        std::swap(to.nHeight, nHeight);
        std::swap(to.nVersion, nVersion);
    }

    //! equality test
    friend bool operator==(const CEDCCoins &a, const CEDCCoins &b) 
	{
         // Empty CEDCCoins objects are always equal.
         if (a.IsPruned() && b.IsPruned())
             return true;
         return a.fCoinBase == b.fCoinBase &&
                a.nHeight == b.nHeight &&
                a.nVersion == b.nVersion &&
                a.vout == b.vout;
    }
    friend bool operator!=(const CEDCCoins &a, const CEDCCoins &b) 
	{
        return !(a == b);
    }

    void CalcMaskSize(unsigned int &nBytes, unsigned int &nNonzeroBytes) const;

    bool IsCoinBase() const 
	{
        return fCoinBase;
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const 
	{
        unsigned int nSize = 0;
        unsigned int nMaskSize = 0, nMaskCode = 0;
        CalcMaskSize(nMaskSize, nMaskCode);
        bool fFirst = vout.size() > 0 && !vout[0].IsNull();
        bool fSecond = vout.size() > 1 && !vout[1].IsNull();
        assert(fFirst || fSecond || nMaskCode);
        unsigned int nCode = 8*(nMaskCode - (fFirst || fSecond ? 0 : 1)) + (fCoinBase ? 1 : 0) + (fFirst ? 2 : 0) + (fSecond ? 4 : 0);
        // version
        nSize += ::GetSerializeSize(VARINT(this->nVersion), nType, nVersion);
        // size of header code
        nSize += ::GetSerializeSize(VARINT(nCode), nType, nVersion);
        // spentness bitmask
        nSize += nMaskSize;
        // txouts themself
        for (unsigned int i = 0; i < vout.size(); i++)
            if (!vout[i].IsNull())
                nSize += ::GetSerializeSize(CEDCTxOutCompressor(REF(vout[i])), nType, nVersion);
        // height
        nSize += ::GetSerializeSize(VARINT(nHeight), nType, nVersion);
        return nSize;
    }

    template<typename Stream>
    void Serialize(Stream &s, int nType, int nVersion) const 
	{
        unsigned int nMaskSize = 0, nMaskCode = 0;
        CalcMaskSize(nMaskSize, nMaskCode);
        bool fFirst = vout.size() > 0 && !vout[0].IsNull();
        bool fSecond = vout.size() > 1 && !vout[1].IsNull();
        assert(fFirst || fSecond || nMaskCode);
        unsigned int nCode = 8*(nMaskCode - (fFirst || fSecond ? 0 : 1)) + (fCoinBase ? 1 : 0) + (fFirst ? 2 : 0) + (fSecond ? 4 : 0);
        // version
        ::Serialize(s, VARINT(this->nVersion), nType, nVersion);

        // header code
        ::Serialize(s, VARINT(nCode), nType, nVersion);

        // spentness bitmask
        for (unsigned int b = 0; b<nMaskSize; b++) 
		{
            unsigned char chAvail = 0;
            for (unsigned int i = 0; i < 8 && 2+b*8+i < vout.size(); i++)
                if (!vout[2+b*8+i].IsNull())
                    chAvail |= (1 << i);
            ::Serialize(s, chAvail, nType, nVersion);
        }
        // txouts themself
        for (unsigned int i = 0; i < vout.size(); i++) 
		{
            if (!vout[i].IsNull())
                ::Serialize(s, CEDCTxOutCompressor(REF(vout[i])), nType, nVersion);
        }
        // coinbase height
        ::Serialize(s, VARINT(nHeight), nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream &s, int nType, int nVersion) 
	{
        unsigned int nCode = 0;

        // version
        ::Unserialize(s, VARINT(this->nVersion), nType, nVersion);

        // header code
        ::Unserialize(s, VARINT(nCode), nType, nVersion);

        fCoinBase = nCode & 1;
        std::vector<bool> vAvail(2, false);
        vAvail[0] = (nCode & 2) != 0;
        vAvail[1] = (nCode & 4) != 0;
        unsigned int nMaskCode = (nCode / 8) + ((nCode & 6) != 0 ? 0 : 1);

        // spentness bitmask
        while (nMaskCode > 0) 
		{
            unsigned char chAvail = 0;
            ::Unserialize(s, chAvail, nType, nVersion);

            for (unsigned int p = 0; p < 8; p++) 
			{
                bool f = (chAvail & (1 << p)) != 0;
                vAvail.push_back(f);
            }

            if (chAvail != 0)
                nMaskCode--;
        }
        // txouts themself
        vout.assign(vAvail.size(), CEDCTxOut());
        for (unsigned int i = 0; i < vAvail.size(); i++) 
		{
            if (vAvail[i])
                ::Unserialize(s, REF(CEDCTxOutCompressor(vout[i])), nType, nVersion);
        }
        // coinbase height
        ::Unserialize(s, VARINT(nHeight), nType, nVersion);
        Cleanup();
    }

    //! mark a vout spent
    bool Spend(uint32_t nPos);

    //! check whether a particular output is still available
    bool IsAvailable(unsigned int nPos) const 
	{
        return (nPos < vout.size() && !vout[nPos].IsNull());
    }

    //! check whether the entire CEDCCoins is spent
    //! note that only !IsPruned() CEDCCoins can be serialized
    bool IsPruned() const 
	{
        BOOST_FOREACH(const CEDCTxOut &out, vout)
            if (!out.IsNull())
                return false;
        return true;
    }

    size_t DynamicMemoryUsage() const 
	{
        size_t ret = memusage::DynamicUsage(vout);
        BOOST_FOREACH(const CEDCTxOut &out, vout) 
		{
            ret += RecursiveDynamicUsage(out.scriptPubKey);
        }
        return ret;
    }
};

struct CEDCCoinsCacheEntry
{
    CEDCCoins coins; // The actual cached data.
    unsigned char flags;

    enum Flags 
	{
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
        FRESH = (1 << 1), // The parent view does not have this entry (or it is pruned).
    };

    CEDCCoinsCacheEntry() : coins(), flags(0) {}
};

typedef boost::unordered_map<uint256, CEDCCoinsCacheEntry, SaltedTxidHasher> CEDCCoinsMap;

/** Cursor for iterating over CoinsView state */
class CEDCCoinsViewCursor
{
public:
    CEDCCoinsViewCursor(const uint256 &hashBlockIn): hashBlock(hashBlockIn) {}
    virtual ~CEDCCoinsViewCursor();

    virtual bool GetKey(uint256 &key) const = 0;
    virtual bool GetValue(CEDCCoins &coins) const = 0;
    /* Don't care about GetKeySize here */
    virtual unsigned int GetValueSize() const = 0;

    virtual bool Valid() const = 0;
    virtual void Next() = 0;

    //! Get best block at the time this cursor was created
    const uint256 &GetBestBlock() const 
	{ 
		return hashBlock; 
	}
private:
    uint256 hashBlock;
};

/** Abstract view on the open txout dataset. */
class CEDCCoinsView
{
public:
    //! Retrieve the CEDCCoins (unspent transaction outputs) for a given txid
    virtual bool GetCoins(const uint256 &txid, CEDCCoins &coins) const;

    //! Just check whether we have data for a given txid.
    //! This may (but cannot always) return true for fully spent transactions
    virtual bool HaveCoins(const uint256 &txid) const;

    //! Retrieve the block hash whose state this CEDCCoinsView currently represents
    virtual uint256 GetBestBlock() const;

    //! Do a bulk modification (multiple CEDCCoins changes + BestBlock change).
    //! The passed mapCoins can be modified.
    virtual bool BatchWrite(CEDCCoinsMap &mapCoins, const uint256 &hashBlock);

    //! Get a cursor to iterate over the whole state
    virtual CEDCCoinsViewCursor *Cursor() const;

    //! As we use CEDCCoinsViews polymorphically, have a virtual destructor
    virtual ~CEDCCoinsView() {}
};

/** CEDCCoinsView backed by another CCoinsView */
class CEDCCoinsViewBacked : public CEDCCoinsView
{
protected:
    CEDCCoinsView *base;

public:
    CEDCCoinsViewBacked(CEDCCoinsView *viewIn);
    bool GetCoins(const uint256 &txid, CEDCCoins &coins) const;
    bool HaveCoins(const uint256 &txid) const;
    uint256 GetBestBlock() const;
    void SetBackend(CEDCCoinsView &viewIn);
    bool BatchWrite(CEDCCoinsMap &mapCoins, const uint256 &hashBlock);
    CEDCCoinsViewCursor *Cursor() const;
};


class CEDCCoinsViewCache;

/** 
 * A reference to a mutable cache entry. Encapsulating it allows us to run
 *  cleanup code after the modification is finished, and keeping track of
 *  concurrent modifications. 
 */
class CEDCCoinsModifier
{
private:
    CEDCCoinsViewCache& cache;
    CEDCCoinsMap::iterator it;
    size_t cachedCoinUsage; // Cached memory usage of the CEDCCoins object before modification
    CEDCCoinsModifier(CEDCCoinsViewCache& cache_, CEDCCoinsMap::iterator it_, size_t usage);

public:
    CEDCCoins* operator->() 
	{ 
		return &it->second.coins; 
	}
    CEDCCoins& operator*() 
	{ 
		return it->second.coins; 
	}
    ~CEDCCoinsModifier();
    friend class CEDCCoinsViewCache;
};

/** CEDCCoinsView that adds a memory cache for transactions to another CEDCCoinsView */
class CEDCCoinsViewCache : public CEDCCoinsViewBacked
{
protected:
    /* Whether this cache has an active modifier. */
    bool hasModifier;


    /**
     * Make mutable so that we can "fill the cache" even from Get-methods
     * declared as "const".  
     */
    mutable uint256 hashBlock;
    mutable CEDCCoinsMap cacheCoins;

    /* Cached dynamic memory usage for the inner CCoins objects. */
    mutable size_t cachedCoinsUsage;

public:
    CEDCCoinsViewCache(CEDCCoinsView *baseIn);
    ~CEDCCoinsViewCache();

    // Standard CCoinsView methods
    bool GetCoins(const uint256 &txid, CEDCCoins &coins) const;
    bool HaveCoins(const uint256 &txid) const;
    uint256 GetBestBlock() const;
    void SetBestBlock(const uint256 &hashBlock);
    bool BatchWrite(CEDCCoinsMap &mapCoins, const uint256 &hashBlock);

    /**
     * Check if we have the given tx already loaded in this cache.
     * The semantics are the same as HaveCoins(), but no calls to
     * the backing CEDCCoinsView are made.
     */
    bool HaveCoinsInCache(const uint256 &txid) const;

    /**
     * Return a pointer to CEDCCoins in the cache, or NULL if not found. This is
     * more efficient than GetCoins. Modifications to other cache entries are
     * allowed while accessing the returned pointer.
     */
    const CEDCCoins* AccessCoins(const uint256 &txid) const;

    /**
     * Return a modifiable reference to a CEDCCoins. If no entry with the given
     * txid exists, a new one is created. Simultaneous modifications are not
     * allowed.
     */
    CEDCCoinsModifier ModifyCoins(const uint256 &txid);

    /**
     * Return a modifiable reference to a CEDCCoins. Assumes that no entry with the given
     * txid exists and creates a new one. This saves a database access in the case where
     * the coins were to be wiped out by FromTx anyway.  This should not be called with
     * the 2 historical coinbase duplicate pairs because the new coins are marked fresh, and
     * in the event the duplicate coinbase was spent before a flush, the now pruned coins
     * would not properly overwrite the first coinbase of the pair. Simultaneous modifications
     * are not allowed.
     */
    CEDCCoinsModifier ModifyNewCoins(const uint256 &txid, bool coinbase);

    /**
     * Push the modifications applied to this cache to its base.
     * Failure to call this method before destruction will cause the changes to be forgotten.
     * If false is returned, the state of this cache (and its backing view) will be undefined.
     */
    bool Flush();

    /**
     * Removes the transaction with the given hash from the cache, if it is
     * not modified.
     */
    void Uncache(const uint256 &txid);

    //! Calculate the size of the cache (in number of transactions)
    unsigned int GetCacheSize() const;

    //! Calculate the size of the cache (in bytes)
    size_t DynamicMemoryUsage() const;

    /** 
     * Amount of equibits coming in to a transaction
     * Note that lightweight clients may not know anything besides the hash of previous transactions,
     * so may not be able to calculate this.
     *
     * @param[in] tx	transaction for which we are checking input total
     * @return	Sum of value of all inputs (scriptSigs)
     */
    CAmount GetValueIn(const CEDCTransaction& tx) const;

    //! Check whether all prevouts of the transaction are present in the UTXO set represented by this view
    bool HaveInputs(const CEDCTransaction& tx) const;

    /**
     * Return priority of tx at height nHeight. Also calculate the sum of the values of the inputs
     * that are already in the chain.  These are the inputs that will age and increase priority as
     * new blocks are added to the chain.
     */
    double GetPriority(const CEDCTransaction &tx, int nHeight, CAmount &inChainInputValue) const;

    const CEDCTxOut &GetOutputFor(const CEDCTxIn& input) const;

    friend class CEDCCoinsModifier;

private:
    CEDCCoinsMap::iterator FetchCoins(const uint256 &txid);
    CEDCCoinsMap::const_iterator FetchCoins(const uint256 &txid) const;

    /**
     * By making the copy constructor private, we prevent accidentally using it when one intends to create a cache on top of a base cache.
     */
    CEDCCoinsViewCache(const CEDCCoinsViewCache &);
};

