// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "txdb.h"
#include "edccoins.h"
#include "dbwrapper.h"
#include "chain.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <boost/function.hpp>

class CBlockIndex;
class CEDCCoinsViewDBCursor;
class uint256;


/** 
 * CCoinsView backed by the coin database (chainstate/) 
 */
class CEDCCoinsViewDB : public CEDCCoinsView
{
protected:
    CDBWrapper db;

public:
    CEDCCoinsViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

	/**
	 * Get coins matching txid
     */
    bool GetCoins(const uint256 &txid, CEDCCoins &coins) const;

	/**
     * Returns true if any coins have txid
     */
    bool HaveCoins(const uint256 &txid) const;

	/**
     * Gets id of current best block
     */
    uint256 GetBestBlock() const;

	/**
     * Writes specified coins and block hash
     */
    bool BatchWrite(CEDCCoinsMap &mapCoins, const uint256 &hashBlock);

	/**
     * Cursor to coins in DB
     */
    CEDCCoinsViewCursor * Cursor() const;
};

/** 
 * Specialization of CEDCCoinsViewCursor to iterate over a CEDCCoinsViewDB 
 */
class CEDCCoinsViewDBCursor: public CEDCCoinsViewCursor
{
public:
    ~CEDCCoinsViewDBCursor() {}

	/**
     * Returns true if the first element of the key corresponding to the cursor
	 * is DB_COINS. The key parameter is assigned the second element of the key.
     */
    bool GetKey(uint256 &key) const;

	/**
     * Returns true if cursor references coins. Assigns coins to parameter.
     */
    bool GetValue(CEDCCoins &coins) const;

	/**
     * Returns size of value referenced by cursor
     */
    unsigned int GetValueSize() const;

	/**
     * Returns true if cursor references a coin (ie. key.first == DB_COINS)
     */
    bool Valid() const;

	/**
     * Increments cursor. Invalidates key of cursor if we are at the end.
     */
    void Next();

private:
    CEDCCoinsViewDBCursor(CDBIterator * pcursorIn, const uint256 &hashBlockIn):
        CEDCCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {}

    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, uint256> keyTmp;

    friend class CEDCCoinsViewDB;
};

/** 
 * Access to the block database (blocks/index/) 
 */
class CEDCBlockTreeDB : public CDBWrapper
{
public:
    CEDCBlockTreeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

private:
    CEDCBlockTreeDB(const CEDCBlockTreeDB &);
    void operator=(const CEDCBlockTreeDB &);

public:
    bool WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo *> > & fileInfo, 
						int nLastFile, 
						const std::vector<const CBlockIndex *> & blockinfo);

	/**
     * Load fileinfo with block file corresponding to nFile
     */
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo & fileinfo);

	/**
     * Assign nFile the index of the last block file
     */
    bool ReadLastBlockFile(int & nFile);

	/**
     * If fReindex is true, write the DB_REINDEX_FLAG. Else, erase it.
     */
    bool WriteReindexing(bool fReindex);

	/**
     * Load true if the DB_REINDEX_FLAG was written
     */
    bool ReadReindexing(bool & fReindex);

	/**
     * Load pos with value corresponding to txid
     */
    bool ReadTxIndex(const uint256 & txid, CDiskTxPos & pos);

	/**
     * Write collection of txid/TX positions
     */
    bool WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> > & list);

	/**
     * Write flag corresponding to name key value
     */
    bool WriteFlag(const std::string & name, bool fValue);

	/**
     * Read flag corresponding to name key value. If not present, it is assigned false.
     */
    bool ReadFlag(const std::string & name, bool & fValue);

	/**
     * Loads and does a Proof-of-work check on the block index
     */
    bool LoadBlockIndexGuts(boost::function<CBlockIndex * (const uint256 &)> insertBlockIndex);
};

