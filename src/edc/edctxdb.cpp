// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edctxdb.h"

#include "chainparams.h"
#include "hash.h"
#include "pow.h"
#include "uint256.h"
#include "edcutil.h"
#include "edcchainparams.h"


#include <stdint.h>

#include <boost/thread.hpp>

using namespace std;

static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';

static const char DB_BEST_BLOCK = 'B';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';


CEDCCoinsViewDB::CEDCCoinsViewDB(
	size_t nCacheSize, 
	bool fMemory, 	
	bool fWipe) : db(edcGetDataDir() / "chainstate", nCacheSize, fMemory, fWipe, true) 
{
}

bool CEDCCoinsViewDB::GetCoins(const uint256 &txid, CEDCCoins &coins) const 
{
    return db.Read(make_pair(DB_COINS, txid), coins);
}

bool CEDCCoinsViewDB::HaveCoins(const uint256 &txid) const 
{
    return db.Exists(make_pair(DB_COINS, txid));
}

uint256 CEDCCoinsViewDB::GetBestBlock() const 
{
    uint256 hashBestChain;

    if (!db.Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();

    return hashBestChain;
}

bool CEDCCoinsViewDB::BatchWrite( CEDCCoinsMap &mapCoins, const uint256 &hashBlock) 
{
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;

    for (CEDCCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) 
	{
        if (it->second.flags & CEDCCoinsCacheEntry::DIRTY) 
		{
            if (it->second.coins.IsPruned())
                batch.Erase(make_pair(DB_COINS, it->first));
            else
                batch.Write(make_pair(DB_COINS, it->first), it->second.coins);
            changed++;
        }
        count++;
        CEDCCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }
    if (!hashBlock.IsNull())
        batch.Write(DB_BEST_BLOCK, hashBlock);

    edcLogPrint("coindb", "Committing %u changed transactions (out of %u) to coin database...\n", 
		(unsigned int)changed, (unsigned int)count);

    return db.WriteBatch(batch);
}

CEDCBlockTreeDB::CEDCBlockTreeDB(
	size_t nCacheSize, 
	bool fMemory, 
	bool fWipe) : 
	CDBWrapper(edcGetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe)
{
}

bool CEDCBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) 
{
    return Read(make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CEDCBlockTreeDB::WriteReindexing(bool fReindexing) 
{
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
    else
        return Erase(DB_REINDEX_FLAG);
}

bool CEDCBlockTreeDB::ReadReindexing(bool &fReindexing) 
{
    fReindexing = Exists(DB_REINDEX_FLAG);
    return true;
}

bool CEDCBlockTreeDB::ReadLastBlockFile(int &nFile) 
{
    return Read(DB_LAST_BLOCK, nFile);
}

CEDCCoinsViewCursor *CEDCCoinsViewDB::Cursor() const
{
    CEDCCoinsViewDBCursor *i = new CEDCCoinsViewDBCursor(
		const_cast<CDBWrapper*>(&db)->NewIterator(), GetBestBlock());

    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COINS);

    // Cache key of first record
    i->pcursor->GetKey(i->keyTmp);

    return i;
}

bool CEDCCoinsViewDBCursor::GetKey(uint256 &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COINS) 
	{
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CEDCCoinsViewDBCursor::GetValue(CEDCCoins &coins) const
{
    return pcursor->GetValue(coins);
}

unsigned int CEDCCoinsViewDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}

bool CEDCCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COINS;
}

void CEDCCoinsViewDBCursor::Next()
{
    pcursor->Next();
    if (!pcursor->Valid() || !pcursor->GetKey(keyTmp))
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
}

bool CEDCBlockTreeDB::WriteBatchSync(
	const std::vector<std::pair<int, const CBlockFileInfo*> > & fileInfo, 
															int nLastFile, 
						const std::vector<const CBlockIndex*> & blockinfo) 
{
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo*> >::const_iterator 
		it=fileInfo.begin(); it != fileInfo.end(); it++)
	{
        batch.Write(make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }

    batch.Write(DB_LAST_BLOCK, nLastFile);

    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); 
	it != blockinfo.end(); it++) 
	{
        batch.Write(make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), CDiskBlockIndex(*it));
    }
    return WriteBatch(batch, true);
}

bool CEDCBlockTreeDB::ReadTxIndex(const uint256 &txid, CDiskTxPos &pos) 
{
    return Read(make_pair(DB_TXINDEX, txid), pos);
}

bool CEDCBlockTreeDB::WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >&vect) 
{
    CDBBatch batch(*this);

    for (std::vector<std::pair<uint256,CDiskTxPos> >::const_iterator 
		it=vect.begin(); it!=vect.end(); it++)
        batch.Write(make_pair(DB_TXINDEX, it->first), it->second);

    return WriteBatch(batch);
}

bool CEDCBlockTreeDB::WriteFlag(const std::string &name, bool fValue) 
{
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CEDCBlockTreeDB::ReadFlag(const std::string &name, bool &fValue) 
{
    char ch;

    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';

    return true;
}

bool CEDCBlockTreeDB::LoadBlockIndexGuts(
	boost::function<CBlockIndex*(const uint256&)> insertBlockIndex)
{
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(make_pair(DB_BLOCK_INDEX, uint256()));

    // Load mapBlockIndex
    while (pcursor->Valid()) 
	{
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) 
		{
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) 
			{
                // Construct block index object
                CBlockIndex* pindexNew = insertBlockIndex(diskindex.GetBlockHash());
                pindexNew->pprev          = insertBlockIndex(diskindex.hashPrev);
                pindexNew->nHeight        = diskindex.nHeight;
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nDataPos       = diskindex.nDataPos;
                pindexNew->nUndoPos       = diskindex.nUndoPos;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->nBits          = diskindex.nBits;
                pindexNew->nNonce         = diskindex.nNonce;
                pindexNew->nStatus        = diskindex.nStatus;
                pindexNew->nTx            = diskindex.nTx;

                if (!CheckProofOfWork(pindexNew->GetBlockHash(), pindexNew->nBits, edcParams().GetConsensus()))
                    return edcError("LoadBlockIndex(): CheckProofOfWork failed: %s", pindexNew->ToString());

                pcursor->Next();
            } 
			else 
			{
                return edcError("LoadBlockIndex() : failed to read value");
            }
        } 
		else 
		{
            break;
        }
    }

    return true;
}
