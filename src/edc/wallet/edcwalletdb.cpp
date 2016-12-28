// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/wallet/edcwalletdb.h"

#include "edc/edcbase58.h"
#include "consensus/validation.h"
#include "edc/edcmain.h" // For CheckTransaction
#include "protocol.h"
#include "serialize.h"
#include "sync.h"
#include "edc/edcutil.h"
#include "utiltime.h"
#include "edc/wallet/edcwallet.h"
#include "edc/edcparams.h"
#include "edc/edcapp.h"
#include "edc/message/edcmessage.h"
#include "edc/rpc/edcwot.h"
#include "edc/rpc/edcpolling.h"

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>

using namespace std;

static uint64_t nAccountingEntryNumber = 0;

namespace
{
// Wallet DB Keys:
//
const std::string ACC               = "acc";        // ACC:account-name/pubkey
const std::string ACENTRY           = "acentry";    // ACENTRY:(account-name:account-number)/acentry
const std::string BESTBLOCK         = "bestblock";  // BESTBLOCK/empty-locator
const std::string BESTBLOCK_NOMERKLE= "bestblock_nomerkle";  // BESTBLOCK_NOMERKLE/locator
const std::string CKEY              = "ckey";       // CKEY:pubkey/privkey-secret
const std::string CSCRIPT           = "cscript";    // CSCRIPT:hash/script
const std::string DEFAULTKEY        = "defaultkey"; // DEFAULTKEY/pubkey
const std::string DESTDATA          = "destdata";   // DESTDATA:(address:key)/value
const std::string HDCHAIN			= "hdchain";	// HDCHAIN/value
#ifdef USE_HSM
const std::string HSM_KEY			= "HSM_key";    // HSM_KEY:pubkey/HSM-ID
const std::string HSM_POOL          = "HSM_pool";   // HSM_POOL:number/keypool
#endif
const std::string IPROXY            = "iproxy";     // IPROXY:(addr,paddr:iaddr)/(ts:sign)
const std::string IPROXY_RVK        = "iproxy_rvk"; // IPROXY_RVK:(addr:paddr,iaddr)/(ts:sign)
const std::string ISSUER            = "issuer";     // ISSUER:issuer-name/issuer
const std::string KEY               = "key";        // KEY:pubkey/(privkey:hash(pubkey,privkey))
const std::string KEYMETA           = "keymeta";    // KEYMETA:pubkey/key-meta
const std::string MINVERSION        = "minversion"; // MINVERSION/version
const std::string MKEY              = "mkey";       // MKEY:id/masterkey
const std::string NAME              = "name";       // NAME:address/name
const std::string ORDERPOSNEXT      = "orderposnext";  // ORDERPOSNEXT/order-pos-next
const std::string POOL              = "pool";       // POOL:number/keypool
const std::string PURPOSE           = "purpose";    // PURPOSE:address/purpose
const std::string TX                = "tx";         // TX:trx-hash/trx
const std::string USER_MSG          = "user_msg";   // USER_MSG:(tag:hash)/msg
const std::string VERSION           = "version";    // VERSION/version
const std::string WATCHS            = "watchs";     // WATCHS/dest
const std::string WKEY              = "wkey";       // WKEY:pubkey/privkey
}

bool CEDCWalletDB::WriteName(const string& strAddress, const string& strName)
{
	EDCapp & theApp = EDCapp::singleton();
    theApp.incWalletDBUpdated();

    return Write(make_pair(NAME, strAddress), strName);
}

bool CEDCWalletDB::EraseName(const string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(make_pair(NAME, strAddress));
}

bool CEDCWalletDB::WritePurpose(const string& strAddress, const string& strPurpose)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(make_pair(PURPOSE, strAddress), strPurpose);
}

bool CEDCWalletDB::ErasePurpose(const string& strPurpose)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(make_pair(PURPOSE, strPurpose));
}

bool CEDCWalletDB::WriteTx(const CEDCWalletTx& wtx)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(TX, wtx.GetHash()), wtx);
}

bool CEDCWalletDB::EraseTx(uint256 hash)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(std::make_pair(TX, hash));
}

bool CEDCWalletDB::WriteKey(
	 	 const CPubKey & vchPubKey, 
		const CPrivKey & vchPrivKey, 
	const CKeyMetadata & keyMeta)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();

    if (!Write(std::make_pair(KEYMETA, vchPubKey),
               keyMeta, false))
        return false;

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return Write(std::make_pair(KEY, vchPubKey), 
		std::make_pair(vchPrivKey, Hash(vchKey.begin(), vchKey.end())), false);
}

#ifdef USE_HSM
bool CEDCWalletDB::WriteHSMKey(
	 const CPubKey & vchPubKey, 
 const std::string & hsmID,
const CKeyMetadata & keyMeta
)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();

    if (!Write(std::make_pair(KEYMETA, vchPubKey),
               keyMeta, false))
        return false;

    return Write(std::make_pair(HSM_KEY, vchPubKey), hsmID, false);
}
#endif

bool CEDCWalletDB::WriteCryptedKey(
	                   const CPubKey & vchPubKey,
    const std::vector<unsigned char> & vchCryptedSecret,
                  const CKeyMetadata & keyMeta)
{
	EDCapp & theApp = EDCapp::singleton();

    const bool fEraseUnencryptedKey = true;
    theApp.incWalletDBUpdated();

    if (!Write(std::make_pair(KEYMETA, vchPubKey), keyMeta))
        return false;

    if (!Write(std::make_pair(CKEY, vchPubKey), vchCryptedSecret, false))
        return false;

    if (fEraseUnencryptedKey)
    {
        Erase(std::make_pair(KEY, vchPubKey));
        Erase(std::make_pair(WKEY, vchPubKey));
    }

    return true;
}

bool CEDCWalletDB::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(MKEY, nID), kMasterKey, true);
}

bool CEDCWalletDB::WriteCScript(const uint160& hash, const CScript& redeemScript)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(CSCRIPT, hash), *(const CScriptBase*)(&redeemScript), false);
}

bool CEDCWalletDB::WriteWatchOnly(const CScript &dest)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(WATCHS, *(const CScriptBase*)(&dest)), '1');
}

bool CEDCWalletDB::EraseWatchOnly(const CScript &dest)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(std::make_pair(WATCHS, *(const CScriptBase*)(&dest)));
}

bool CEDCWalletDB::WriteBestBlock(const CBlockLocator& locator)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    Write(BESTBLOCK, CBlockLocator()); // Write empty block locator so versions that require a merkle branch automatically rescan

    return Write(BESTBLOCK_NOMERKLE, locator);
}

bool CEDCWalletDB::ReadBestBlock(CBlockLocator& locator)
{
    if (Read(BESTBLOCK, locator) && !locator.vHave.empty()) 
		return true;

    return Read(BESTBLOCK_NOMERKLE, locator);
}

bool CEDCWalletDB::WriteOrderPosNext(int64_t nOrderPosNext)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(ORDERPOSNEXT, nOrderPosNext);
}

bool CEDCWalletDB::WriteDefaultKey(const CPubKey& vchPubKey)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(DEFAULTKEY, vchPubKey);
}

bool CEDCWalletDB::ReadPool(int64_t nPool, CKeyPool& keypool)
{
    return Read(std::make_pair(POOL, nPool), keypool);
}

bool CEDCWalletDB::WritePool(int64_t nPool, const CKeyPool& keypool)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(POOL, nPool), keypool);
}

bool CEDCWalletDB::ErasePool(int64_t nPool)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(std::make_pair(POOL, nPool));
}

#ifdef USE_HSM
bool CEDCWalletDB::ReadHSMPool(int64_t nPool, CKeyPool& keypool)
{
    return Read(std::make_pair(HSM_POOL, nPool), keypool);
}

bool CEDCWalletDB::WriteHSMPool(int64_t nPool, const CKeyPool& keypool)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(HSM_POOL, nPool), keypool);
}

bool CEDCWalletDB::EraseHSMPool(int64_t nPool)
{
	EDCapp & theApp = EDCapp::singleton();
    theApp.incWalletDBUpdated();

    return Erase(std::make_pair(HSM_POOL, nPool));
}
#endif

bool CEDCWalletDB::WriteMinVersion(int nVersion)
{
    return Write(MINVERSION, nVersion);
}

bool CEDCWalletDB::ReadAccount(const string& strAccount, CAccount& account)
{
    account.SetNull();
    return Read(make_pair(ACC, strAccount), account);
}

bool CEDCWalletDB::WriteAccount(const string& strAccount, const CAccount& account)
{
    return Write(make_pair(ACC, strAccount), account);
}

bool CEDCWalletDB::ReadIssuer(const string& strIssuer, CIssuer & issuer )
{
    issuer.SetNull();
    return Read(make_pair(ISSUER, strIssuer), issuer );
}

bool CEDCWalletDB::WriteIssuer(const string& strIssuer, const CIssuer & issuer )
{
	EDCapp & theApp = EDCapp::singleton();
    theApp.incWalletDBUpdated();

    return Write(make_pair(ISSUER, strIssuer), issuer );
}

bool CEDCWalletDB::WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry)
{
    return Write(std::make_pair(ACENTRY, 
		std::make_pair(acentry.strAccount, nAccEntryNum)), acentry);
}

bool CEDCWalletDB::WriteAccountingEntry_Backend(const CAccountingEntry& acentry)
{
    return WriteAccountingEntry(++nAccountingEntryNumber, acentry);
}

CAmount CEDCWalletDB::GetAccountCreditDebit(const string& strAccount)
{
    list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    CAmount nCreditDebit = 0;
    BOOST_FOREACH (const CAccountingEntry& entry, entries)
        nCreditDebit += entry.nCreditDebit;

    return nCreditDebit;
}

void CEDCWalletDB::ListAccountCreditDebit(const string& strAccount, list<CAccountingEntry>& entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__) + ": cannot create DB cursor");

    bool setRange = true;
    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (setRange)
            ssKey << std::make_pair(ACENTRY, 
				std::make_pair((fAllAccounts ? string("") : strAccount), uint64_t(0)));

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange);
        setRange = false;

        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__) + ": error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != ACENTRY)
            break;

        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        ssKey >> acentry.nEntryNo;
        entries.push_back(acentry);
    }

    pcursor->close();
}

DBErrors CEDCWalletDB::ReorderTransactions(CEDCWallet* pwallet)
{
    LOCK(pwallet->cs_wallet);

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CEDCWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef pair<CEDCWalletTx*, CAccountingEntry*> TxPair;
    typedef multimap<int64_t, TxPair > TxItems;
    TxItems txByTime;

    for (map<uint256, CEDCWalletTx>::iterator it = pwallet->mapWallet.begin(); 
	it != pwallet->mapWallet.end(); ++it)
    {
        CEDCWalletTx* wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->nTimeReceived, TxPair(wtx, (CAccountingEntry*)0)));
    }

    list<CAccountingEntry> acentries;
    ListAccountCreditDebit("", acentries);

    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txByTime.insert(make_pair(entry.nTime, TxPair((CEDCWalletTx*)0, &entry)));
    }

    int64_t& nOrderPosNext = pwallet->nOrderPosNext;
    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CEDCWalletTx *const pwtx = (*it).second.first;
        CAccountingEntry *const pacentry = (*it).second.second;
        int64_t& nOrderPos = (pwtx != 0) ? pwtx->nOrderPos : pacentry->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (pwtx)
            {
                if (!WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            BOOST_FOREACH(const int64_t& nOffsetStart, nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (pwtx)
            {
                if (!WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
    }
    WriteOrderPosNext(nOrderPosNext);

    return DB_LOAD_OK;
}

class CWalletScanState 
{
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    unsigned int nKeyMeta;
    bool fIsEncrypted;
    bool fAnyUnordered;
    int nFileVersion;
    vector<uint256> vWalletUpgrade;

    CWalletScanState() {
        nKeys = nCKeys = nKeyMeta = 0;
        fIsEncrypted = false;
        fAnyUnordered = false;
        nFileVersion = 0;
    }
};

bool
ReadKeyValue(
	      CEDCWallet * pwallet, 
       	 CDataStream & ssKey, 
      	 CDataStream & ssValue,
    CWalletScanState & wss, 
	          string & strType, 
	          string & strErr)
{
    try 
	{
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;

        if (strType == NAME)
        {
            string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CEDCBitcoinAddress(strAddress).Get()].name;
        }
        else if (strType == PURPOSE)
        {
            string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CEDCBitcoinAddress(strAddress).Get()].purpose;
        }
        else if (strType == TX)
        {
            uint256 hash;
            ssKey >> hash;
            CEDCWalletTx wtx;
            ssValue >> wtx;
            CValidationState state;
            if (!(CheckTransaction(wtx, state) && (wtx.GetHash() == hash) && state.IsValid()))
                return false;

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
            {
                if (!ssValue.empty())
                {
                    char fTmp;
                    char fUnused;
                    ssValue >> fTmp >> fUnused >> wtx.strFromAccount;
                    strErr = strprintf("LoadWallet() upgrading tx ver=%d %d '%s' %s",
                        wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                }
                else
                {
                    strErr = strprintf("LoadWallet() repairing tx ver=%d %s", 
                        wtx.fTimeReceivedIsTxTime, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                wss.vWalletUpgrade.push_back(hash);
            }

            if (wtx.nOrderPos == -1)
                wss.fAnyUnordered = true;

            pwallet->LoadToWallet(wtx);
        }
        else if (strType == ACENTRY)
        {
            string strAccount;
            ssKey >> strAccount;
            uint64_t nNumber;
            ssKey >> nNumber;
            if (nNumber > nAccountingEntryNumber)
                nAccountingEntryNumber = nNumber;

            if (!wss.fAnyUnordered)
            {
                CAccountingEntry acentry;
                ssValue >> acentry;
                if (acentry.nOrderPos == -1)
                    wss.fAnyUnordered = true;
            }
        }
        else if (strType == WATCHS)
        {
            CScript script;
            ssKey >> *(CScriptBase*)(&script);
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
                pwallet->LoadWatchOnly(script);

            // Watch-only addresses have no birthday information for now,
            // so set the wallet birthday to the beginning of time.
            pwallet->nTimeFirstKey = 1;
        }
        else if (strType == KEY || strType == WKEY)
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash;

            if (strType == KEY)
            {
                wss.nKeys++;
                ssValue >> pkey;
            } 
			else 
			{
                CWalletKey wkey;
                ssValue >> wkey;
                pkey = wkey.vchPrivKey;
            }

            // Old wallets store keys as "key" [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the 
            // public key is re-derived from the private key using EC 
            // operations as a checksum. Newer wallets store keys as 
            // "key"[pubkey] => [privkey][hash(pubkey,privkey)], which is much 
			// faster while remaining backwards-compatible.
            try
            {
                ssValue >> hash;
            }
            catch (...) 
			{
            	edcLogPrintf("Warning: Exception thrown during key input processing\n");
			}

            bool fSkipCheck = false;

            if (!hash.IsNull())
            {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey.begin(), vchKey.end()) != hash)
                {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck))
            {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (!pwallet->LoadKey(key, vchPubKey))
            {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        }
        else if (strType == MKEY)
        {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(pwallet->mapMasterKeys.count(nID) != 0)
            {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        }
        else if (strType == CKEY)
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            wss.nCKeys++;

            if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
            {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        }
        else if (strType == KEYMETA)
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            pwallet->LoadKeyMetadata(vchPubKey, keyMeta);

            // find earliest key creation time, as wallet birthday
            if (!pwallet->nTimeFirstKey ||
                (keyMeta.nCreateTime < pwallet->nTimeFirstKey))
                pwallet->nTimeFirstKey = keyMeta.nCreateTime;
        }
        else if (strType == DEFAULTKEY)
        {
            ssValue >> pwallet->vchDefaultKey;
        }
        else if (strType == POOL)
        {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;

			pwallet->LoadKeyPool(nIndex, keypool);
        }
        else if (strType == VERSION)
        {
            ssValue >> wss.nFileVersion;
            if (wss.nFileVersion == 10300)
                wss.nFileVersion = 300;
        }
        else if (strType == CSCRIPT)
        {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> *(CScriptBase*)(&script);
            if (!pwallet->LoadCScript(script))
            {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        }
        else if (strType == ORDERPOSNEXT)
        {
            ssValue >> pwallet->nOrderPosNext;
        }
        else if (strType == DESTDATA)
        {
            std::string strAddress, strKey, strValue;
            ssKey >> strAddress;
            ssKey >> strKey;
            ssValue >> strValue;
            if (!pwallet->LoadDestData(CEDCBitcoinAddress(strAddress).Get(), strKey, strValue))
            {
				strErr = "Error reading wallet database: LoadDestData failed";
				return false;
			}
		}
        else if (strType == HDCHAIN )
        {
            CHDChain chain;
            ssValue >> chain;
            if (!pwallet->SetHDChain(chain, true))
            {
                strErr = "Error reading wallet database: SetHDChain failed";
                return false;
            }
        }
		else if( strType == ISSUER )
		{
			; // no-op?
		}
		else if( strType == USER_MSG )
		{
			std::string tag;
			ssKey >> tag;

			uint256 hash;
			ssKey >> hash;

			CUserMessage * msg = CUserMessage::create( tag, ssValue );
			
			if(!msg->verify())
			{
				strErr = "Error reading wallet database: Invalid message loaded";
				return false;
			}
			pwallet->LoadMessage( msg );
		}
#ifdef USE_HSM
		else if( strType == HSM_POOL )
		{
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;
            pwallet->setHSMKeyPool.insert(nIndex);

            // If no metadata exists yet, create a default with the pool key's
            // creation time. Note that this may be overwritten by actually
            // stored metadata for that key later, which is fine.
            CKeyID keyid = keypool.vchPubKey.GetID();
            if (pwallet->mapKeyMetadata.count(keyid) == 0)
                pwallet->mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
		}
		else if( strType == HSM_KEY )
		{
            CPubKey pubKey;
            ssKey >> pubKey;
            if (!pubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }

			std::string hsmID;
			ssValue >> hsmID;

			if(!pwallet->AddHSMKey( pubKey, hsmID ))
            {
				strErr = "Error reading wallet database: Add HSM Key failed";
				return false;
			}
		}
#endif
	} 
	catch (...)
	{
		return false;
	}
	return true;
}

static bool IsKeyType(string strType)
{
    return (strType== KEY || strType == WKEY ||
            strType == MKEY || strType == CKEY
#ifdef USE_HSM
			|| strType == HSM_KEY
#endif
);
}

DBErrors CEDCWalletDB::LoadWallet(CEDCWallet* pwallet)
{
    pwallet->vchDefaultKey = CPubKey();
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try 
	{
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read(MINVERSION, nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            edcLogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                edcLogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            string strType, strErr;
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr))
            {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType))
                    result = DB_CORRUPT;
                else
                {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    if (strType == TX)
					{
						EDCparams & params = EDCparams::singleton();
                        // Rescan if there is a bad transaction record:
						if( mapArgs.count( "-eb_rescan" ) == 0 )
	                        params.rescan = true;
					}
                }
            }
            if (!strErr.empty())
                edcLogPrintf("%s\n", strErr);
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) 
	{
        throw;
    }
    catch (...) 
	{
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DB_LOAD_OK)
        return result;

    edcLogPrintf("nFileVersion = %d\n", wss.nFileVersion);

    edcLogPrintf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n",
           wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys) != wss.nKeyMeta)
        pwallet->nTimeFirstKey = 1; // 0 would be considered 'no value'

    BOOST_FOREACH(uint256 hash, wss.vWalletUpgrade)
        WriteTx(pwallet->mapWallet[hash]);

    // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
    if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000))
        return DB_NEED_REWRITE;

    if (wss.nFileVersion < CLIENT_VERSION) // Update
        WriteVersion(CLIENT_VERSION);

    if (wss.fAnyUnordered)
        result = ReorderTransactions(pwallet);

    pwallet->laccentries.clear();
    ListAccountCreditDebit("*", pwallet->laccentries);
    BOOST_FOREACH(CAccountingEntry& entry, pwallet->laccentries) 
	{
        pwallet->wtxOrdered.insert(make_pair(entry.nOrderPos, CEDCWallet::TxPair((CEDCWalletTx*)0, &entry)));
    }

    return result;
}

DBErrors CEDCWalletDB::FindWalletTx(
			  CEDCWallet * pwallet, 
		 vector<uint256> & vTxHash, 
	vector<CEDCWalletTx> & vWtx)
{
    pwallet->vchDefaultKey = CPubKey();
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try 
	{
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read(MINVERSION, nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            edcLogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                edcLogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            string strType;
            ssKey >> strType;
            if (strType == TX) 
			{
                uint256 hash;
                ssKey >> hash;

                CEDCWalletTx wtx;
                ssValue >> wtx;

                vTxHash.push_back(hash);
                vWtx.push_back(wtx);
            }
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) 
	{
        throw;
    }
    catch (...) 
	{
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    return result;
}

DBErrors CEDCWalletDB::ZapSelectTx(
		 CEDCWallet * pwallet, 
	vector<uint256> & vTxHashIn, 
	vector<uint256> & vTxHashOut)
{
    // build list of wallet TXs and hashes
    vector<uint256> vTxHash;
    vector<CEDCWalletTx> vWtx;
    DBErrors err = FindWalletTx(pwallet, vTxHash, vWtx);

    if (err != DB_LOAD_OK) 
	{
        return err;
    }

    std::sort(vTxHash.begin(), vTxHash.end());
    std::sort(vTxHashIn.begin(), vTxHashIn.end());

    // erase each matching wallet TX
    bool delerror = false;
    vector<uint256>::iterator it = vTxHashIn.begin();
    BOOST_FOREACH (uint256 hash, vTxHash) 
	{
        while (it < vTxHashIn.end() && (*it) < hash) 
		{
            it++;
        }
        if (it == vTxHashIn.end()) 
		{
            break;
        }
        else if ((*it) == hash) 
		{
            pwallet->mapWallet.erase(hash);
            if(!EraseTx(hash)) 
			{
                edcLogPrint("db", "Transaction was found for deletion but returned database error: %s\n", hash.GetHex());
                delerror = true;
            }
            vTxHashOut.push_back(hash);
        }
    }

    if (delerror) 
	{
        return DB_CORRUPT;
    }
    return DB_LOAD_OK;
}

DBErrors CEDCWalletDB::ZapWalletTx(CEDCWallet* pwallet, vector<CEDCWalletTx>& vWtx)
{
    // build list of wallet TXs
    vector<uint256> vTxHash;
    DBErrors err = FindWalletTx(pwallet, vTxHash, vWtx);
    if (err != DB_LOAD_OK)
        return err;

    // erase each wallet TX
    BOOST_FOREACH (uint256& hash, vTxHash) 
	{
        if (!EraseTx(hash))
            return DB_CORRUPT;
    }

    return DB_LOAD_OK;
}

void edcThreadFlushWalletDB(const string& strFile)
{
	EDCapp & theApp = EDCapp::singleton();

    // Make this thread recognisable as the wallet flushing thread
    RenameThread("equibit-wallet");

    static bool fOneThread;
    if (fOneThread)
        return;
    fOneThread = true;
	EDCparams & params = EDCparams::singleton();
    if (!params.flushwallet )
        return;

    unsigned int nLastSeen = theApp.walletDBUpdated();
    unsigned int nLastFlushed = theApp.walletDBUpdated();
    int64_t nLastWalletUpdate = GetTime();
    while (true)
    {
        MilliSleep(500);

        if (nLastSeen != theApp.walletDBUpdated() )
        {
            nLastSeen = theApp.walletDBUpdated();
            nLastWalletUpdate = GetTime();
        }

        if (nLastFlushed != theApp.walletDBUpdated() && GetTime() - nLastWalletUpdate >= 2)
        {
            TRY_LOCK(theApp.bitdb().cs_db,lockDb);
            if (lockDb)
            {
                // Don't do this if any databases are in use
                int nRefCount = 0;
                map<string, int>::iterator mi = theApp.bitdb().mapFileUseCount.begin();
                while (mi != theApp.bitdb().mapFileUseCount.end())
                {
                    nRefCount += (*mi).second;
                    mi++;
                }

                if (nRefCount == 0)
                {
                    boost::this_thread::interruption_point();

                    map<string, int>::iterator _mi = theApp.bitdb().mapFileUseCount.find(strFile);
                    if (_mi != theApp.bitdb().mapFileUseCount.end())
                    {
                        edcLogPrint("db", "Flushing %s\n", strFile);
                        nLastFlushed = theApp.walletDBUpdated();
                        int64_t nStart = GetTimeMillis();

                        // Flush wallet file so it's self contained
                        theApp.bitdb().CloseDb(strFile);
                        theApp.bitdb().CheckpointLSN(strFile);

                        theApp.bitdb().mapFileUseCount.erase(_mi++);
                        edcLogPrint("db", "Flushed %s %dms\n", strFile, GetTimeMillis() - nStart);
                    }
                }
            }
        }
    }
}

//
// Try to (very carefully!) recover wallet file if there is a problem.
//
bool CEDCWalletDB::Recover(
	           CEDCDBEnv & dbenv, 
       const std::string & filename, 
	                  bool fOnlyKeys )
{
    // Recovery procedure:
    // move wallet file to wallet.timestamp.bak
    // Call Salvage with fAggressive=true to
    // get as much data as possible.
    // Rewrite salvaged data to fresh wallet file
    // Set -eb_rescan so any missing transactions will be
    // found.
    int64_t now = GetTime();
    std::string newFilename = strprintf("wallet.%d.bak", now);

    int result = dbenv.dbenv->dbrename(NULL, filename.c_str(), NULL,
                                       newFilename.c_str(), DB_AUTO_COMMIT);
    if (result == 0)
        edcLogPrintf("Renamed %s to %s\n", filename, newFilename);
    else
    {
        edcLogPrintf("Failed to rename %s to %s\n", filename, newFilename);
        return false;
    }

    std::vector<CEDCDBEnv::KeyValPair> salvagedData;
    bool fSuccess = dbenv.Salvage(newFilename, true, salvagedData);
    if (salvagedData.empty())
    {
        edcLogPrintf("Salvage(aggressive) found no records in %s.\n", 
			newFilename);
        return false;
    }
    edcLogPrintf("Salvage(aggressive) found %u records\n", salvagedData.size());

    std::unique_ptr<Db> pdbCopy(new Db(dbenv.dbenv, 0));
    int ret = pdbCopy->open(NULL,               // Txn pointer
                            filename.c_str(),   // Filename
                            "main",             // Logical db name
                            DB_BTREE,           // Database type
                            DB_CREATE,          // Flags
                            0);
    if (ret > 0)
    {
        edcLogPrintf("Cannot create database file %s\n", filename);
        return false;
    }
    CEDCWallet dummyWallet;
    CWalletScanState wss;

    DbTxn* ptxn = dbenv.TxnBegin();
    BOOST_FOREACH(CEDCDBEnv::KeyValPair& row, salvagedData)
    {
        if (fOnlyKeys)
        {
            CDataStream ssKey(row.first, SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(row.second, SER_DISK, CLIENT_VERSION);
            string strType, strErr;
            bool fReadOK;
            {
                // Required in LoadKeyMetadata():
                LOCK(dummyWallet.cs_wallet);
                fReadOK = ReadKeyValue(&dummyWallet, ssKey, ssValue,
                                        wss, strType, strErr);
            }
            if (!IsKeyType(strType) && strType != "hdchain")
                continue;
            if (!fReadOK)
            {
                edcLogPrintf("WARNING: CEDCWalletDB::Recover skipping %s: %s\n",
					strType, strErr);
                continue;
            }
        }

        Dbt datKey(&row.first[0], row.first.size());
        Dbt datValue(&row.second[0], row.second.size());
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE);

        if (ret2 > 0)
            fSuccess = false;
    }
    ptxn->commit(0);
    pdbCopy->close(0);

    return fSuccess;
}

bool CEDCWalletDB::Recover(CEDCDBEnv& dbenv, const std::string& filename)
{
    return CEDCWalletDB::Recover(dbenv, filename, false);
}

bool CEDCWalletDB::WriteDestData(
	const std::string & address, 
	const std::string & key, 
	const std::string & value)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(std::string(DESTDATA), 
		std::make_pair(address, key)), value);
}

bool CEDCWalletDB::EraseDestData(const std::string &address, const std::string &key)
{
	EDCapp & theApp = EDCapp::singleton();
    theApp.incWalletDBUpdated();

    return Erase(std::make_pair(std::string(DESTDATA), std::make_pair(address, key)));
}

namespace
{

bool dumpKey( 
	    ostream & out,		// IN/OUT
	CDataStream & ssKey,	// IN
    	 string & strType,	// OUT
		 string & msgTag )  // OUT
{
    try 
	{
        ssKey >> strType;
		out << strType;

        if (strType == NAME)
        {
            string strAddress;
            ssKey >> strAddress;
			out << ':' << strAddress;
        }
        else if (strType == PURPOSE)
        {
            string strAddress;
            ssKey >> strAddress;
			out << ':' << strAddress;
        }
        else if (strType == TX)
        {
            uint256 hash;
            ssKey >> hash;
			out << ':' << hash.ToString();
        }
        else if (strType == ACENTRY)
        {
            string strAccount;
            uint64_t nNumber;

            ssKey >> strAccount;
            ssKey >> nNumber;

			out << ':' << strAccount << ':' << nNumber;
        }
        else if (strType == WATCHS)
        {
            CScript script;
            ssKey >> *static_cast<CScriptBase *>(&script);
			out << HexStr(script);
        }
        else if (strType == KEY || strType == WKEY)
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
			out << ':' << HexStr( vchPubKey );
        }
        else if (strType == MKEY)
        {
            unsigned int nID;
            ssKey >> nID;
			out << ':' << nID;
        }
        else if (strType == CKEY)
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
			out << ':' << HexStr( vchPubKey );
        }
        else if (strType == KEYMETA)
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
			out << ':' << HexStr( vchPubKey );
        }
        else if (strType == DEFAULTKEY)
        {
			// no-op
        }
        else if (strType == POOL)
        {
            int64_t nIndex;
            ssKey >> nIndex;
			out << ':' << nIndex;
        }
        else if (strType == VERSION)
        {
			// no-op
        }
        else if (strType == CSCRIPT)
        {
            uint160 hash;
            ssKey >> hash;
			out << ':' << hash.ToString();
        }
        else if (strType == ORDERPOSNEXT)
        {
			// no-op
        }
        else if (strType == DESTDATA)
        {
            std::string strAddress;
            ssKey >> strAddress;

            std::string strKey;
            ssKey >> strKey;

			out << ':' << strAddress << ':' << strKey;
        }
		else if( strType == BESTBLOCK )
		{
			// no-op
		}
		else if( strType == BESTBLOCK_NOMERKLE )
		{
			// no-op
		}
		else if( strType == MINVERSION )
		{
			// no-op
		}
		else if( strType == ACC )
		{
            std::string name;
            ssKey >> name;
			out << ':' << name;
		}
		else if( strType == ISSUER )
		{
            std::string name;
            ssKey >> name;
			out << ':' << name;
		}
		else if( strType == USER_MSG )
		{
			ssKey >> msgTag;
			uint256	hash;
			ssKey >> hash;
			out << ':' << msgTag << ':' << hash.ToString();
		}
#ifdef USE_HSM
		else if( strType == HSM_POOL )
		{
            int64_t nIndex;
            ssKey >> nIndex;
			out << ':' << nIndex;
		}
		else if( strType == HSM_KEY )
		{
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
			out << ':' << HexStr( vchPubKey );
		}
#endif
		else
		{
			out << "ERROR: Unsupported key [" << strType  << "]" << endl;
		}

		out << endl;
    } 
	catch (...)
    {
        return false;
    }

    return true;
}

bool
dumpValue(
	 		  ostream & out,     // OUT
			   string & strType, // IN
		  CDataStream & ssValue, // IN
	const std::string & msgTag ) // IN
{
    try 
	{
        if (strType == NAME)
        {
			string name;
            ssValue >> name;
			out << " \"" << name << "\"" << endl;
        }
        else if (strType == PURPOSE)
        {
			string purpose;
            ssValue >> purpose;
			out << " \"" << purpose << "\"" << endl;
        }
        else if (strType == TX)
        {
            CEDCWalletTx wtx;
            ssValue >> wtx;
			out << wtx.toJSON( " " );
        }
        else if (strType == ACENTRY)
        {
            CAccountingEntry acentry;
            ssValue >> acentry;

			out << " {\"account\":" << acentry.strAccount 
				<< " \",creditDebit\":" << acentry.nCreditDebit
				<< " \",time\":" << acentry.nTime
				<< " \",otherAccount\":" << acentry.strOtherAccount
				<< " \",comment\":" << acentry.strComment
				<< " \",mapValue\":[";

			auto i = acentry.mapValue.begin();
			auto e = acentry.mapValue.end();
			bool first = true;
			while( i != e )
			{
				if(!first)
					out << ",";
				else
					first = false;

				out << "[" << i->first << "," << i->second << "]";
				++i;
			}
			out << "]";

			out	<< " \",orderPos\":" << acentry.nOrderPos
				<< " \",entryNo\":" << acentry.nEntryNo
				<< "}\n";
        }
        else if (strType == WATCHS)
        {
            char fYes;
            ssValue >> fYes;
			out << " " << fYes << endl;
        }
        else if (strType == KEY )
        {
            CPrivKey pkey;
            uint256 hash;

            ssValue >> pkey;
            ssValue >> hash;

			out << " {\"key\":" << HexStr(pkey) << ",\"hash\":" << hash.ToString() << "}\n";
        }
        else if (strType == MKEY)
        {
            CMasterKey masterKey;
            ssValue >> masterKey;

			out << " {";
			out << "  \"cryptedKey\":" << HexStr(masterKey.vchCryptedKey) << "," << endl;
			out << "  \"salt\":" << HexStr(masterKey.vchSalt) << "," << endl;
			out << "  \"derivationMethod\":" << masterKey.nDerivationMethod << "," << endl;
			out << "  \"derivationIterations\":" << masterKey.nDeriveIterations << "," << endl;
			out << "  \"otherDerivationParamters\":" << HexStr(masterKey.vchOtherDerivationParameters) << endl;

			out << " }\n";
        }
        else if (strType == CKEY)
        {
            vector<unsigned char> privKey;
            ssValue >> privKey;

			out << " " << HexStr( privKey ) << endl;
        }
        else if (strType == KEYMETA)
        {
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;

			std::string t = ctime( &keyMeta.nCreateTime );
			t = t.substr( 0, t.size() - 1 );

			out << "{\"version\":" << keyMeta.nVersion << ", \"createTime\":" << t << "}" << endl;
        }
        else if (strType == DEFAULTKEY)
        {
			CPubKey defaultKey;
            ssValue >> defaultKey;
			out << " " << HexStr( defaultKey ) << endl;
        }
        else if (strType == POOL)
        {
            CKeyPool keypool;
            ssValue >> keypool;

			out << " {\"pool\":" << keypool.nTime << ", \"pubKey\":" << 
				HexStr(keypool.vchPubKey) << "}" << endl;
        }
        else if (strType == VERSION)
        {
			int fileVersion;
            ssValue >> fileVersion;
			out << " " << fileVersion << endl;
        }
        else if (strType == CSCRIPT)
        {
            CScript script;
            ssValue >> *(CScriptBase*)(&script);
			out << " " << HexStr(script) << endl;
        }
        else if (strType == ORDERPOSNEXT)
        {
			int64_t orderPosNext;
			ssValue >> orderPosNext;
			out << " " << orderPosNext << endl;
        }
        else if (strType == DESTDATA)
        {
            std::string strValue;
            ssValue >> strValue;
			out << " " << strValue << endl;
        }
		else if( strType == BESTBLOCK )
		{
			CBlockLocator locator;
			ssValue >> locator;

			out << " [\n";

			auto i = locator.vHave.begin();
			auto e = locator.vHave.end();

			bool first = true;
			while( i != e )
			{
				if(!first)
					out << ",\n";
				else
					first = false;
	
				out << HexStr(*i);
				++i;
			}

			out << "\n ]\n";
		}
		else if( strType == BESTBLOCK_NOMERKLE )
		{
			CBlockLocator locator;
			ssValue >> locator;

			out << " [\n";

			auto i = locator.vHave.begin();
			auto e = locator.vHave.end();

			bool first = true;
			while( i != e )
			{
				if(!first)
					out << ",\n";
				else
					first = false;
	
				out << HexStr(*i);
				++i;
			}

			out << "\n ]\n";
		}
		else if( strType == MINVERSION )
		{
			int version;
			ssValue >> version;
			out << " " << version << endl;
		}
		else if( strType == ACC )
		{
            CAccount acct;
            ssValue >> acct;
			out << " " << HexStr(acct.vchPubKey) << endl;
		}
		else if( strType == ISSUER )
		{
            CIssuer issuer;
            ssValue >> issuer;

			out << " {\"pubKey\":" << HexStr(issuer.pubKey_)
				<< ", \"location\":" << issuer.location_
				<< ", \"email\":" << issuer.emailAddress_
				<< ", \"phone_number\":" << issuer.phoneNumber_
				<< "}" << endl;
		}
		else if( strType == USER_MSG )
		{
			CUserMessage * msg = CUserMessage::create( msgTag, ssValue );
			out << msg->ToJSON() << endl;
			delete msg;
		}
#ifdef USE_HSM
		else if( strType == HSM_POOL )
		{
            CKeyPool keypool;
            ssValue >> keypool;

			out << " {\"hsm_pool\":" << keypool.nTime << ", \"pubKey\":" << 
				HexStr(keypool.vchPubKey) << "}" << endl;
		}
		else if( strType == HSM_KEY )
		{
			std::string hsmID;
			ssValue >> hsmID;
			out << " " << hsmID << endl;
		}
#endif
		else
		{
			edcLogPrintf( "Error: Unsupported key in walletdb\n" );
		}
    } 
	catch (...)
    {
        edcLogPrintf("Error getting value from wallet database cursor\n");
    }

    return true;
}

}

void CEDCWalletDB::Dump( ostream & out )
{
    try 
	{
        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            edcLogPrintf("Error getting wallet database cursor\n");
            return;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);

            int ret = ReadAtCursor(pcursor, ssKey, ssValue);

            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                edcLogPrintf("Error reading next record from wallet database\n");
                break;
            }

			string strType;
			string msgTag;
			if(!dumpKey( out, ssKey, strType, msgTag ))
				break;
			out << '[' << endl;
			if(!dumpValue( out, strType, ssValue, msgTag ))
				break;
			out << ']' << endl;
		}

        pcursor->close();
    }
    catch (...) 
	{
		// It is just a dump, so do not allow it to affect the process
    }
}

void CEDCWalletDB::ListIssuers( vector<pair<string,CIssuer>> & issuers )
{
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__) + ": cannot create DB cursor");

    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue);

        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__) + ": error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType == ISSUER)
		{
			string name;
        	ssKey >> name;

        	CIssuer issuer;
        	ssValue >> issuer;

        	issuers.push_back( make_pair(name, issuer) );
		}
    }

    pcursor->close();
}

bool CEDCWalletDB::WriteUserMsg(const CUserMessage * msg )
{
	EDCapp & theApp = EDCapp::singleton();
    theApp.incWalletDBUpdated();

	if( const CPeerToPeer * p2pmsg = dynamic_cast<const CPeerToPeer *>(msg))
		return Write( 
			make_pair( make_pair( USER_MSG, msg->vtag() ), msg->GetHash()), 
			*p2pmsg );
	else if( const CBroadcast * bmsg = dynamic_cast<const CBroadcast *>(msg))
		return Write( 
			make_pair( make_pair( USER_MSG, msg->vtag() ), msg->GetHash()), 
			*bmsg );
	else if( const CMulticast * mmsg = dynamic_cast<const CMulticast *>(msg))
		return Write( 
			make_pair( make_pair( USER_MSG, msg->vtag() ), msg->GetHash()), 
			*mmsg );

	assert(false);
	return false;
}

bool CEDCWalletDB::EraseUserMsg(const CUserMessage * msg )
{
	EDCapp & theApp = EDCapp::singleton();
    theApp.incWalletDBUpdated();
	return Erase( make_pair( make_pair( USER_MSG, msg->vtag() ), msg->GetHash()));
}

namespace
{
// They should be ordered in ascening order by the probablity that a message will be that type
//
const char * msgTypeTags[] =
{
	"Ask",
	"Bid",
	"Private",
	"Vote",
	"CashDividend",
	"Poll",
	"Acquisition",
	"Assimilation",
	"Bankruptcy",
	"BonusIssue",
	"BonusRights",
	"BuyBackProgram",
	"CashStockOption",
	"ClassAction",
	"ConversionOfConvertibleBonds",
	"CouponPayment",
	"Delisting",
	"DeMerger",
	"DividendReinvestmentPlan",
	"DutchAuction",
	"EarlyRedemption",
	"FinalRedemption",
	"GeneralAnnouncement",
	"InitialPublicOffering",
	"Liquidation",
	"Lottery",
	"MandatoryExchange",
	"Merger",
	"MergerWithElections",
	"NameChange",
	"OddLotTender",
	"OptionalPut",
	"OtherEvent",
	"PartialRedemption",
	"ParValueChange",
	"ReturnOfCapital",
	"ReverseStockSplit",
	"RightsAuction",
	"RightsIssue",
	"SchemeofArrangement",
	"ScripDividend",
	"ScripIssue",
	"Spinoff",
	"SpinOffWithElections",
	"StockDividend",
	"StockSplit",
	"SubscriptionOffer",
	"Takeover",
	"TenderOffer",
	"VoluntaryExchange",
	"WarrantExercise",
	"WarrantExpiry",
	"WarrantIssue",
	"AssetPrivate",
};
}

void CEDCWalletDB::GetMessage( const uint256 & hash, CUserMessage * & msg )
{
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__) + ": cannot create DB cursor");

	uint256 readHash = hash;

    for( size_t i = 0; i < (sizeof(msgTypeTags)/sizeof(char *)); ++i )
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);

        // Read next record
        ssKey << std::make_pair( 
			std::make_pair( USER_MSG, std::string(msgTypeTags[i])), readHash );

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, true );

        if (ret == DB_NOTFOUND)
            continue;
        if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__) + ": error scanning DB");
        }

		std::string readType;
		ssKey >> readType;

		// If we have gone past the USER_MSGs
		if( readType != USER_MSG )
			continue;

		ssKey >> readType;
		ssKey >> readHash;

		if( readHash != hash )
			continue;

		msg = CUserMessage::create( readType, ssValue );
		return;
    }

    pcursor->close();
	msg = NULL;
}

void CEDCWalletDB::DeleteMessage( const uint256 & hash )
{
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__) + ": cannot create DB cursor");

	uint256 readHash = hash;

    for( size_t i = 0; i < (sizeof(msgTypeTags)/sizeof(char *)); ++i )
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);

        // Read next record
        ssKey << std::make_pair( 
			std::make_pair( USER_MSG, std::string(msgTypeTags[i])), readHash );

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, true );

        if (ret == DB_NOTFOUND)
            continue;
        if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__) + ": error scanning DB");
        }

		std::string readType;
		ssKey >> readType;

		// If we have gone past the USER_MSGs
		if( readType != USER_MSG )
			continue;

		ssKey >> readType;
		ssKey >> readHash;

		if( readHash != hash )
			continue;

		CUserMessage * msg = CUserMessage::create( readType, ssValue );
		pcursor->close();
		EraseUserMsg( msg );
		delete msg;
		return;
	}
	pcursor->close();
}

namespace
{
bool keep(
	CPeerToPeer * msg,
	time_t from,
   	time_t to,
   	const std::set<std::string> & senders,
   	const std::set<std::string> & receivers )
{
	if( from && from < msg->second() )
		return false;

	if( to && to > msg->second() )
		return false;

	if( senders.size() && 
	( senders.find( msg->senderAddr() ) == senders.end() ))
		return false;

	if( receivers.size() &&
	( receivers.find( msg->receiverAddr() ) == receivers.end() ) )
		return false;

	return true;
}

bool keep(
	CMulticast * msg,
	time_t from,
   	time_t to,
   	const std::set<std::string> & senders )
{
	if( from && from < msg->second() )
		return false;

	if( to && to > msg->second() )
		return false;

	if( senders.size() && 
	( senders.find( msg->senderAddr() ) == senders.end() ) )
		return false;

	return true;
}

bool keep(
	CBroadcast * msg,
	time_t from,
   	time_t to,
   	const std::set<std::string> & senders )
{
	if( from && from < msg->second() )
		return false;

	if( to && to > msg->second() )
		return false;

	if( senders.size() && 
	( senders.find( msg->senderAddr() ) == senders.end() ) )
		return false;

	return true;
}

}

void CEDCWalletDB::GetMessages( 
		  const std::string & type,
    			  		Dbc * pcursor,
   					   time_t from,
    				   time_t to,
const std::set<std::string> & assets,
const std::set<std::string> & senders,
const std::set<std::string> & receivers,
std::vector<CUserMessage *> & out
)
{
	bool setRange = true;

	uint256	hash;

   	while (true)
   	{
   		// Read next record
   		CDataStream ssKey(SER_DISK, CLIENT_VERSION);
   		ssKey << std::make_pair( std::make_pair( USER_MSG, type ), hash );

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange );

   		if (ret == DB_NOTFOUND)
       		break;
   		else if (ret != 0)
   		{
       		pcursor->close();
       		throw runtime_error(std::string(__func__) + ": error scanning DB");
   		}

		std::string readType;
		ssKey >> readType;

		// If we have gone past the USER_MSGs
		if( readType != USER_MSG )
			break;

		ssKey >> readType;

		// If we the key loaded does not match the requested key
		if( type != readType )
			break;

		ssKey >> hash;

		// Get the next one for the rest of the loop
		setRange = false;

		CUserMessage * msg = CUserMessage::create( type, ssValue );

		if( CBroadcast * bmsg = dynamic_cast<CBroadcast *>(msg) )
		{
			if( keep( bmsg, from, to, senders ))
				out.push_back(msg);
			else
				delete msg;
		}
		else if( CMulticast * mmsg = dynamic_cast<CMulticast *>(msg) )
		{
			if( keep( mmsg, from, to, senders ))
				out.push_back(msg);
			else
				delete msg;
		}
		else
		{
			CPeerToPeer * p2pmsg = dynamic_cast<CPeerToPeer *>(msg);
			assert(p2pmsg);
			if( keep( p2pmsg, from, to, senders, receivers ))
				out.push_back(msg);
			else
				delete msg;
		}
   	}
}

void CEDCWalletDB::GetMessages( 
   		time_t from,
    	time_t to,
    	const std::set<std::string> & assets,
    	const std::set<std::string> & types,
    	const std::set<std::string> & senders,
    	const std::set<std::string> & receivers,
		   std::vector<CUserMessage *> & out
	)
{
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__) + ": cannot create DB cursor");

	if( types.size() )
	{
		auto i = types.begin();
		auto e = types.end();
		while( i != e )
		{
			GetMessages( *i, pcursor, from, to, assets, senders, receivers, out );
			++i;
		}
	}
	else
	{
    	for( size_t i = 0; i < (sizeof(msgTypeTags)/sizeof(char *)); ++i )
		{
			GetMessages( msgTypeTags[i], pcursor, from, to, assets, senders, receivers, out );
		}
	}

	pcursor->close();
}

void CEDCWalletDB::DeleteMessages( 
		  const std::string & type,
   					   time_t from,
    				   time_t to,
const std::set<std::string> & assets,
const std::set<std::string> & senders,
const std::set<std::string> & receivers
)
{
    Dbc * pcursor = NULL;

	bool setRange = false;
	uint256	hash;

   	while (true)
   	{
		if(!pcursor)
		{
    		pcursor = GetCursor();
		    if (!pcursor)
       			throw runtime_error(std::string(__func__) + ": cannot create DB cursor");
			setRange = true;
			hash.SetNull();
		}

   		// Read next record
   		CDataStream ssKey(SER_DISK, CLIENT_VERSION);
   		ssKey << std::make_pair( std::make_pair( USER_MSG, type ), hash );

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange );

   		if (ret == DB_NOTFOUND)
       		break;
   		else if (ret != 0)
   		{
       		pcursor->close();
       		throw runtime_error(std::string(__func__) + ": error scanning DB");
   		}

        std::string readType;
        ssKey >> readType;

        // If we have gone past the USER_MSGs
        if( readType != USER_MSG )
            break;

        ssKey >> readType;

        // If we the key loaded does not match the requested key
        if( type != readType )
            break;

        ssKey >> hash;

		// Get the next one for the rest of the loop
		setRange = false;

		CUserMessage * msg = CUserMessage::create( type, ssValue );

		if( CBroadcast * bmsg = dynamic_cast<CBroadcast *>(msg) )
		{
			if( keep( bmsg, from, to, senders ))
			{
       			pcursor->close();
				pcursor = NULL;
				EraseUserMsg( msg );
			}

			delete msg;
		}
		else if( CMulticast * mmsg = dynamic_cast<CMulticast *>(msg) )
		{
			if( keep( mmsg, from, to, senders ))
			{
       			pcursor->close();
				pcursor = NULL;
				EraseUserMsg( msg );
			}

			delete msg;
		}
		else
		{
			CPeerToPeer * p2pmsg = dynamic_cast<CPeerToPeer *>(msg);
			assert(p2pmsg);
			if( keep( p2pmsg, from, to, senders, receivers ))
			{
       			pcursor->close();
				pcursor = NULL;
				EraseUserMsg( msg );
			}

			delete msg;
		}
   	}

	if(pcursor)
		pcursor->close();
}

void CEDCWalletDB::DeleteMessages( 
	time_t from,
   	time_t to,
   	const std::set<std::string> & assets,
   	const std::set<std::string> & types,
   	const std::set<std::string> & senders,
   	const std::set<std::string> & receivers )
{
	if( types.size() )
	{
		auto i = types.begin();
		auto e = types.end();
		while( i != e )
		{
			DeleteMessages( *i, from, to, assets, senders, receivers );
			++i;
		}
	}
	else
	{
    	for( size_t i = 0; i < (sizeof(msgTypeTags)/sizeof(char *)); ++i )
		{
			DeleteMessages( msgTypeTags[i], from, to, assets, senders, receivers );
		}
	}
}


bool CEDCWalletDB::WriteHDChain(const CHDChain& chain)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::string(HDCHAIN), chain);
}
