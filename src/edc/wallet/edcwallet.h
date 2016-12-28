// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "wallet/wallet.h"
#include "amount.h"
#include "streams.h"
#include "tinyformat.h"
#include "edc/edcui_interface.h"
#include "utilstrencodings.h"
#include "edc/edcvalidationinterface.h"
#include "edc/script/edcismine.h"
#include "wallet/crypter.h"
#include "edc/wallet/edcwalletdb.h"
#include "wallet/rpcwallet.h"
#include "edc/primitives/edctransaction.h"
#include "edc/rpc/edcpolling.h"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/shared_ptr.hpp>

class CEDCWallet;

/**
 * Settings
 */
//! if set, all keys will be derived by using BIP32
static const bool EDC_DEFAULT_USE_HD_WALLET = true;

extern const char * edcDEFAULT_WALLET_DAT;

class EDCapp;
class EDCparams;
class CBlockIndex;
class CCoinControl;
class CEDCBitcoinAddress;
class CEDCOutput;
class CEDCReserveKey;
class CScript;
class CEDCTxMemPool;
class CEDCWalletTx;
class CEDCBlock;
class WoTCertificate;


/** A transaction with a merkle branch linking it to the block chain. */
class CEDCMerkleTx : public CEDCTransaction
{
private:
  /** Constant used in hashBlock to indicate tx has been abandoned */
    static const uint256 ABANDON_HASH;

public:
    uint256 hashBlock;

    /* An nIndex == -1 means that hashBlock (in nonzero) refers to the earliest
     * block in the chain we know this or any in-wallet dependency conflicts
     * with. Older clients interpret nIndex == -1 as unconfirmed for backward
     * compatibility.
     */
    int nIndex;

    CEDCMerkleTx()
    {
        Init();
    }

    CEDCMerkleTx(const CEDCTransaction& txIn) : CEDCTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = uint256();
        nIndex = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        std::vector<uint256> vMerkleBranch; // For compatibility with older versions.
        READWRITE(*(CEDCTransaction*)this);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    int SetMerkleBranch(const CBlockIndex * pindex, int posInBlock );

    /**
     * Return depth of transaction in blockchain:
     * <0  : conflicts with a transaction this deep in the blockchain
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */
    int GetDepthInMainChain(const CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const 
	{ 
		const CBlockIndex *pindexRet; 
		return GetDepthInMainChain(pindexRet); 
	}
    bool IsInMainChain() const 	
	{ 
		const CBlockIndex *pindexRet; 
		return GetDepthInMainChain(pindexRet) > 0; 
	}
    int GetBlocksToMaturity() const;

    /** Pass this transaction to the mempool. Fails if absolute fee exceeds absurd fee. */
    bool AcceptToMemoryPool(bool fLimitFree, const CAmount nAbsurdFee);

    bool hashUnset() const 
	{ 
		return (hashBlock.IsNull() || hashBlock == ABANDON_HASH); 
	}
    bool isAbandoned() const 
	{ 
		return (hashBlock == ABANDON_HASH); 
	}
    void setAbandoned() 
	{ 
		hashBlock = ABANDON_HASH; 
	}

	std::string toJSON( const char * ) const;
};

/** 
 * A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CEDCWalletTx : public CEDCMerkleTx
{
private:
    const CEDCWallet * pwallet;

public:
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //!< time received by this node
    unsigned int nTimeSmart;
    char fFromMe;
    std::string strFromAccount;
    int64_t nOrderPos; //!< position in ordered transaction list

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fWatchDebitCached;
    mutable bool fWatchCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable CAmount nDebitCached;
    mutable CAmount nCreditCached;
    mutable CAmount nImmatureCreditCached;
    mutable CAmount nAvailableCreditCached;
    mutable CAmount nWatchDebitCached;
    mutable CAmount nWatchCreditCached;
    mutable CAmount nImmatureWatchCreditCached;
    mutable CAmount nAvailableWatchCreditCached;
    mutable CAmount nChangeCached;

    CEDCWalletTx()
    {
        Init(NULL);
    }

    CEDCWalletTx(const CEDCWallet* pwalletIn)
    {
        Init(pwalletIn);
    }

    CEDCWalletTx(const CEDCWallet* pwalletIn, const CEDCMerkleTx& txIn) : CEDCMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    CEDCWalletTx(const CEDCWallet* pwalletIn, const CEDCTransaction& txIn) : CEDCMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    void Init(const CEDCWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        fDebitCached = false;
        fCreditCached = false;
        fImmatureCreditCached = false;
        fAvailableCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nCreditCached = 0;
        nImmatureCreditCached = 0;
        nAvailableCreditCached = 0;
        nWatchDebitCached = 0;
        nWatchCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        if (ser_action.ForRead())
            Init(NULL);
        char fSpent = false;

        if (!ser_action.ForRead())
        {
            mapValue["fromaccount"] = strFromAccount;

            WriteOrderPos(nOrderPos, mapValue);

            if (nTimeSmart)
                mapValue["timesmart"] = strprintf("%u", nTimeSmart);
        }

        READWRITE(*(CEDCMerkleTx*)this);
        std::vector<CEDCMerkleTx> vUnused; //!< Used to be vtxPrev
        READWRITE(vUnused);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (ser_action.ForRead())
        {
            strFromAccount = mapValue["fromaccount"];

            ReadOrderPos(nOrderPos, mapValue);

            nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(mapValue["timesmart"]) : 0;
        }

        mapValue.erase("fromaccount");
        mapValue.erase("version");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
    }

    //! make sure balances are recalculated
    void MarkDirty()
    {
        fCreditCached = false;
        fAvailableCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CEDCWallet *pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    //! filter decides which addresses will count towards the debit
    CAmount GetDebit(const isminefilter& filter) const;
    CAmount GetCredit(const isminefilter& filter) const;
    CAmount GetImmatureCredit(bool fUseCache=true) const;
    CAmount GetAvailableCredit(bool fUseCache=true) const;
    CAmount GetImmatureWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetAvailableWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetChange() const;

    void GetAmounts(std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent, 
					CAmount& nFee, 
					std::string& strSentAccount, 
					const isminefilter& filter) const;

    void GetAccountAmounts(	const std::string& strAccount, 
							CAmount& nReceived,
                           	CAmount& nSent, 
							CAmount& nFee, 
							const isminefilter& filter) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    // True if only scriptSigs are different
    bool IsEquivalentTo(const CEDCWalletTx& tx) const;

    bool InMempool() const;
    bool IsTrusted() const;

    int64_t GetTxTime() const;
    int GetRequestCount() const;

    bool RelayWalletTransaction(CEDCConnman * connman);

    std::set<uint256> GetConflicts() const;

	std::string toJSON( const char * margin ) const;
};

class CEDCOutput
{
public:
    const CEDCWalletTx *tx;
    int i;
    int nDepth;
    bool fSpendable;
    bool fSolvable;

    CEDCOutput(const CEDCWalletTx * txIn, int iIn, int nDepthIn, bool fSpendableIn, bool fSolvableIn)
    {
        tx = txIn; i = iIn; nDepth = nDepthIn; fSpendable = fSpendableIn; fSolvable = fSolvableIn;
    }

    std::string ToString() const;
};

/** 
 * A CEDCWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
class CEDCWallet : public CCryptoKeyStore, public CEDCValidationInterface
{
private:

	typedef std::set<std::pair<const CEDCWalletTx*,unsigned int> > CoinSet;

	bool AddFee(
                EDCapp & theApp,   			// IN
             EDCparams & params,   	 		// IN
                double dPriorityIn,	 		// IN: Priority from authorized coins
               CoinSet & authCoins, 		// IN: Authorized coins
CEDCMutableTransaction & txIn,				// IN: Input Transaction
		  CEDCWalletTx & wtxNew,   			// OUT: The wallet transaction
	    CEDCReserveKey & reservekey,		// IN/OUT: Key from pool to be destination of change
				   int & nChangePosInOut,	// IN/OUT: Position in txn for change
               CAmount & nFeeRet,   		// OUT: The computed fee
		   std::string & strFailReason,		// OUT: Reason for failure
	const CCoinControl * coinControl = NULL,// IN
				    bool sign = true		// IN
		) const;

    /**
     * Select a set of coins such that nValueRet >= nTargetValue and at least
     * all coins from coinControl are selected; Never select unconfirmed coins
     * if they are not ours
     */
    bool SelectCoins(
		const std::vector<CEDCOutput>& vAvailableCoins, 
		const CAmount & nTargetValue, 
		std::set<std::pair<const CEDCWalletTx*,unsigned int> >& setCoinsRet, 
		CAmount& nValueRet, 
		const CCoinControl *coinControl = NULL) const;

    CEDCWalletDB *pwalletdbEncryption;

    //! the current wallet version: clients below this version are not able to
	//  load the wallet
    int nWalletVersion;

    //! the maximum wallet format version: memory-only variable that specifies 
	//  to what version this wallet may be upgraded
    int nWalletMaxVersion;

    int64_t nNextResend;
    int64_t nLastResend;
    bool fBroadcastTransactions;

    /**
     * Used to keep track of spent outpoints, and
     * detect and report conflicts (double-spends or
     * mutated transactions where the mutant gets mined).
     */
    typedef std::multimap<COutPoint, uint256> TxSpends;

    TxSpends mapTxSpends;
    void AddToSpends(const COutPoint& outpoint, const uint256& wtxid);
    void AddToSpends(const uint256& wtxid);

    /* Mark a transaction (and its in-wallet descendants) as conflicting with 
	 * a particular block. */
    void MarkConflicted(const uint256& hashBlock, const uint256& hashTx);

    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>);

    /* the HD chain data model (external chain counters) */
    CHDChain hdChain;

	bool fFileBacked;

    std::map< std::pair<std::string, uint256 >, CUserMessage *> messageMap;

	//               pubkey      authoring Key/revoke reason
	struct WoTdata
	{
		WoTdata( const CPubKey & pk ): pubkey(pk), revoked(false)
		{
		}
		WoTdata( const CPubKey & pk, const std::string & reason ): 
			pubkey(pk), revoked(true), revokeReason(reason)
		{
		}

		CPubKey		pubkey;
		bool		revoked;
		std::string	revokeReason;
	};

	std::multimap< CPubKey, WoTdata >	wotCertificates;

#ifdef USE_HSM
	std::map<CKeyID, std::pair<CPubKey, std::string > > hsmKeyMap;

	void GetHSMKeys( std::set<CKeyID> & ) const;
#endif

	bool wotChainExists(const CPubKey & spk, const CPubKey & epk, 
						uint64_t currlen, uint64_t maxlen );
	bool wotChainExists(const CPubKey & spk, const CPubKey & epk, const CPubKey & expk,
						uint64_t currlen, uint64_t maxlen );

	struct Proxy
	{
		//       Poll ID           Proxy addr/time stamp/is_active
		std::map<std::string, std::tuple<CKeyID, std::string, bool> >	pollProxies;

		//       Issuer            Proxy addr/time stamp/is_active
		std::map<CKeyID, std::tuple<CKeyID, std::string, bool> >	issuerProxies;

		//         Proxy addr/timestamp/is_active
		std::tuple<CKeyID, std::string, bool> generalProxy;
	};

	//			address
	std::map<CKeyID, Proxy>			proxyMap;
	std::map<uint256, Poll>			polls;
	std::map<uint256, PollResult>	pollResults;

public:
    /*
     * Main wallet lock.
     * This lock protects all the fields added by CEDCWallet
     *   except for:
     *      fFileBacked (immutable after instantiation)
     *      strWalletFile (immutable after instantiation)
     */
    mutable CCriticalSection cs_wallet;

	std::set<int64_t>	setKeyPool;

    std::string strWalletFile;

    void LoadKeyPool(int nIndex, const CKeyPool &keypool)
    {
        setKeyPool.insert(nIndex);

        // If no metadata exists yet, create a default with the pool key's
        // creation time. Note that this may be overwritten by actually
        // stored metadata for that key later, which is fine.
        CKeyID keyid = keypool.vchPubKey.GetID();
        if (mapKeyMetadata.count(keyid) == 0)
            mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
    }

#ifdef USE_HSM
    std::set<int64_t> setHSMKeyPool;
#endif
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    CEDCWallet()
    {
        SetNull();
    }

    CEDCWallet(const std::string& strWalletFileIn)
    {
        SetNull();

        strWalletFile = strWalletFileIn;
        fFileBacked = true;
    }

    ~CEDCWallet()
    {
        delete pwalletdbEncryption;
        pwalletdbEncryption = NULL;
    }

    void SetNull()
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        nOrderPosNext = 0;
        nNextResend = 0;
        nLastResend = 0;
        nTimeFirstKey = 0;
        fBroadcastTransactions = false;
    }

    std::map<uint256, CEDCWalletTx> mapWallet;
    std::list<CAccountingEntry> laccentries;

    typedef std::pair<CEDCWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems wtxOrdered;

    int64_t nOrderPosNext;
    std::map<uint256, int> mapRequestCount;

    std::map<CTxDestination, CAddressBookData> mapAddressBook;

    CPubKey vchDefaultKey;

    std::set<COutPoint> setLockedCoins;

    int64_t nTimeFirstKey;

    const CEDCWalletTx* GetWalletTx(const uint256& hash) const;

    //! check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf) 
	{ 
		AssertLockHeld(cs_wallet); 
		return nWalletMaxVersion >= wf; 
	}

    /**
     * populate vCoins with vector of available CEDCOutputs.
     */
    void AvailableCoins(
		std::vector<CEDCOutput>& vCoins, 
		bool fOnlyConfirmed=true, 
		const CCoinControl *coinControl = NULL, 
		bool fIncludeZeroValue=false) const;

    /**
     * populate vCoins with vector of available CEDCOutputs authorized by issuer.
     */
    void AvailableCoins(
		std::vector<CEDCOutput>& vCoins, 
		CEDCBitcoinAddress & issuer,
					unsigned wotlvl,
						bool fOnlyConfirmed=true, 
		const CCoinControl * coinControl = NULL, 
						bool fIncludeZeroValue=false
	) const;

    /**
     * Shuffle and select coins until nTargetValue is reached while avoiding
     * small change; This method is stochastic for some inputs and upon
     * completion the coin set and corresponding actual target value is
     * assembled
     */
    bool SelectCoinsMinConf(
		const CAmount& nTargetValue, 
		int nConfMine, 
		int nConfTheirs, 
		std::vector<CEDCOutput> vCoins, 
		std::set<std::pair<const CEDCWalletTx*,unsigned int> >& setCoinsRet, 
		CAmount& nValueRet) const;

    bool IsSpent(const uint256& hash, unsigned int n) const;

    bool IsLockedCoin(uint256 hash, unsigned int n) const;
    void LockCoin(const COutPoint& output);
    void UnlockCoin(const COutPoint& output);
    void UnlockAllCoins();
    void ListLockedCoins(std::vector<COutPoint>& vOutpts);

    /**
     * keystore implementation
     * Generate a new key
     */
    CPubKey GenerateNewKey();
#ifdef USE_HSM
    CPubKey GenerateNewHSMKey();
	bool GetHSMPubKey( const CKeyID & address, CPubKey & vchPubKeyOut ) const;
#endif

    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);

#ifdef USE_HSM
	//! Adds a public key and HSM ID to the map
	bool AddHSMKey( const CPubKey &, const std::string & hsmID );
	
	//! Returns HSM ID corresponding to the CKeyID, if it exists
	//
	bool GetHSMKey( const CKeyID &, std::string & hsmID ) const;

	bool HaveHSMKey( const CKeyID & address ) const;
#endif

    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey) 
	{ 
		return CCryptoKeyStore::AddKeyPubKey(key, pubkey); 
	}

    //! Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &metadata);

    bool LoadMinVersion(int nVersion) 
	{ 
		AssertLockHeld(cs_wallet); 
		nWalletVersion = nVersion; 
		nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion); 
		return true; 
	}

    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);

    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);

    bool AddCScript(const CScript& redeemScript);
    bool LoadCScript(const CScript& redeemScript);

    //! Adds a destination data tuple to the store, and saves it to disk
    bool AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value);

    //! Erases a destination data tuple in the store and on disk
    bool EraseDestData(const CTxDestination &dest, const std::string &key);

    //! Adds a destination data tuple to the store, without saving it to disk
    bool LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value);

    //! Look up a destination data tuple in the store, return true if found false otherwise
    bool GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const;

    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript &dest);
    bool RemoveWatchOnly(const CScript &dest);

    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);

    bool Unlock(const SecureString& strWalletPassphrase);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);

    void GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const;
#ifdef USE_HSM
    void GetHSMKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const;
#endif

    /** 
     * Increment the next transaction order id
     * @return next transaction order id
     */
    int64_t IncOrderPosNext(CEDCWalletDB *pwalletdb = NULL);
	DBErrors ReorderTransactions();

    bool AccountMove(std::string strFrom, std::string strTo, CAmount nAmount, std::string strComment = "");
	bool GetAccountPubkey(CPubKey &pubKey, std::string strAccount, bool bForceNew = false);
    void MarkDirty();
    bool AddToWallet(const CEDCWalletTx& wtxIn, bool fFlushOnClose=true);
	bool LoadToWallet(const CEDCWalletTx& wtxIn);
    void SyncTransaction(const CEDCTransaction& tx, const CBlockIndex *pindex, int posInBlock);
    bool AddToWalletIfInvolvingMe(const CEDCTransaction& tx, const CBlockIndex* pIndex, int posInBlock, bool fUpdate);
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
    void ReacceptWalletTransactions();
    void ResendWalletTransactions(int64_t nBestBlockTime, CEDCConnman * connman);
    std::vector<uint256> ResendWalletTransactionsBefore(int64_t nTime, CEDCConnman * connman);
    CAmount GetBalance() const;
    CAmount GetUnconfirmedBalance() const;
    CAmount GetImmatureBalance() const;
    CAmount GetWatchOnlyBalance() const;
    CAmount GetUnconfirmedWatchOnlyBalance() const;
    CAmount GetImmatureWatchOnlyBalance() const;

    /**
     * Insert additional inputs into the transaction by
     * calling CreateTransaction();
     */
    bool FundTransaction(
		CEDCMutableTransaction & tx, 
					   CAmount & nFeeRet, 
							bool overrideEstimatedFeeRate,
				const CFeeRate & specificFeeRate, 
						   int & nChangePosInOut, 
				   std::string & strFailReason, 
							bool includeWatching, 
							bool lockUnspents, 
		  const CTxDestination & destChange = CNoDestination());

    /**
     * Create a new transaction paying the recipients with a set of coins
     * selected by SelectCoins(); Also create the change output, when needed
     * @note passing nChangePosInOut as -1 will result in setting a random position
     */
    bool CreateTransaction(
		const std::vector<CRecipient> & vecSend, 
						 CEDCWalletTx & wtxNew, 
					   CEDCReserveKey & reservekey, 
							  CAmount & nFeeRet, 
								  int & nChangePosInOut,
        				  std::string & strFailReason, 
				   const CCoinControl * coinControl = NULL, 
								   bool sign = true);

    /**
     * Create a new transaction that is created to authorize the EQB of the
     * input TxOut.
     */
    bool CreateAuthorizingTransaction(
                        const CIssuer & issuer,
							   unsigned wotLvl,
		const std::vector<CRecipient> & vecSend, 
						 CEDCWalletTx & wtxNew, 
					   CEDCReserveKey & reservekey, 
							  CAmount & nFeeRet, 
								  int & nChangePosInOut,
        				  std::string & strFailReason );

    /**
     * Create a new transaction that is created to blank the EQB of the input TxOut.
     */
    bool CreateBlankingTransaction(
                        const CIssuer & issuer,
		const std::vector<CRecipient> & vecSend, 
						 CEDCWalletTx & wtxNew, 
					   CEDCReserveKey & reservekey, 
                                   bool feeFromBlank,
							  CAmount & nFeeRet, 
								  int & nChangePosInOut,
        				  std::string & strFailReason );

    /**
     * Create a new trusted transaction paying the recipients with a set of coins
     * selected by SelectCoins(); Also create the change output, when needed
     * @note passing nChangePosInOut as -1 will result in setting a random position
     */
    bool CreateTrustedTransaction(
				   CEDCBitcoinAddress & issuer, 
							   unsigned wotLvl,
		const std::vector<CRecipient> & vecSend, 
						 CEDCWalletTx & wtxNew, 
					   CEDCReserveKey & reservekey, 
							  CAmount & nFeeRet, 
								  int & nChangePosInOut,
        				  std::string & strFailReason, 
				   const CCoinControl * coinControl = NULL, 
								   bool sign = true);

    bool CommitTransaction(CEDCWalletTx& wtxNew, CEDCReserveKey& reservekey, CEDCConnman * connman);

	void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& entries);

    bool AddAccountingEntry(const CAccountingEntry&);
    bool AddAccountingEntry(const CAccountingEntry&, CEDCWalletDB *pwalletdb);

    static CFeeRate minTxFee;
    static CFeeRate fallbackFee;

    /**
     * Estimate the minimum fee considering user set parameters
     * and the required fee
     */
    static CAmount GetMinimumFee(
			 unsigned int nTxBytes, 
			 unsigned int nConfirmTarget, 
	const CEDCTxMemPool & pool);

    /**
     * Return the minimum required fee taking into account the
     * floating relay fee and user set minimum transaction fee
     */
    static CAmount GetRequiredFee(unsigned int nTxBytes);

    bool NewKeyPool();
    bool TopUpKeyPool(unsigned int kpSize = 0);
    void ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool);
    void KeepKey(int64_t nIndex);
    void ReturnKey(int64_t nIndex);
    bool GetKeyFromPool(CPubKey &key);
#ifdef USE_HSM
    bool NewHSMKeyPool();
    bool TopUpHSMKeyPool(unsigned int kpSize = 0);
    void ReserveKeyFromHSMKeyPool(int64_t& nIndex, CKeyPool& keypool);
    void KeepHSMKey(int64_t nIndex);
    void ReturnHSMKey(int64_t nIndex);
    bool GetHSMKeyFromPool(CPubKey &key);
    int64_t GetOldestHSMKeyPoolTime();
    void GetAllReserveHSMKeys(std::set<CKeyID>& setAddress) const;
#endif
    int64_t GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID>& setAddress) const;

    std::set< std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, CAmount> GetAddressBalances();

	CAmount GetAccountBalance(const std::string& strAccount, int nMinDepth, const isminefilter& filter);
	CAmount GetAccountBalance( CEDCWalletDB& walletdb, const std::string& strAccount, int nMinDepth, const isminefilter& filter);

    std::set<CTxDestination> GetAccountAddresses(const std::string& strAccount) const;

    isminetype IsMine(const CEDCTxIn& txin) const;
    CAmount GetDebit(const CEDCTxIn& txin, const isminefilter& filter) const;
    isminetype IsMine(const CEDCTxOut& txout) const;
    CAmount GetCredit(const CEDCTxOut& txout, const isminefilter& filter) const;
    bool IsChange(const CEDCTxOut& txout) const;
    CAmount GetChange(const CEDCTxOut& txout) const;
    bool IsMine(const CEDCTransaction& tx) const;
    /** should probably be renamed to IsRelevantToMe */
    bool IsFromMe(const CEDCTransaction& tx) const;
    CAmount GetDebit(const CEDCTransaction& tx, const isminefilter& filter) const;
    CAmount GetCredit(const CEDCTransaction& tx, const isminefilter& filter) const;
    CAmount GetChange(const CEDCTransaction& tx) const;
    void SetBestChain(const CBlockLocator& loc);

    DBErrors LoadWallet(bool& fFirstRunRet);
    DBErrors ZapWalletTx(std::vector<CEDCWalletTx>& vWtx);
    DBErrors ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut);

    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& purpose);

    bool DelAddressBook(const CTxDestination& address);

    void UpdatedTransaction(const uint256 &hashTx);

    void Inventory(const uint256 &hash)
    {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end())
                (*mi).second++;
        }
    }

    void GetScriptForMining(boost::shared_ptr<CReserveScript> &script);
    void ResetRequestCount(const uint256 &hash)
    {
        LOCK(cs_wallet);
        mapRequestCount[hash] = 0;
    };
    
    unsigned int GetKeyPoolSize()
    {
        AssertLockHeld(cs_wallet); // setKeyPool
        return setKeyPool.size();
    }

#ifdef USE_HSM
    unsigned int GetHSMKeyPoolSize()
    {
        AssertLockHeld(cs_wallet); // setHSMKeyPool
        return setHSMKeyPool.size();
    }
#endif

    bool SetDefaultKey(const CPubKey &vchPubKey);

    //! signify that a particular wallet feature is now used. this may change nWalletVersion and 
	//  nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CEDCWalletDB * pwalletdbIn = NULL, bool fExplicit = false);

    //! change which version we're allowed to upgrade to (note that this does not immediately 
	//  imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    //! get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion() { LOCK(cs_wallet); return nWalletVersion; }

    //! Get wallet transactions that conflict with given transaction (spend same outputs)
    std::set<uint256> GetConflicts(const uint256& txid) const;

    //! Flush wallet (bitdb flush)
    void Flush(bool shutdown=false);

    //! Verify the wallet database and perform salvage if required
    static bool Verify();
    
    /** 
     * Address book entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CEDCWallet *wallet, const CTxDestination
            &address, const std::string &label, bool isMine,
            const std::string &purpose,
            ChangeType status)> NotifyAddressBookChanged;

    /** 
     * Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CEDCWallet *wallet, const uint256 &hashTx,
            ChangeType status)> NotifyTransactionChanged;

    /** Show progress e.g. for rescan */
    boost::signals2::signal<void (const std::string &title, int nProgress)> ShowProgress;

    /** Watch-only address added */
    boost::signals2::signal<void (bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** Inquire whether this wallet broadcasts transactions. */
    bool GetBroadcastTransactions() const { return fBroadcastTransactions; }

    /** Set whether this wallet broadcasts transactions. */
    void SetBroadcastTransactions(bool broadcast) { fBroadcastTransactions = broadcast; }

    /* Mark a transaction (and it in-wallet descendants) as abandoned so its 
       inputs may be respent. */
    bool AbandonTransaction(const uint256& hashTx);

	/** Load Message into the wallet **/
	void LoadMessage( CUserMessage * msg );
	bool AddMessage( CUserMessage * msg );

	void GetMessage( const uint256 &, CUserMessage * & msg );
	void DeleteMessage( const uint256 & );

	void GetMessages( 
   		time_t from,
    	time_t to,
    	const std::set<std::string> & assets,
    	const std::set<std::string> & types,
    	const std::set<std::string> & senders,
    	const std::set<std::string> & receivers,
		   std::vector<CUserMessage *> & out
	);
	void DeleteMessages( 
   		time_t from,
    	time_t to,
    	const std::set<std::string> & assets,
    	const std::set<std::string> & types,
    	const std::set<std::string> & senders,
    	const std::set<std::string> & receivers );

    /* Returns the wallets help message */
    static std::string GetWalletHelpString(bool showDebug);

    /* Initializes the wallet, returns a new CEDCWallet instance or a null pointer 
	   in case of an error */
    static bool InitLoadWallet();

    /* Wallets parameter interaction */
    static bool ParameterInteraction();

	bool BackupWallet(const std::string& strDest);

    /* Set the HD chain model (chain child index counters) */
    bool SetHDChain(const CHDChain& chain, bool memonly);
	const CHDChain& GetHDChain() { return hdChain; }

    /* Returns true if HD is enabled */
    bool IsHDEnabled();

    /* Generates a new HD master key (will not be activated) */
    CPubKey GenerateNewHDMasterKey();

    /* Set the current HD master key (will reset the chain child index counters) */
    bool SetHDMasterKey(const CPubKey& key);

	bool AddWoTCertificate( const CPubKey & pk1, const CPubKey & pk2, const WoTCertificate & cert,
		std::string & );
	bool RevokeWoTCertificate(const CPubKey & pk1, const CPubKey & pk2, 
							  const std::string & reason, std::string & );
	bool DeleteWoTCertificate(const CPubKey & pk1, const CPubKey & pk2, std::string & );
	bool WoTchainExists( const CPubKey &, const CPubKey &, uint64_t );
	bool WoTchainExists( const CPubKey &, const CPubKey &, const CPubKey &, uint64_t );

	void LoadWoTCertificate( const CPubKey & pk1, const CPubKey & pk2, const WoTCertificate & cert );
	void LoadWoTCertificateRevoke( const CPubKey & pk1, const CPubKey & pk2, const std::string & reason );

	bool AddGeneralProxy( const CKeyID &, const CKeyID &, std::string & );
	bool AddGeneralProxyRevoke(  const CKeyID &, const CKeyID &, std::string & );
	bool AddIssuerProxy(const CKeyID &, const CKeyID &, const CKeyID &, std::string & );
	bool AddIssuerProxyRevoke(  const CKeyID &, const CKeyID &, const CKeyID &, std::string & );
	bool AddPollProxy(  const CKeyID &, const CKeyID &, const std::string &, std::string & );
	bool AddPollProxyRevoke( const CKeyID &, const CKeyID &, const std::string &, std::string & );

	bool VerifyProxy( const std::string & ts, const std::string & addr, const std::string & paddr, 
		const std::string & other, const std::vector<unsigned char > &, std::string & );

	void LoadGeneralProxy( const std::string & ts, const CKeyID &, const CKeyID & );
	void LoadGeneralProxyRevoke( const std::string & ts, const CKeyID &, const CKeyID & );
	void LoadIssuerProxy( const std::string & ts, const CKeyID &, const CKeyID &, const CKeyID & );
	void LoadIssuerProxyRevoke( const std::string & ts, const CKeyID &, const CKeyID &, const CKeyID & );
	void LoadPollProxy( const std::string & ts, const CKeyID &, const CKeyID &, const std::string & );
	void LoadPollProxyRevoke( const std::string & ts, const CKeyID &, const CKeyID &, const std::string & );

	bool AddPoll( const Poll &, const uint256 &, std::string & );
	
	bool pollResult( const uint256 &, const PollResult * & ) const;

	bool AddVote( struct timespec &, const CKeyID & addr, const CKeyID & iaddr, const std::string & pollid,
			const std::string & response, const CKeyID & pAddr, std::string & errStr );
};

/** A key allocated from the key pool. */
class CEDCReserveKey : public CReserveScript
{
protected:
    CEDCWallet* pwallet;
    int64_t nIndex;
    CPubKey vchPubKey;
public:
    CEDCReserveKey(CEDCWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn;
    }

    ~CEDCReserveKey()
    {
        ReturnKey();
    }

    void ReturnKey();
    bool GetReservedKey(CPubKey &pubkey);
    void KeepKey();
    void KeepScript() { KeepKey(); }
};

class CIssuer
{
public:
	CPubKey pubKey_;
	std::string location_;
	std::string emailAddress_;
	std::string phoneNumber_;

	CIssuer( 
		const std::string & loc, 
		const std::string & ea, 
		const std::string & pn ):
		location_(loc),
		emailAddress_(ea),
		phoneNumber_(pn)
	{
		SetNull();
	}

	CIssuer()
	{
		SetNull();
	}

	void SetNull()
	{
		pubKey_ = CPubKey();
	}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation >
	inline void SerializationOp( 
		 Stream & s, 
		Operation ser_action, 
			  int nType, 
			  int nVersion )
	{
		if(!(nType & SER_GETHASH))
			READWRITE(nVersion);
		READWRITE(pubKey_);
		READWRITE(location_);
		READWRITE(emailAddress_);
		READWRITE(phoneNumber_);
	}
};
