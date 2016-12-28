// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "primitives/transaction.h"
#include "amount.h"
#include "uint256.h"
#include "pubkey.h"
#include "script/script.h"


class CEDCTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CEDCTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /* If CEDCTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /* If CEDCTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CEDCTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CEDCTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CEDCTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CEDCTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(prevout);
        READWRITE(*(CScriptBase*)(&scriptSig));
        READWRITE(nSequence);
    }

    friend bool operator==(const CEDCTxIn& a, const CEDCTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CEDCTxIn& a, const CEDCTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;

	std::string toJSON( const char * ) const;
};

enum Currency
{
	BTC
};

class CEDCTxOut
{
public:
	CAmount 	nValue;			// Num of equibits being transferred
	unsigned	wotMinLevel;	// Minimum WoT level used when coins moved
	uint256		receiptTxID;	// Related BTC Transaction ID (optional)
	Currency	payCurr;		// Payment currency
	CPubKey		issuerPubKey;	// Public Key of issuer
	CKeyID 		issuerAddr;		// Issuer's payment address
	CScript		scriptPubKey;	// Script defining the conditions needed to
								// spend the output (ie. smart contract)

    CEDCTxOut():nValue(0), wotMinLevel(0), payCurr(BTC)
    {
        SetNull();
    }

	CEDCTxOut( const CAmount & nValueIn, CScript scriptPubKeyIn );

    CEDCTxOut(	const CAmount & nValueIn, 
				       unsigned wotMinLevel, 
				const CPubKey &	issuerPubKey,
				 const CKeyID & issuerAddr,
				        CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(nValue);
		READWRITE(wotMinLevel);
		READWRITE(receiptTxID);
		READWRITE(issuerPubKey);
		READWRITE(issuerAddr);
		READWRITE(*(CScriptBase*)(&scriptPubKey));

		if(ser_action.ForRead())
		{
			int curr;
			READWRITE(curr);
			payCurr = static_cast<Currency>(curr);
		}
		else
		{
			int curr = payCurr;
			READWRITE(curr);
		}
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    uint256 GetHash() const;

    CAmount GetDustThreshold(const CFeeRate &minRelayTxFee) const
    {
        // "Dust" is defined in terms of CEDCTransaction::minRelayTxFee,
        // which has units satoshis-per-kilobyte.
        // If you'd pay more than 1/3 in fees
        // to spend something, then we consider it dust.
		// A typical spendable non-segwit txout is 34 bytes big, and will
        // need a CTxIn of at least 148 bytes to spend:
        // so dust is a spendable txout less than
        // 546*minRelayTxFee/1000 (in satoshis).
        // A typical spendable segwit txout is 31 bytes big, and will
        // need a CTxIn of at least 67 bytes to spend:
        // so dust is a spendable txout less than
        // 294*minRelayTxFee/1000 (in satoshis).
        if (scriptPubKey.IsUnspendable())
            return 0;

        size_t nSize = GetSerializeSize(SER_DISK, 0);
        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) 
		{
            // sum the sizes of the parts of a transaction input
            // with 75% segwit discount applied to the script size.
            nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
        } 
		else 
		{
            nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
        }

        return 3 * minRelayTxFee.GetFee(nSize);
    }

    bool IsDust(const CFeeRate &minRelayTxFee) const
    {
        return (nValue < GetDustThreshold(minRelayTxFee));
    }

    friend bool operator==(const CEDCTxOut& a, const CEDCTxOut& b)
    {
        return a.nValue  == b.nValue
			&& a.wotMinLevel == b.wotMinLevel
			&& a.receiptTxID == b.receiptTxID
			&& a.issuerPubKey == b.issuerPubKey
			&& a.issuerAddr == b.issuerAddr
            && a.scriptPubKey == b.scriptPubKey;
		;
    }

    friend bool operator!=(const CEDCTxOut& a, const CEDCTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;

	std::string toJSON( const char * ) const;
};

struct CEDCMutableTransaction;

/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - int32_t nVersion
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CTxWitness wit;
 * - uint32_t nLockTime
 */
template<typename Stream, typename Operation, typename TxType>
inline void edcSerializeTransaction(
	TxType & tx, 
	Stream & s, 
	Operation ser_action, 
	int nType, 
	int nVersion) 
{
    const bool fAllowWitness = !(nVersion & SERIALIZE_TRANSACTION_NO_WITNESS);

    READWRITE(*const_cast<int32_t*>(&tx.nVersion));
    unsigned char flags = 0;

    if (ser_action.ForRead()) 
	{
        const_cast<std::vector<CEDCTxIn>*>(&tx.vin)->clear();
        const_cast<std::vector<CEDCTxOut>*>(&tx.vout)->clear();
        const_cast<CTxWitness*>(&tx.wit)->SetNull();
        /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
        READWRITE(*const_cast<std::vector<CEDCTxIn>*>(&tx.vin));

        if (tx.vin.size() == 0 && fAllowWitness) 
		{
            /* We read a dummy or an empty vin. */
            READWRITE(flags);
            if (flags != 0) 
			{
                READWRITE(*const_cast<std::vector<CEDCTxIn>*>(&tx.vin));
                READWRITE(*const_cast<std::vector<CEDCTxOut>*>(&tx.vout));
            }
        } 
		else 
		{
            /* We read a non-empty vin. Assume a normal vout follows. */
            READWRITE(*const_cast<std::vector<CEDCTxOut>*>(&tx.vout));
        }
        if ((flags & 1) && fAllowWitness) 
		{
            /* The witness flag is present, and we support witnesses. */
            flags ^= 1;
            const_cast<CTxWitness*>(&tx.wit)->vtxinwit.resize(tx.vin.size());
            READWRITE(tx.wit);
        }
        if (flags) 
		{
            /* Unknown flag in the serialization */
            throw std::ios_base::failure("Unknown transaction optional data");
        }
    } 
	else 
	{
        // Consistency check
        assert(tx.wit.vtxinwit.size() <= tx.vin.size());
        if (fAllowWitness) 
		{
            /* Check whether witnesses need to be serialized. */
            if (!tx.wit.IsNull()) 
			{
                flags |= 1;
            }
        }
        if (flags) 
		{
            /* Use extended format in case witnesses are to be serialized. */
            std::vector<CEDCTxIn> vinDummy;
            READWRITE(vinDummy);
            READWRITE(flags);
        }
        READWRITE(*const_cast<std::vector<CEDCTxIn>*>(&tx.vin));
        READWRITE(*const_cast<std::vector<CEDCTxOut>*>(&tx.vout));
        if (flags & 1) 
		{
            const_cast<CTxWitness*>(&tx.wit)->vtxinwit.resize(tx.vin.size());
            READWRITE(tx.wit);
        }
    }
    READWRITE(*const_cast<uint32_t*>(&tx.nLockTime));
}


class CEDCTransaction
{
private:
    /** Memory only. */
	const uint256 hash;

public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION=1;

    // Changing the default transaction version requires a two step process: first
    // adapting relay policy by bumping MAX_STANDARD_VERSION, and then later date
    // bumping the default CURRENT_VERSION at which point both CURRENT_VERSION and
    // MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION=2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CEDCTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const int32_t nVersion;
    const std::vector<CEDCTxIn> vin;
    const std::vector<CEDCTxOut> vout;
	CTxWitness wit; // Not const: can change without invalidating the txid cache
    const uint32_t nLockTime;

	/** Construct a CEDCTransaction that qualifies as IsNull() */
	CEDCTransaction();

	/** Convert a CEDCMutableTransaction into a CEDCTransaction. */
	CEDCTransaction(const CEDCMutableTransaction &tx);

	CEDCTransaction& operator=(const CEDCTransaction& tx);

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        edcSerializeTransaction(*this, s, ser_action, nType, nVersion);
        if (ser_action.ForRead()) 
		{
            UpdateHash();
        }
	}

	bool IsNull() const 
	{
		return vin.empty() && vout.empty();
	}

	const uint256& GetHash() const 
	{
		return hash;
	}

    // Compute a hash that includes both transaction and witness data
    uint256 GetWitnessHash() const;

	// Return sum of txouts.
	CAmount GetValueOut() const;

	// GetValueIn() is a method on CCoinsViewCache, because
	// inputs must be known to compute value in.

	// Compute priority, given priority of inputs and (optionally) tx size
	double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

	// Compute modified tx size for priority calculation (optionally given tx size)
	unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;
    
    /**
     * Get the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const;

	bool IsCoinBase() const
	{
		return (vin.size() == 1 && vin[0].prevout.IsNull());
	}

	friend bool operator==(const CEDCTransaction& a, const CEDCTransaction& b)
	{
		return a.hash == b.hash;
	}

	friend bool operator!=(const CEDCTransaction& a, const CEDCTransaction& b)
	{
		return a.hash != b.hash;
	}

	std::string ToString() const;

	std::string toJSON( const char * ) const;

	void UpdateHash() const;
};

/** A mutable version of CEDCTransaction. */
struct CEDCMutableTransaction
{
	int32_t nVersion;
	std::vector<CEDCTxIn> vin;
	std::vector<CEDCTxOut> vout;
    CTxWitness wit;
	uint32_t nLockTime;

	CEDCMutableTransaction();
	CEDCMutableTransaction(const CEDCTransaction& tx);

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		edcSerializeTransaction(*this, s, ser_action, nType, nVersion);
	}

	/** Compute the hash of this CEDCMutableTransaction. This is computed on the
	 * fly, as opposed to GetHash() in CEDCTransaction, which uses a cached result.
	 */
	uint256 GetHash() const;
};

/** Compute the weight of a transaction, as defined by BIP 141 */
int64_t edcGetTransactionWeight(const CEDCTransaction &tx);
