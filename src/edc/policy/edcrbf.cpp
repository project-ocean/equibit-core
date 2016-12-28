// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/policy/edcrbf.h"

bool SignalsOptInRBF(const CEDCTransaction &tx)
{
    BOOST_FOREACH(const CEDCTxIn &txin, tx.vin) 
	{
        if (txin.nSequence < std::numeric_limits<unsigned int>::max()-1) 
		{
            return true;
        }
    }
    return false;
}

RBFTransactionState IsRBFOptIn(const CEDCTransaction &tx, CEDCTxMemPool &pool)
{
    AssertLockHeld(pool.cs);

    CEDCTxMemPool::setEntries setAncestors;

    // First check the transaction itself.
    if (SignalsOptInRBF(tx)) 
	{
        return RBF_TRANSACTIONSTATE_REPLACEABLE_BIP125;
    }

    // If this transaction is not in our App.mempool, then we can't be sure
    // we will know about all its inputs.
    if (!pool.exists(tx.GetHash())) 
	{
        return RBF_TRANSACTIONSTATE_UNKNOWN;
    }

    // If all the inputs have nSequence >= maxint-1, it still might be
    // signaled for RBF if any unconfirmed parents have signaled.
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    CEDCTxMemPoolEntry entry = *pool.mapTx.find(tx.GetHash());
    pool.CalculateMemPoolAncestors(entry, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    BOOST_FOREACH(CEDCTxMemPool::txiter it, setAncestors) 
	{
        if (SignalsOptInRBF(it->GetTx())) 
		{
            return RBF_TRANSACTIONSTATE_REPLACEABLE_BIP125;
        }
    }
    return RBF_TRANSACTIONSTATE_FINAL;
}
