// Copyright (c) 2016 The Bitcoin developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "policy/rbf.h"
#include "edc/edctxmempool.h"

// Check whether the sequence numbers on this transaction are signaling
// opt-in to replace-by-fee, according to BIP 125
bool SignalsOptInRBF(const CEDCTransaction &tx);

// Determine whether an in-mempool transaction is signaling opt-in to RBF
// according to BIP 125
// This involves checking sequence numbers of the transaction, as well
// as the sequence numbers of all in-mempool ancestors.
RBFTransactionState IsRBFOptIn(const CEDCTransaction &tx, CEDCTxMemPool &pool);

