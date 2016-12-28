// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "core_memusage.h"
#include "edc/primitives/edctransaction.h"
#include "edc/primitives/edcblock.h"
#include "memusage.h"


static inline size_t RecursiveDynamicUsage(const CEDCTxIn& in) 
{
    return RecursiveDynamicUsage(in.scriptSig) + RecursiveDynamicUsage(in.prevout);
}

static inline size_t RecursiveDynamicUsage(const CEDCTxOut& out) 
{
    return RecursiveDynamicUsage(out.scriptPubKey);
}

static inline size_t RecursiveDynamicUsage(const CEDCTransaction& tx) 
{
    size_t mem = memusage::DynamicUsage(tx.vin) + memusage::DynamicUsage(tx.vout) + RecursiveDynamicUsage(tx.wit);
    for (std::vector<CEDCTxIn>::const_iterator it = tx.vin.begin(); it != tx.vin.end(); it++) 
	{
        mem += RecursiveDynamicUsage(*it);
    }
    for (std::vector<CEDCTxOut>::const_iterator it = tx.vout.begin(); it != tx.vout.end(); it++) 
	{
        mem += RecursiveDynamicUsage(*it);
    }
    return mem;
}

static inline size_t RecursiveDynamicUsage(const CEDCMutableTransaction& tx) 
{
    size_t mem = memusage::DynamicUsage(tx.vin) + memusage::DynamicUsage(tx.vout) + RecursiveDynamicUsage(tx.wit);
    for (std::vector<CEDCTxIn>::const_iterator it = tx.vin.begin(); it != tx.vin.end(); it++) 
	{
        mem += RecursiveDynamicUsage(*it);
    }
    for (std::vector<CEDCTxOut>::const_iterator it = tx.vout.begin(); it != tx.vout.end(); it++) 
	{
        mem += RecursiveDynamicUsage(*it);
    }
    return mem;
}

static inline size_t RecursiveDynamicUsage(const CEDCBlock& block) 
{
    size_t mem = memusage::DynamicUsage(block.vtx);
    for (std::vector<CEDCTransaction>::const_iterator it = block.vtx.begin(); it != block.vtx.end(); it++) 
	{
        mem += RecursiveDynamicUsage(*it);
    }
    return mem;
}

