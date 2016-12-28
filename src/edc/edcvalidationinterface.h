// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "validationinterface.h"
#include <boost/signals2/signal.hpp>
#include <boost/shared_ptr.hpp>

class CEDCBlock;
class CBlockIndex;
struct CBlockLocator;
class CBlockIndex;
class CReserveScript;
class CEDCTransaction;
class CEDCValidationInterface;
class CEDCConnman;
class CValidationState;
class uint256;

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CEDCValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CEDCValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void edcUnregisterAllValidationInterfaces();
/** Push an updated transaction to all registered wallets */
void SyncWithWallets(const CEDCTransaction& tx, const CBlockIndex *pindex, int posInBlock = -1);

class CEDCValidationInterface 
{
protected:
    virtual void UpdatedBlockTip(const CBlockIndex *pindex) {}
    virtual void SyncTransaction(const CEDCTransaction &tx, const CBlockIndex *pindex, int posInBlock) {}
    virtual void SetBestChain(const CBlockLocator &locator) {}
    virtual void UpdatedTransaction(const uint256 &hash) {}
    virtual void Inventory(const uint256 &hash) {}
    virtual void ResendWalletTransactions(int64_t nBestBlockTime, CEDCConnman * connman ) {}
    virtual void BlockChecked(const CEDCBlock&, const CValidationState&) {}
    virtual void GetScriptForMining(boost::shared_ptr<CReserveScript>&) {};
    virtual void ResetRequestCount(const uint256 &hash) {};
    friend void ::RegisterValidationInterface(CEDCValidationInterface*);
    friend void ::UnregisterValidationInterface(CEDCValidationInterface*);
    friend void ::edcUnregisterAllValidationInterfaces();
};

struct CEDCMainSignals 
{
    /** Notifies listeners of updated block chain tip */
    boost::signals2::signal<void (const CBlockIndex *)> UpdatedBlockTip;
    /** Notifies listeners of updated transaction data (transaction, and optionally the block it is found in. */
    boost::signals2::signal<void (const CEDCTransaction &, const CBlockIndex *pindex, int posInBlock)> SyncTransaction;
    /** Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible). */
    boost::signals2::signal<void (const uint256 &)> UpdatedTransaction;
    /** Notifies listeners of a new active block chain. */
    boost::signals2::signal<void (const CBlockLocator &)> SetBestChain;
    /** Notifies listeners about an inventory item being seen on the network. */
    boost::signals2::signal<void (const uint256 &)> Inventory;
    /** Tells listeners to broadcast their data. */
    boost::signals2::signal<void (int64_t nBestBlockTime, CEDCConnman * connman )> Broadcast;
    /** Notifies listeners of a block validation result */
    boost::signals2::signal<void (const CEDCBlock&, const CValidationState&)> BlockChecked;
    /** Notifies listeners that a key for mining is required (coinbase) */
    boost::signals2::signal<void (boost::shared_ptr<CReserveScript>&)> ScriptForMining;
    /** Notifies listeners that a block has been successfully mined */
    boost::signals2::signal<void (const uint256 &)> BlockFound;
};

CEDCMainSignals& edcGetMainSignals();

