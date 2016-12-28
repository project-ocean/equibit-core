// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcvalidationinterface.h"

static CEDCMainSignals g_signals;

CEDCMainSignals& edcGetMainSignals()
{
    return g_signals;
}

void RegisterValidationInterface(CEDCValidationInterface* pwalletIn) 
{
    g_signals.UpdatedBlockTip.connect(boost::bind(&CEDCValidationInterface::UpdatedBlockTip, pwalletIn, _1));
    g_signals.SyncTransaction.connect(boost::bind(&CEDCValidationInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.UpdatedTransaction.connect(boost::bind(&CEDCValidationInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.SetBestChain.connect(boost::bind(&CEDCValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.Inventory.connect(boost::bind(&CEDCValidationInterface::Inventory, pwalletIn, _1));
    g_signals.Broadcast.connect(boost::bind(&CEDCValidationInterface::ResendWalletTransactions, pwalletIn, _1, _2));
    g_signals.BlockChecked.connect(boost::bind(&CEDCValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.ScriptForMining.connect(boost::bind(&CEDCValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.BlockFound.connect(boost::bind(&CEDCValidationInterface::ResetRequestCount, pwalletIn, _1));
}

void UnregisterValidationInterface(CEDCValidationInterface* pwalletIn) 
{
    g_signals.BlockFound.disconnect(boost::bind(&CEDCValidationInterface::ResetRequestCount, pwalletIn, _1));
    g_signals.ScriptForMining.disconnect(boost::bind(&CEDCValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.BlockChecked.disconnect(boost::bind(&CEDCValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.Broadcast.disconnect(boost::bind(&CEDCValidationInterface::ResendWalletTransactions, pwalletIn, _1, _2));
    g_signals.Inventory.disconnect(boost::bind(&CEDCValidationInterface::Inventory, pwalletIn, _1));
    g_signals.SetBestChain.disconnect(boost::bind(&CEDCValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.UpdatedTransaction.disconnect(boost::bind(&CEDCValidationInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.SyncTransaction.disconnect(boost::bind(&CEDCValidationInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.UpdatedBlockTip.disconnect(boost::bind(&CEDCValidationInterface::UpdatedBlockTip, pwalletIn, _1));
}

void edcUnregisterAllValidationInterfaces() 
{
    g_signals.BlockFound.disconnect_all_slots();
    g_signals.ScriptForMining.disconnect_all_slots();
    g_signals.BlockChecked.disconnect_all_slots();
    g_signals.Broadcast.disconnect_all_slots();
    g_signals.Inventory.disconnect_all_slots();
    g_signals.SetBestChain.disconnect_all_slots();
    g_signals.UpdatedTransaction.disconnect_all_slots();
    g_signals.SyncTransaction.disconnect_all_slots();
    g_signals.UpdatedBlockTip.disconnect_all_slots();
}

void SyncWithWallets(
	const CEDCTransaction & tx, 
		const CBlockIndex * pindex, 
		  				int posInBlock) 
{
    g_signals.SyncTransaction(tx, pindex, posInBlock );
}
