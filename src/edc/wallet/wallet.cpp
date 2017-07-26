// Copyright (c) 2016-2017 The Equibit Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "wallet/coincontrol.h"
#include "policy/policy.h"
#include "validation.h"
#include "txmempool.h"
#include "base58.h"
#include "issuer.h"
#include "random.h"
#include "util.h"

#include <boost/foreach.hpp>

using namespace std;


void CWallet::AvailableCoins(vector<COutput>& vCoins, CBitcoinAddress& issuer, unsigned wotlvl, bool fOnlyConfirmed, const CCoinControl* coinControl, bool fIncludeZeroValue) const
{
    CKeyID issuerID;
    issuer.GetKeyID(issuerID);

    vCoins.clear();
    {
        LOCK2(cs_main, cs_wallet);

        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const uint256& wtxid = it->first;
            const CWalletTx* pcoin = &(*it).second;

            if (!CheckFinalTx(*pcoin)) continue;
            if (fOnlyConfirmed && !pcoin->IsTrusted()) continue;
            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0) continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0) continue;

            // We should not consider coins which aren't at least in our mempool
            // It's possible for these to be conflicted via ancestors which we may never be able to detect
            if (nDepth == 0 && !pcoin->InMempool()) continue;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++)
            {
                const CTxOut & vout = pcoin->tx->vout[i];

#if 0
                // Skip coins with invalid authorizing issuer
                if (vout.issuerAddr != issuerID) continue;

                // Skip coins whose WoT level is below the minimum level
                if (vout.wotMinLevel > wotlvl) continue;
#endif

                isminetype mine = IsMine(vout);
                if (
                    !(IsSpent(wtxid, i)) &&
                    mine != ISMINE_NO &&
                    !IsLockedCoin((*it).first, i) &&
                    (
                        vout.nValue > 0 || fIncludeZeroValue) &&
                        (
                            !coinControl || !coinControl->HasSelected() ||
                            coinControl->fAllowOtherInputs ||
                            coinControl->IsSelected(COutPoint((*it).first, i))
                            )
                    )
                {
                    vCoins.push_back(COutput(pcoin, i, nDepth, ((mine & ISMINE_SPENDABLE) != ISMINE_NO) || (coinControl && coinControl->fAllowWatchOnly && (mine & ISMINE_WATCH_SOLVABLE) != ISMINE_NO), (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO));
                }
            }
        }
    }
}

bool CWallet::create_issuing_transaction(
    const CIssuer& issuer,
    const std::string payload,
    const std::vector<CRecipient>& vecSend,
    CWalletTx& wtxNew,
    CReserveKey& reservekey,
    CAmount& nFeeRet,
    int& nChangePosInOut,
    std::string& strFailReason)
{
    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;

    BOOST_FOREACH(const CRecipient& recipient, vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }

        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount) nSubtractFeeFromAmount++;
    }

    if (vecSend.empty() || nValue < 0)
    {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;

    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    txNew.nLockTime = chainActive.Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0) txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int)chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        LOCK2(cs_main, cs_wallet);
        {
            std::vector<COutput> vAvailableCoins;

            CBitcoinAddress blank;
            AvailableCoins(vAvailableCoins, blank, 0, true, nullptr, false);
            CKeyID id = issuer.pubKey_.GetID();
            CTxDestination address = CBitcoinAddress(id).Get();

            nFeeRet = 0;

            // Start with no fee and loop until there is enough fee
            while (true)
            {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;
                bool fFirst = true;

                CAmount nValueToSelect = nValue;

                if (nSubtractFeeFromAmount == 0) nValueToSelect += nFeeRet;

                double dPriority = 0;

                // vouts to the payees
                BOOST_FOREACH(const CRecipient& recipient, vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    txout.m_equibit.m_payload = payload;

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                        }
                    }

                    if (txout.IsDust(minRelayTxFee))
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");

                        return false;
                    }

                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                CoinSet setCoins;
                CAmount nValueIn = 0;

                if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, nullptr))
                {
                    // HERE
                    strFailReason = _("Insufficient funds");
                    return false;
                }

                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    CAmount nCredit = pcoin.first->tx->vout[pcoin.second].nValue;
                    //The coin age after the next block (depth+1) is used instead of the current,
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction.
                    //But mempool inputs might still be in the mempool, so their age stays 0
                    int age = pcoin.first->GetDepthInMainChain();

                    assert(age >= 0);

                    if (age != 0) age += 1;

                    dPriority += (double)nCredit * age;
                }

                const CAmount nChange = nValueIn - nValueToSelect;

                if (nChange > 0)
                {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-equibit-address
                    CScript scriptChange;

                    // Note: We use a new key here to keep it from being obvious which side is the change.
                    //  The drawback is that by not reusing a previous key, the change may be lost if a
                    //  backup is restored, if the backup doesn't have the new private key for the change.
                    //  If we reused the old key, it would be possible to add code to look for and
                    //  rediscover unknown transactions that were written with keys of ours to recover
                    //  post-backup change.

                    // Reserve a new key pair from key pool
                    CPubKey vchPubKey;

                    bool ret = reservekey.GetReservedKey(vchPubKey);

                    assert(ret); // should never fail, as we just unlocked

                    scriptChange = GetScriptForDestination(vchPubKey.GetID());

                    CTxOut newTxOut(nChange, scriptChange);

                    // We do not move dust-change to fees, because the sender would end up paying more than requested.
                    // This would be against the purpose of the all-inclusive feature.
                    // So instead we raise the change and deduct from the recipient.
                    if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust(minRelayTxFee))
                    {
                        CAmount nDust = newTxOut.GetDustThreshold(minRelayTxFee) - newTxOut.nValue;
                        newTxOut.nValue += nDust; // raise change until no more dust

                        for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                        {
                            if (vecSend[i].fSubtractFeeFromAmount)
                            {
                                txNew.vout[i].nValue -= nDust;

                                if (txNew.vout[i].IsDust(minRelayTxFee))
                                {
                                    strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                                    return false;
                                }

                                break;
                            }
                        }
                    }

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (newTxOut.IsDust(minRelayTxFee))
                    {
                        nChangePosInOut = -1;
                        nFeeRet += nChange;
                        reservekey.ReturnKey();
                    }
                    else
                    {
                        if (nChangePosInOut == -1)
                        {
                            // Insert change txn at random position:
                            nChangePosInOut = GetRandInt(txNew.vout.size() + 1);
                        }
                        else if ((unsigned int)nChangePosInOut > txNew.vout.size())
                        {
                            strFailReason = _("Change index out of range");
                            return false;
                        }

                        vector<CTxOut>::iterator position = txNew.vout.begin() + nChangePosInOut;
                        txNew.vout.insert(position, newTxOut);
                    }
                }
                else reservekey.ReturnKey();

                // Fill vin
                //
                // NOTE: how the sequence number is set to non-maxint so that the nLockTime set above actually works.
                //
                // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
                // we use the highest possible value in that range (maxint-2)
                // to avoid conflicting with other possible uses of nSequence,
                // and in the spirit of "smallest possible change from prior behavior".
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*, unsigned int)& coin, setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second, CScript(),
                                              std::numeric_limits<unsigned int>::max() - (fWalletRbf ? 2 : 1)));

                // Sign
                int nIn = 0;
                CTransaction txNewConst(txNew);

                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*, unsigned int)& coin, setCoins)
                {
                    bool signSuccess;
                    const CScript& scriptPubKey = coin.first->tx->vout[coin.second].scriptPubKey;
                    SignatureData sigdata;

                    signSuccess = ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, coin.first->tx->vout[coin.second].nValue, SIGHASH_ALL), scriptPubKey, sigdata);

                    if (!signSuccess)
                    {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }
                    else
                    {
                        UpdateTransaction(txNew, nIn, sigdata);
                    }

                    nIn++;
                }

                unsigned int nBytes = GetVirtualTransactionSize(txNew);

                // Embed the constructed transaction data in wtxNew.
                wtxNew.SetTx(std::make_shared<const CTransaction>(txNew));

                // Limit size
                if (GetTransactionWeight(txNew) >= MAX_STANDARD_TX_WEIGHT)
                {
                    strFailReason = _("Transaction too large");
                    return false;
                }

                dPriority = wtxNew.tx->ComputePriority(dPriority, nBytes);

                // Can we complete this as a free transaction?
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE)
                {
                    // Not enough fee: enough priority?
                    double dPriorityNeeded = mempool.estimateSmartPriority(nTxConfirmTarget);
                    // Require at least hard-coded AllowFree.
                    if (dPriority >= dPriorityNeeded && AllowFree(dPriority)) break;
                }

                CAmount nFeeNeeded = GetMinimumFee(nBytes, nTxConfirmTarget, mempool);
                // If we made it here and we aren't even able to meet the relay
                // fee on the next pass, give up because we must be at the 
                // maximum allowed fee.
                if (nFeeNeeded < minRelayTxFee.GetFee(nBytes))
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded) break; // Done, enough fee included.

                                                  // Include more fee and try again.
                nFeeRet = nFeeNeeded;

                continue;
            }
        }
    }

    return true;
}
