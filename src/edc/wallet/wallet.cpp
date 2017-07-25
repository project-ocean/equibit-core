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
