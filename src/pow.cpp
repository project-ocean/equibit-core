// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2017 The Raven Core developers
// Copyright (c) 2018 The Equibit Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef BUILD_BTC

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4)
        nActualTimespan = params.nPowTargetTimespan / 4;
    if (nActualTimespan > params.nPowTargetTimespan * 4)
        nActualTimespan = params.nPowTargetTimespan * 4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

#else // BUILD_EQB

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "tinyformat.h"
#include "uint256.h"
#include "util.h"
#include "validation.h"

unsigned int static GetNextWorkRequiredBTC(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

	// Short circuit
    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentInterval() != 0) {
        if (params.fPowAllowMinDifficultyBlocks) {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
                return nProofOfWorkLimit;
            else {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast->nBits, params.powLimit, pindexFirst->GetBlockTime(), pindexLast->GetBlockTime(), params.nPowTargetTimespan);
}

unsigned int static GetNextWorkRequiredDGW(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    /* current difficulty formula, dash - DarkGravity v3, written by Evan Duffield - evan@dash.org */
    assert(pindexLast != nullptr);

    // Short circuit
    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    int64_t nPastBlocks = params.DifficultyAdjustmentInterval();

    // make sure we have at least (nPastBlocks + 1) blocks, otherwise just return powLimit
    if (!pindexLast || pindexLast->nHeight < nPastBlocks) {
        return nProofOfWorkLimit;
    }

    if (params.fPowAllowMinDifficultyBlocks) {
        // Special difficulty rule:
        // If the new block's timestamp is more than 2 * target spacing
        // then allow mining of a min-difficulty block.
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
            return nProofOfWorkLimit;
        else {
            // Return the last non-special-min-difficulty-rules-block
            const CBlockIndex* pindex = pindexLast;
            while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 &&
                   pindex->nBits == nProofOfWorkLimit)
                pindex = pindex->pprev;
            return pindex->nBits;
        }
    }

    const CBlockIndex* pindex = pindexLast;
    arith_uint256 bnPastTargetAvg;

    for (unsigned int nCountBlocks = 1; nCountBlocks <= nPastBlocks; nCountBlocks++) {
        arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
        if (nCountBlocks == 1) {
            bnPastTargetAvg = bnTarget;
        } else {
            // NOTE: that's not an average really...
            bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);
        }

        if (nCountBlocks != nPastBlocks) {
            assert(pindex->pprev); // should never fail
            pindex = pindex->pprev;
        }
    }

    return CalculateNextWorkRequired(bnPastTargetAvg.GetCompact(), params.powLimit, pindex->GetBlockTime(), pindexLast->GetBlockTime(), params.nPowTargetTimespan);
}

unsigned int CalculateNextWorkRequired(uint32_t nBits, uint256 powLimit, int64_t nFirstBlockTime, int64_t nLastBlockTime, int64_t nPowTargetTimespan)
{
    assert(nLastBlockTime >= nFirstBlockTime);

    // Limit adjustment step
    int64_t nActualTimespan = nLastBlockTime - nFirstBlockTime;

    if (nActualTimespan < nPowTargetTimespan / 4)
        nActualTimespan = nPowTargetTimespan / 4;
    if (nActualTimespan > nPowTargetTimespan * 4)
        nActualTimespan = nPowTargetTimespan * 4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(nBits);
    bnNew *= nActualTimespan;
    bnNew /= nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    int dgw = GetNextWorkRequiredDGW(pindexLast, pblock, params);
    int btc = GetNextWorkRequiredBTC(pindexLast, pblock, params);
    int64_t nPrevBlockTime = (pindexLast->pprev ? pindexLast->pprev->GetBlockTime() : pindexLast->GetBlockTime());

    LogPrint(BCLog::NET, "Block %s - version: %s: found next work required using DGW: [%s] (BTC would have been [%s]\t(%+d)\t(%0.3f%%)\t(%s sec))\n",
        pindexLast->nHeight + 1, pblock->nVersion, dgw, btc, btc - dgw, (float)(btc - dgw) * 100.0 / (float)dgw, pindexLast->GetBlockTime() - nPrevBlockTime);

    return dgw;
}

#endif // END_BUILD

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
