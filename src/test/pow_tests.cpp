// Copyright (c) 2015-2017 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <random.h>
#include <util.h>
#include <test/test_bitcoin.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)


#ifdef BUILD_BTC

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739; // Block #32255
    pindexLast.nBits = 0x1d00ffff;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1d00d86a);
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996; // Block #2015
    pindexLast.nBits = 0x1d00ffff;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1d00ffff);
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671; // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1c0168fd);
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443; // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1d00e1fd);
}


#else // BUILD_EQB


static int64_t FirstBlockTime = 1000000000; // arbitrary start time

static uint256 StandardPowLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // From CMainParams
static uint256 TestPowTarget = uint256S("0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff");

static int64_t nPowTargetTimespanBTC = 14 * 24 * 60 * 60; // two weeks
static int64_t nPowTargetTimespanDWG = 24 * 60 * 60;      // 1 day


// We can't expect to get exact values for calculated nBits because the compact format uses 32 bits to store 256 bits
// so instead we'll test for something close here differing by less than 1 part in a million.
// https://bitcoin.org/en/developer-reference#target-nbits
const double DiffThreshold = 1.e-6;

BOOST_AUTO_TEST_CASE(get_next_work_10_percent)
{
    int64_t nLastBlockTime = FirstBlockTime + nPowTargetTimespanDWG / 10;

    arith_uint256 bnPowInitial = UintToArith256(TestPowTarget);
    arith_uint256 bnPowExpected = UintToArith256(TestPowTarget) / 4; // Everything below 1/4 should be treated like 1/4
    uint32_t nBitsExpected = bnPowExpected.GetCompact();

    uint32_t nBitsNew = CalculateNextWorkRequired(bnPowInitial.GetCompact(), StandardPowLimit, FirstBlockTime, nLastBlockTime, nPowTargetTimespanDWG);
    double bitsDiff = fabs(log(1.0 * nBitsNew / nBitsExpected));

    BOOST_CHECK_LT(bitsDiff, DiffThreshold);
}

BOOST_AUTO_TEST_CASE(get_next_work_30_percent)
{
    int64_t nLastBlockTime = FirstBlockTime + nPowTargetTimespanDWG * 3 / 10;

    arith_uint256 bnPowInitial = UintToArith256(TestPowTarget);
    arith_uint256 bnPowExpected = UintToArith256(TestPowTarget) * 3 / 10;
    uint32_t nBitsExpected = bnPowExpected.GetCompact();

    uint32_t nBitsNew = CalculateNextWorkRequired(bnPowInitial.GetCompact(), StandardPowLimit, FirstBlockTime, nLastBlockTime, nPowTargetTimespanDWG);
    uint32_t nBitsDiff = abs(int(nBitsExpected - nBitsNew));
    double bitsDiff = fabs(log(1.0 * nBitsNew / nBitsExpected));

    BOOST_CHECK_LT(bitsDiff, DiffThreshold);
}

BOOST_AUTO_TEST_CASE(get_next_work_80_percent)
{
    int64_t nLastBlockTime = FirstBlockTime + nPowTargetTimespanDWG * 4 / 5;

    arith_uint256 bnPowInitial = UintToArith256(TestPowTarget);
    arith_uint256 bnPowExpected = UintToArith256(TestPowTarget) * 4 / 5;
    uint32_t nBitsExpected = bnPowExpected.GetCompact();

    uint32_t nBitsNew = CalculateNextWorkRequired(bnPowInitial.GetCompact(), StandardPowLimit, FirstBlockTime, nLastBlockTime, nPowTargetTimespanDWG);
    double bitsDiff = fabs(log(1.0 * nBitsNew / nBitsExpected));

    BOOST_CHECK_LT(bitsDiff, DiffThreshold);
}

BOOST_AUTO_TEST_CASE(get_next_work_125_percent)
{
    int64_t nLastBlockTime = FirstBlockTime + nPowTargetTimespanDWG * 5 / 4;

    arith_uint256 bnPowInitial = UintToArith256(TestPowTarget);
    arith_uint256 bnPowExpected = UintToArith256(TestPowTarget) * 5 / 4;
    uint32_t nBitsExpected = bnPowExpected.GetCompact();

    uint32_t nBitsNew = CalculateNextWorkRequired(bnPowInitial.GetCompact(), StandardPowLimit, FirstBlockTime, nLastBlockTime, nPowTargetTimespanDWG);
    double bitsDiff = fabs(log(1.0 * nBitsNew / nBitsExpected));

    BOOST_CHECK_LT(bitsDiff, DiffThreshold);
}

BOOST_AUTO_TEST_CASE(get_next_work_300_percent)
{
    int64_t nLastBlockTime = FirstBlockTime + nPowTargetTimespanDWG * 3;

    arith_uint256 bnPowInitial = UintToArith256(TestPowTarget);
    arith_uint256 bnPowExpected = UintToArith256(TestPowTarget) * 3;
    uint32_t nBitsExpected = bnPowExpected.GetCompact();

    uint32_t nBitsNew = CalculateNextWorkRequired(bnPowInitial.GetCompact(), StandardPowLimit, FirstBlockTime, nLastBlockTime, nPowTargetTimespanDWG);
    double bitsDiff = fabs(log(1.0 * nBitsNew / nBitsExpected));

    BOOST_CHECK_LT(bitsDiff, DiffThreshold);
}

BOOST_AUTO_TEST_CASE(get_next_work_500_percent)
{
    int64_t nLastBlockTime = FirstBlockTime + nPowTargetTimespanDWG * 5;

    arith_uint256 bnPowInitial = UintToArith256(TestPowTarget);
    arith_uint256 bnPowExpected = UintToArith256(TestPowTarget) * 4; // Everything above 4x should be treated like 4x
    uint32_t nBitsExpected = bnPowExpected.GetCompact();

    uint32_t nBitsNew = CalculateNextWorkRequired(bnPowInitial.GetCompact(), StandardPowLimit, FirstBlockTime, nLastBlockTime, nPowTargetTimespanDWG);
    double bitsDiff = fabs(log(1.0 * nBitsNew / nBitsExpected));

    BOOST_CHECK_LT(bitsDiff, DiffThreshold);
}

// Initialize simulated blockchain 
static int InitializeBlocks(std::vector<CBlockIndex>& blocks, Consensus::Params& params)
{
    const unsigned int nInterval = 2 * params.DifficultyAdjustmentInterval();
    const unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    assert(blocks.size() > nInterval);

    for (int i = 0; i < nInterval; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = i ? blocks[i - 1].nTime + params.nPowTargetSpacing : 1269211443; // Arbitrary start time copied from GetBlockProofEquivalentTime_test
        blocks[i].nBits = nProofOfWorkLimit;
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    return nInterval;
}

// Difficulty should remain constant when the block time interval is exactly the target interval
BOOST_AUTO_TEST_CASE(GetNextWorkRequired_steady_state)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    Consensus::Params params = chainParams->GetConsensus();
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    CBlockHeader header;
    const int nBlocks = 1000;
    std::vector<CBlockIndex> blocks(nBlocks);

    int nBlocksInitialized = InitializeBlocks(blocks, params);

    for (int i = nBlocksInitialized; i < nBlocks; i++) {
        header.nVersion = 1;
        header.nTime = blocks[i - 1].nTime + params.nPowTargetSpacing;

        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = header.nTime;
        blocks[i].nBits = GetNextWorkRequired(blocks[i].pprev, &header, params);
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);

        BOOST_CHECK_EQUAL(blocks[i].nBits, blocks[i - 1].nBits);
    }
}

// Simulate a blockchain to check that the difficulty changes in expected ways with the block times
BOOST_AUTO_TEST_CASE(GetNextWorkRequired_changing)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    Consensus::Params params = chainParams->GetConsensus();
    const unsigned int nInterval = params.DifficultyAdjustmentInterval() + 1;
    const unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    CBlockHeader header;
    const int nBlocks = 1000;
    std::vector<CBlockIndex> blocks(nBlocks);

    int nBlocksInitialized = InitializeBlocks(blocks, params);

    for (int i = nBlocksInitialized; i < nBlocks; i++) {
        uint32_t blockTime = params.nPowTargetSpacing;
        
        // In the first phase we'll simulate short block times to increase difficulty
        // and second phase we'll simulate long block times to decrease difficulty.
        if (i < nBlocks / 2) {
            blockTime /= 2;
        } else {
            blockTime *= 2;
        }

        header.nVersion = 1;
        header.nTime = blocks[i - 1].nTime + blockTime;

        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = header.nTime;
        blocks[i].nBits = GetNextWorkRequired(blocks[i].pprev, &header, params);
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);

        int diff = blocks[i].nBits - blocks[i - 1].nBits;

        // std::cout << i << " " << blocks[i].nBits << " " << diff << std::endl;

        // Ensure that if the difficulty hasn't changed then we're already at the limit,
        // otherwise ensure that difficulty is increasing (nBits decreasing) for the first phase
        // and vice versa for the second phase.
        if (diff == 0) {
            BOOST_CHECK_EQUAL(blocks[i].nBits, nProofOfWorkLimit);
        } else {
            if (i <= nBlocks / 2) {
                BOOST_CHECK_LT(diff, 0);
            } else {
                BOOST_CHECK_GT(diff, 0);
            }
        }
    }
}

// BTC legacy tests below, functionally idential to the ones in the BUILD_BTC conditional compilation block above
// but updated with the new function signature.

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work_btc)
{
    int64_t nFirstBlockTime = 1261130161; // Block #30240
    int64_t nLastBlockTime = 1262152739;  // Block #32255

    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(0x1d00ffff, StandardPowLimit, nFirstBlockTime, nLastBlockTime, nPowTargetTimespanBTC), 0x1d00d86a);
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit_btc)
{
    int64_t nFirstBlockTime = 1231006505; // Block #0
    int64_t nLastBlockTime = 1233061996;  // Block #2015

    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(0x1d00ffff, StandardPowLimit, nFirstBlockTime, nLastBlockTime, nPowTargetTimespanBTC), 0x1d00ffff);
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual_btc)
{
    int64_t nFirstBlockTime = 1279008237; // Block #66528
    int64_t nLastBlockTime = 1279297671;  // Block #68543

    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(0x1c05a3f4, StandardPowLimit, nFirstBlockTime, nLastBlockTime, nPowTargetTimespanBTC), 0x1c0168fd);
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual_btc)
{
    int64_t nFirstBlockTime = 1263163443; // NOTE: Not an actual block time
    int64_t nLastBlockTime = 1269211443;  // Block #46367

    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(0x1c387f6f, StandardPowLimit, nFirstBlockTime, nLastBlockTime, nPowTargetTimespanBTC), 0x1d00e1fd);
}

#endif // END_BUILD

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

BOOST_AUTO_TEST_SUITE_END()
