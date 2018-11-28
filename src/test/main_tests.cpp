// Copyright (c) 2014-2017 The Bitcoin Core developers
// Copyright (c) 2018 Equibit Group AG
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <validation.h>
#include <net.h>

#include <test/test_bitcoin.h>

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

#ifdef BUILD_BTC
static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    int maxHalvings = 64;
    CAmount nInitialSubsidy = 50 * COIN;

    CAmount nPreviousSubsidy = nInitialSubsidy * 2; // for height == 0
    BOOST_CHECK_EQUAL(nPreviousSubsidy, nInitialSubsidy * 2);
    for (int nHalvings = 0; nHalvings < maxHalvings; nHalvings++) {
        int nHeight = nHalvings * consensusParams.nSubsidyHalvingInterval;
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
        BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
        nPreviousSubsidy = nSubsidy;
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(maxHalvings * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
}

static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval)
{
    Consensus::Params consensusParams;
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    TestBlockSubsidyHalvings(consensusParams);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    TestBlockSubsidyHalvings(chainParams->GetConsensus()); // As in main
    TestBlockSubsidyHalvings(150); // As in regtest
    TestBlockSubsidyHalvings(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 14000000; nHeight += 1000) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        BOOST_CHECK(nSubsidy <= 50 * COIN);
        nSum += nSubsidy * 1000;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, 2099999997690000ULL);
}

bool ReturnFalse() { return false; }
bool ReturnTrue() { return true; }


BOOST_AUTO_TEST_CASE(test_combiner_all)
{
    boost::signals2::signal<bool (), CombinerAll> Test;
    BOOST_CHECK(Test());
    Test.connect(&ReturnFalse);
    BOOST_CHECK(!Test());
    Test.connect(&ReturnTrue);
    BOOST_CHECK(!Test());
    Test.disconnect(&ReturnFalse);
    BOOST_CHECK(Test());
    Test.disconnect(&ReturnTrue);
    BOOST_CHECK(Test());
}
#else  // BUILD_EQB

static const CAmount    MAX_COINBASE = 52.5 * COIN;

static void TestBlockSubsidyCurve(const Consensus::Params& consensusParams)
{
    // Pre-calculated block mining reward for test
    static std::map<int, CAmount> blockNumToMiningReward = {
                                                            std::pair<int, CAmount>(0       , GENESIS_BLOCK_REWARD),
                                                            std::pair<int, CAmount>(1       , FIRST_BLOCK_REWARD),
                                                            std::pair<int, CAmount>(52500   , 506341245),
                                                            std::pair<int, CAmount>(105000  , 827458486),
                                                            std::pair<int, CAmount>(157500  , 1322666848),
                                                            std::pair<int, CAmount>(210000  , 2041088800),
                                                            std::pair<int, CAmount>(262500  , 2983908560),
                                                            std::pair<int, CAmount>(315000  , 4032576406),
                                                            std::pair<int, CAmount>(367500  , 4904234072),
                                                            std::pair<int, CAmount>(419999  , 5249999999),
                                                            std::pair<int, CAmount>(420000  , 5250000000),
                                                            std::pair<int, CAmount>(420001  , 5249999999),
                                                            std::pair<int, CAmount>(472500  , 4904234072),
                                                            std::pair<int, CAmount>(525000  , 4032576406),
                                                            std::pair<int, CAmount>(577500  , 2983908560),
                                                            std::pair<int, CAmount>(630000  , 2041088800),
                                                            std::pair<int, CAmount>(682500  , 1322666848),
                                                            std::pair<int, CAmount>(735000  , 827458486),
                                                            std::pair<int, CAmount>(787500  , 506341245),
                                                            std::pair<int, CAmount>(840000  , 305670953),
                                                            std::pair<int, CAmount>(892500  , 183023491),
                                                            std::pair<int, CAmount>(945000  , 109050395),
                                                            std::pair<int, CAmount>(997500  , 64785313),
                                                            std::pair<int, CAmount>(1050000 , 38421164),
                                                            std::pair<int, CAmount>(1102500 , 22762315),
                                                            std::pair<int, CAmount>(1155000 , 13477113),
                                                            std::pair<int, CAmount>(1207500 , 7976642),
                                                            std::pair<int, CAmount>(1260000 , 4720090),
                                                            std::pair<int, CAmount>(1312500 , 2792707),
                                                            std::pair<int, CAmount>(1365000 , 1652220),
                                                           };
 
    std::map<int, CAmount>::iterator itr_Heights = blockNumToMiningReward.begin();
    std::map<int, CAmount>::iterator itr_HeightMiningRewardFinder;

    while (itr_Heights != blockNumToMiningReward.end())
    {
        int nHeightTest = itr_Heights->first / consensusParams.nSubsidyAccelerationFactor;

        itr_HeightMiningRewardFinder = blockNumToMiningReward.find(nHeightTest);

        if (itr_HeightMiningRewardFinder != blockNumToMiningReward.end())
        {
            CAmount nSubsidy = GetBlockSubsidy(nHeightTest, consensusParams);
            if (nHeightTest > 1)
            {
                BOOST_CHECK(nSubsidy <= MAX_COINBASE);
            }
//            if (nSubsidy != itr_HeightMiningRewardFinder->second)
//                std::cout << "\nnHeight = " << nHeightTest << "\tnSubC = " << nSubsidy << "\tnSubR= " << itr_HeightMiningRewardFinder->second;
            BOOST_CHECK_EQUAL(nSubsidy, itr_HeightMiningRewardFinder->second);
        }
        ++ itr_Heights;
    }
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto mainchainParams = CreateChainParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(mainchainParams->GetConsensus().nSubsidyAccelerationFactor, 1);   // As in mainNet
    TestBlockSubsidyCurve(mainchainParams->GetConsensus());

    const auto testchainParams = CreateChainParams(CBaseChainParams::TESTNET);          // As in testNet
    BOOST_CHECK_EQUAL(testchainParams->GetConsensus().nSubsidyAccelerationFactor, 1);
    // no need to run the TestBlockSubsidyCurve for testNet as its similar to mainNet

    const auto regchainParams = CreateChainParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(regchainParams->GetConsensus().nSubsidyAccelerationFactor, 1400); // As in regTest
    TestBlockSubsidyCurve(regchainParams->GetConsensus());
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    CAmount nSum = 0;
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    //std::cout << "\n\n   subsidy_limit_test ( " << MAX_COINBASE <<" ) " << "   Acc.Factor = " << chainParams->GetConsensus().nSubsidyAccelerationFactor;

    for (int nHeight = 1; nHeight < 2500002; nHeight += 1000)
    {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        nSum += nSubsidy;
        //std::cout << "\nnHeight = " << nHeight << "\tnSubsidy = " << nSubsidy << "\tnSum= " << nSum ;
        if (nHeight > 1 )
        {
            BOOST_CHECK(nSubsidy <= MAX_COINBASE);
        }
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, 133094593368744ULL);  // Total mining rewards of block_1, block_1001, block_2001, .... block_2500001
}
#endif // END_BUILD

BOOST_AUTO_TEST_SUITE_END()
