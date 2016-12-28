// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcchainparams.h"
#include "edc/consensus/edcmerkle.h"

#include "tinyformat.h"
#include "edcutil.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "edcchainparamsseeds.h"

	#include "arith_uint256.h"

static CEDCBlock edcCreateGenesisBlock(
	   const char * pszTimestamp, 
	const CScript & genesisOutputScript, 
	       uint32_t nTime, 
	       uint32_t nNonce, 
	       uint32_t nBits, 
	        int32_t nVersion, 
	const CAmount & genesisReward )
{
    CEDCMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CEDCBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = edcBlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CEDCBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CEDCBlock edcCreateGenesisBlock(
	       uint32_t nTime, 
           uint32_t nNonce, 
       	   uint32_t nBits, 
       	    int32_t nVersion, 
	const CAmount & genesisReward )
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return edcCreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CEDCMainParams : public CEDCChainParams 
{
public:
    CEDCMainParams() 
	{
        strNetworkID = "main";

        // nSubsidyHalvingInterval controls the amount of Equibits paid to the 
        // miner for mining a block. See edcGetBlockSubsidy for the algorithm.
        //
        consensus.nSubsidyHalvingInterval = 210000;

        // The next two parameters support BIP34 processing. See BIP34 in 
        // ConnectBlock for further details. 
        // TODO: These parameters will likely need to be removed from the EDC 
        // implementation since the BIP34Hash will not match.
        //
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931

        // Minimum proof-of-work value
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        // The next two parameters control the POW difficulty adjustment
        // interval
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;

        // If true, then minimum difficulty (POW) blocks are allowed
        consensus.fPowAllowMinDifficultyBlocks = false;

        // If true, then difficulty of previous block is used for current
        // block. See CalculateNextWorkRequired.
        consensus.fPowNoRetargeting = false;

        // Triggers POW rule change. See GetStateFor for details
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016

        // This parameter is never referenced. TODO: Remove it?
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        // BIP9 deployment parameters. The dates can be in the past
        // TODO: What dates do we want to use.
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // Never / undefined

        /**
         * The message start string is designed to be unlikely to occur in 
         * normal data. The characters are rarely used upper ASCII, not valid 
         * as UTF-8, and produce a large 32-bit integer with any alignment.
         */
// TODO: Customize for Equibits
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;

        nDefaultPort = 8330;
        nDefaultSecurePort = 8335;

        nPruneAfterHeight = 100000;

        genesis = edcCreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x3e0ed5e556868b13becebe01502f78862261760bbba955e55091e7374587964d"));
        assert(genesis.hashMerkleRoot == uint256S("0x86fc4663bb6a3144088fe7c6b9d4dfcb81787769d95c132c6aaa1747136928ca"));


// TODO: Equibit DNS seed addresses?
/*
#if BITCOIN_DNSSEEDS
// Any equibit DNS seeds?
		vSeeds.push_back(CDNSSeedData("bitcoin.sipa.be", "seed.bitcoin.sipa.be", true)); // Pieter Wuille
        vSeeds.push_back(CDNSSeedData("bluematt.me", "dnsseed.bluematt.me")); // Matt Corallo
        vSeeds.push_back(CDNSSeedData("dashjr.org", "dnsseed.bitcoin.dashjr.org")); // Luke Dashjr
        vSeeds.push_back(CDNSSeedData("bitcoinstats.com", "seed.bitcoinstats.com")); // Christian Decker
        vSeeds.push_back(CDNSSeedData("xf2.org", "bitseed.xf2.org")); // Jeff Garzik
        vSeeds.push_back(CDNSSeedData("bitcoin.jonasschnelli.ch", "seed.bitcoin.jonasschnelli.ch",true)); // Jonas Schnelli
#endif
*/
// TODO: Equibit prefixes?
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(edcpnSeed6_main, edcpnSeed6_main + ARRAYLEN(edcpnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) 
		{
            boost::assign::map_list_of
            ( 11111, uint256S("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"))
            ( 33333, uint256S("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"))
            ( 74000, uint256S("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"))
            (105000, uint256S("0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"))
            (134444, uint256S("0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"))
            (168000, uint256S("0x000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"))
            (193000, uint256S("0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"))
            (210000, uint256S("0x000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"))
            (216116, uint256S("0x00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"))
            (225430, uint256S("0x00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"))
            (250000, uint256S("0x000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"))
            (279000, uint256S("0x0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"))
            (295000, uint256S("0x00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")),
            1397080064, // * UNIX timestamp of last checkpoint block
            36544669,   // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            60000.0     // * estimated number of transactions per day after checkpoint
        };
    }
};
static CEDCMainParams edcMainParams;

/**
 * Testnet (v3)
 */
class CEDCTestNetParams : public CEDCChainParams 
{
public:
    CEDCTestNetParams() 
	{
        strNetworkID = "test";

        // nSubsidyHalvingInterval controls the amount of Equibits paid to the 
        // miner for mining a block. See edcGetBlockSubsidy for the algorithm
        //
        consensus.nSubsidyHalvingInterval = 210000;

        // The next two parameters support BIP34 processing. See BIP34 in 
        // ConnectBlock for further details. 
        // TODO: These parameters will likely need to be removed from the EDC 
        // implementation since the BIP34Hash will not match.
        //
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182

        // Minimum proof-of-work value
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        // The next two parameters control the POW difficulty adjustment
        // interval
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;

        // If true, then minimum difficulty (POW) blocks are allowed
        consensus.fPowAllowMinDifficultyBlocks = true;

        // If true, then difficulty of previous block is used for current
        // block. See CalculateNextWorkRequired.
        consensus.fPowNoRetargeting = false;

        // Triggers POW rule change. See GetStateFor for details
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains

        // This parameter is never referenced. TODO: Remove it?
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        // BIP9 deployment parameters. The dates can be in the past
        // TODO: What dates do we want to use.
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;

        nDefaultPort = 18330;
        nDefaultSecurePort = 18335;

        nPruneAfterHeight = 1000;

#ifdef MINE_NONCE
		FILE * fh = fopen( "nonce.trace.txt", "w" );

		arith_uint256 target;
		arith_uint256 minH;
		bool b1, b2;
		target.SetCompact( 486604799, &b1, &b2 );
		fprintf( fh, "%s:%d %s\n", __FILE__, __LINE__, target.ToString().c_str() );

		uint32_t nonce = 0; 
   		genesis = edcCreateGenesisBlock(1296688602, nonce, 0x1d00ffff, 1, 50 * COIN);
   		consensus.hashGenesisBlock = genesis.GetHash();
		minH = UintToArith256(consensus.hashGenesisBlock);

		for( ; ; ++nonce )
		{
       		genesis = edcCreateGenesisBlock(1296688602, nonce, 0x1d00ffff, 1, 50 * COIN);
       		consensus.hashGenesisBlock = genesis.GetHash();
			if( nonce % 200000 == 0 ) 
			{
				fprintf( fh, "%s:%d %u %s %s\n", __FILE__, __LINE__, nonce, minH.ToString().c_str(), target.ToString().c_str() ); 
				fflush(fh);
			}

			arith_uint256 p = UintToArith256(consensus.hashGenesisBlock);

			if(p <= target )
				break;

			if(minH > p )
			{
				minH = p;
				fprintf( fh, "%s:%d %u %s\n", __FILE__, __LINE__, nonce, p.ToString().c_str() ); fflush(fh);
			}
		}
fprintf( fh, "%s:%d %u %s\n", __FILE__, __LINE__, nonce, consensus.hashGenesisBlock.ToString().c_str() ); fflush(fh);
fclose(fh);

#endif

  	    genesis = edcCreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
      	consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0xa12bf0e41bc22f4a56be54c7f26339efb490ba81c70cd47012f8f246d9854db5"));
        assert(genesis.hashMerkleRoot == uint256S("0x86fc4663bb6a3144088fe7c6b9d4dfcb81787769d95c132c6aaa1747136928ca"));


        vFixedSeeds.clear();
        vSeeds.clear();
// TODO: Equibit DNS seed addresses?
/*
        vSeeds.push_back(CDNSSeedData("petertodd.org", "seed.bitcoin.petertodd.org", true));
        vSeeds.push_back(CDNSSeedData("bluematt.me", "testnet-seed.bluematt.me"));
        vSeeds.push_back(CDNSSeedData("bitcoin.schildbach.de", "testnet-seed.bitcoin.schildbach.de"));
*/
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(edcpnSeed6_test, edcpnSeed6_test + ARRAYLEN(edcpnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) 
		{
            boost::assign::map_list_of
            ( 546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")),
            1337966069,
            1488,
            300
        };

    }
};
static CEDCTestNetParams edcTestNetParams;

/**
 * Regression test
 */
class CEDCRegTestParams : public CEDCChainParams 
{
public:
    CEDCRegTestParams() 
	{
        strNetworkID = "regtest";

        // nSubsidyHalvingInterval controls the amount of Equibits paid to the 
        // miner for mining a block. See edcGetBlockSubsidy for the algorithm
        //
        consensus.nSubsidyHalvingInterval = 150;

        // The next two parameters support BIP34 processing. See BIP34 in 
        // ConnectBlock for further details. 
        // TODO: These parameters will likely need to be removed from the EDC 
        // implementation since the BIP34Hash will not match.
        //
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)

        // Minimum proof-of-work value
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        // The next two parameters control the POW difficulty adjustment
        // interval
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;

        // If true, then minimum difficulty (POW) blocks are allowed
        consensus.fPowAllowMinDifficultyBlocks = true;

        // If true, then difficulty of previous block is used for current
        // block. See CalculateNextWorkRequired.
        consensus.fPowNoRetargeting = true;

        // Triggers POW rule change. See GetStateFor for details
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains

        // This parameter is never referenced. TODO: Remove it?
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        // BIP9 deployment parameters. The dates can be in the past
        // TODO: What dates do we want to use.
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;

        nDefaultPort = 18442;
        nDefaultSecurePort = 18445;

        nPruneAfterHeight = 1000;

        genesis = edcCreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x3261607423e90efcfca1f8a070be44f35fb0409153e278af240dc7d4ef050968"));
        assert(genesis.hashMerkleRoot == uint256S("0x86fc4663bb6a3144088fe7c6b9d4dfcb81787769d95c132c6aaa1747136928ca"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData)
		{
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
            0,
            0,
            0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CEDCRegTestParams edcRegTestParams;

static CEDCChainParams *edcpCurrentParams = 0;

const CEDCChainParams & edcParams() 
{
    assert(edcpCurrentParams);
    return *edcpCurrentParams;
}

CEDCChainParams & edcParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return edcMainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return edcTestNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return edcRegTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void edcSelectParams(const std::string& network)
{
    SelectBaseParams(network);
    edcpCurrentParams = & edcParams(network);
}

void edcUpdateRegtestBIP9Parameters(
	Consensus::DeploymentPos d, 
					 int64_t nStartTime, 
					 int64_t nTimeout)
{
    edcRegTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}

