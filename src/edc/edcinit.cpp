// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcinit.h"
#include "edcapp.h"
#include "edcparams.h"
#include "edcutil.h"
#include "edcmain.h"
#include "edcchainparams.h"
#include "clientversion.h"
#include "edc/rpc/edcserver.h"
#include "edcui_interface.h"
#include "utilmoneystr.h"
#include "edc/wallet/edcwallet.h"
#include "edctxdb.h"
#include "edc/rpc/edcregister.h"
#include "edchttpserver.h"
#include "edchttprpc.h"
#include "edctorcontrol.h"
#include "consensus/validation.h"
#include <boost/algorithm/string/classification.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#ifdef USE_HSM
#include "Thales/interface.h"
#endif

void edcRegisterAllCoreRPCCommands( CEDCRPCTable & edcTableRPC );
void edcRegisterWalletRPCCommands(CEDCRPCTable & edcTableRPC );
int64_t edcGetAdjustedTime();

extern std::atomic<bool> fRequestShutdown;


namespace
{

const char *FEE_ESTIMATES_FILENAME	 = "fee_estimates.dat";
bool 		fFeeEstimatesInitialized = false;
uint64_t 	EDC_MAX_UPLOAD_TIMEFRAME = 60 * 60 * 24;


void BlockNotifyCallback(
	               bool initialSync, 
	const CBlockIndex * pBlockIndex )
{
	EDCparams & params = EDCparams::singleton();

    if (initialSync || !pBlockIndex)
        return;

    std::string strCmd = params.blocknotify;

    boost::replace_all(strCmd, "%s", pBlockIndex->GetBlockHash().GetHex());
    boost::thread t(runCommand, strCmd); // thread runs free
}

/**
 * This is a minimally invasive approach to shutdown on LevelDB read errors from the
 * chainstate, while keeping user interface out of the common library, which is shared
 * between bitcoind, and bitcoin-qt and non-server tools.
*/
class CEDCCoinsViewErrorCatcher : public CEDCCoinsViewBacked
{
public:
    CEDCCoinsViewErrorCatcher(CEDCCoinsView* view) : CEDCCoinsViewBacked(view) 
	{
	}

    bool GetCoins(const uint256 &txid, CEDCCoins &coins) const 
	{
        try 
		{
            return CEDCCoinsViewBacked::GetCoins(txid, coins);
        } 
		catch(const std::runtime_error& e) 
		{
            edcUiInterface.ThreadSafeMessageBox(_("Error reading from database, shutting down."), "", CEDCClientUIInterface::MSG_ERROR);
            edcLogPrintf("Error reading from database: %s\n", e.what());
            // Starting the shutdown sequence and returning false to the caller
			// would be interpreted as 'entry not found' (as opposed to unable 
			// to read data), and could lead to invalid interpretation. Just 
			// exit immediately, as we can't continue anyway, and all writes 
			// should be atomic.
            abort();
        }
    }
    // Writes do not need similar protection, as failure to write is handled 
	// by the caller.
};

CEDCCoinsViewDB * pcoinsdbview = NULL;
CEDCCoinsViewErrorCatcher * pcoinscatcher = NULL;

/** Used to pass flags to the Bind() function */
enum BindFlags 
{
    BF_NONE         = 0,
    BF_EXPLICIT     = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    BF_WHITELIST    = (1U << 2),
};

#define MIN_CORE_FILEDESCRIPTORS 150

void edcInitLogging()
{
    edcLogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
	edcLogPrintf("Equibit version %s\n", FormatFullVersion());
}

std::string ResolveErrMsg(const char * const optname, const std::string& strBind)
{
    return strprintf(_("Cannot resolve -%s address: '%s'"), optname, strBind);
}

bool Bind(CEDCConnman & connman, const CService &addr, unsigned int flags) 
{
    if (!(flags & BF_EXPLICIT) && edcIsLimited(addr))
        return false;

    std::string strError;
    if (!connman.BindListenPort(addr, strError, (flags & BF_WHITELIST) != 0)) 
	{
        if (flags & BF_REPORT_ERROR)
            return edcInitError(strError);
        return false;
    }
    return true;
}

namespace
{
bool fHaveGenesis = false;
boost::mutex cs_GenesisWait;
CConditionVariable condvar_GenesisWait;

void BlockNotifyGenesisWait(bool, const CBlockIndex *pBlockIndex)
{
    if (pBlockIndex != NULL) {
        {
            boost::unique_lock<boost::mutex> lock_GenesisWait(cs_GenesisWait);
            fHaveGenesis = true;
        }
        condvar_GenesisWait.notify_all();
    }
}

}

struct CImportingNow
{
    CImportingNow() 
	{
		EDCapp & theApp = EDCapp::singleton();
        assert(theApp.importing() == false);
        theApp.importing( true );
    }

    ~CImportingNow() 
	{
		EDCapp & theApp = EDCapp::singleton();
        assert(theApp.importing() == true);
        theApp.importing( false );
    }
};

}

void StartShutdown();

void edcThreadImport(std::vector<boost::filesystem::path> vImportFiles)
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    const CEDCChainParams& chainparams = edcParams();
    RenameThread("equibit-loadblk");
	CImportingNow imp;

    // -eb_reindex

    if (theApp.reindex()) 
	{
        int nFile = 0;

        while (true) 
		{
            CDiskBlockPos pos(nFile, 0);

            if (!boost::filesystem::exists(edcGetBlockPosFilename(pos, "blk")))
                break; // No block files left to reindex

            FILE *file = edcOpenBlockFile(pos, true);
            if (!file)
                break; // This error is logged in edcOpenBlockFile
            edcLogPrintf("Reindexing block file blk%05u.dat...\n", (unsigned int)nFile);
            edcLoadExternalBlockFile(chainparams, file, &pos);
            nFile++;
        }

        theApp.blocktree()->WriteReindexing(false);
        theApp.reindex( false );
        edcLogPrintf("Reindexing finished\n");

        // To avoid ending up in a situation without genesis block, re-try 
		// initializing (no-op if reindexing worked);
        edcInitBlockIndex(chainparams);
    }

    // hardcoded $DATADIR/bootstrap.dat
    boost::filesystem::path pathBootstrap = edcGetDataDir() / "bootstrap.dat";
    if (boost::filesystem::exists(pathBootstrap)) 
	{
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) 
		{
            boost::filesystem::path pathBootstrapOld = edcGetDataDir() / 
				"bootstrap.dat.old";

            edcLogPrintf("Importing bootstrap.dat...\n");
            edcLoadExternalBlockFile(chainparams, file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        } 
		else 
		{
            edcLogPrintf("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }

    // -eb_loadblock=
    BOOST_FOREACH(const boost::filesystem::path& path, vImportFiles) 
	{
        FILE *file = fopen(path.string().c_str(), "rb");
        if (file) 
		{
            edcLogPrintf("Importing blocks file %s...\n", path.string());
            edcLoadExternalBlockFile(chainparams, file);
        } 
		else 
		{
            edcLogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

	// scan for better chains in the block chain database, that are not yet connected in the active best chain
	CValidationState state;
	if (!ActivateBestChain(state, chainparams)) 
	{
		edcLogPrintf("Failed to connect best block");
		StartShutdown();
	}

    if (params.stopafterblockimport) 
	{
        edcLogPrintf("Stopping after block import\n");
        StartShutdown();
    }
}


void edcOnRPCStarted()
{
    edcUiInterface.NotifyBlockTip.connect(&edcRPCNotifyBlockChange);
}

void edcOnRPCStopped()
{
	EDCapp & theApp = EDCapp::singleton();

    edcUiInterface.NotifyBlockTip.disconnect(&edcRPCNotifyBlockChange);
    edcRPCNotifyBlockChange(false, nullptr);
    theApp.blockChange().notify_all();
    edcLogPrint("rpc", "EB RPC stopped.\n");
}

void edcOnRPCPreCommand(const CRPCCommand& cmd)
{
	EDCparams & params = EDCparams::singleton();

    // Observe safe mode
    std::string strWarning = edcGetWarnings("rpc");
    if (strWarning != "" && !params.disablesafemode && !cmd.okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, std::string("Safe mode: ") + strWarning);
}

// If we're using -eb_prune with -eb_reindex, then delete block files that will be 
// ignored by the reindex.  Since reindexing works by starting at block file 0 
// and looping until a blockfile is missing, do the same here to delete any 
// later block files after a gap.  Also delete all rev files since they'll be 
// rewritten by the reindex anyway.  This ensures that vinfoBlockFile is in 
// sync with what's actually on disk by the time we start downloading, so that 
// pruning works correctly.
//
void edcCleanupBlockRevFiles()
{
    using namespace boost::filesystem;
    std::map<std::string, path> mapBlockFiles;

    // Glob all blk?????.dat and rev?????.dat files from the blocks directory.
    // Remove the rev files immediately and insert the blk file paths into an
    // ordered map keyed by block file index.
    edcLogPrintf("Removing unusable blk?????.dat and rev?????.dat files for -eb_reindex with -eb_prune\n");
    path blocksdir = edcGetDataDir() / "blocks";
    for (directory_iterator it(blocksdir); it != directory_iterator(); it++) 
	{
        if (is_regular_file(*it) &&
            it->path().filename().string().length() == 12 &&
            it->path().filename().string().substr(8,4) == ".dat")
        {
            if (it->path().filename().string().substr(0,3) == "blk")
                mapBlockFiles[it->path().filename().string().substr(3,5)] = it->path();
            else if (it->path().filename().string().substr(0,3) == "rev")
                remove(it->path());
        }
    }

    // Remove all block files that aren't part of a contiguous set starting at
    // zero by walking the ordered map (keys are block file indices) by
    // keeping a separate counter.  Once we hit a gap (or if 0 doesn't exist)
    // start removing block files.
    int nContigCounter = 0;
    BOOST_FOREACH(const PAIRTYPE(std::string, path)& item, mapBlockFiles) 
	{
        if (atoi(item.first) == nContigCounter) 
		{
            nContigCounter++;
            continue;
        }
        remove(item.second);
    }
}

std::string edcChainNameFromCommandLine()
{
	EDCparams & params = EDCparams::singleton();

    if (params.regtest && params.testnet)
        throw std::runtime_error("Invalid combination of -eb_regtest and -eb_testnet.");
    if (params.regtest)
        return CBaseChainParams::REGTEST;
    if (params.testnet)
        return CBaseChainParams::TESTNET;
    return CBaseChainParams::MAIN;
}

bool edcAppInitServers(boost::thread_group& threadGroup)
{
	EDCparams & params = EDCparams::singleton();

	EDCRPCServer::OnStarted(&edcOnRPCStarted);
    EDCRPCServer::OnStopped(&edcOnRPCStopped);
    EDCRPCServer::OnPreCommand(&edcOnRPCPreCommand);

    if (!edcInitHTTPServer())
        return false;

    if (!edcStartRPC())
        return false;

    if (!edcStartHTTPRPC())
        return false;

    if (params.rest && !edcStartREST())
        return false;

    if (!edcStartHTTPServer())
        return false;

    return true;
}

bool EdcAppInit(
	boost::thread_group & threadGroup, 
		 	 CScheduler & scheduler,
			 const char * passPhrase )
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();
	bool rc = params.validate();

	if( !rc )
		return rc;

    // Check for -eb_testnet or -eb_regtest parameter (Params() calls are only valid 
	// after this clause)
    try 
	{
        edcSelectParams(edcChainNameFromCommandLine());
    } 
	catch (const std::exception& e) 
	{
        fprintf(stderr, "Error: %s\n", e.what());
        return false;
    }

	try
	{
		if(mapArgs.count("-eb_server") == 0 )
			params.server = true;

    	// Set this early so that parameter interactions go to console
	    edcInitLogging();

        // ************************************* Step 1: setup
		if(!theApp.initSSL( params.cacert, params.cert, params.privkey, 
		passPhrase, params.maxverdepth ))
			edcLogPrint( "net", "SSL initialization failed. Secure communications disabled\n" );

    	if (!SetupNetworking())
       	 	return edcInitError("Initializing networking failed");

    	// ************************************* Step 2: parameter interactions
    
		// Make sure enough file descriptors are available
    	int nBind = std::max((int)(params.bind.size() + params.whitebind.size()), 1);
	    int nUserMaxConnections = params.maxconnections;

    	int nMaxConnections = std::max(nUserMaxConnections, 0);

    	// Trim requested connection counts, to fit into system limitations
    	nMaxConnections =  std::max(std::min( nMaxConnections, 
			(int)(FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS)), 0);
    
		int nFD = RaiseFileDescriptorLimit( nMaxConnections + MIN_CORE_FILEDESCRIPTORS);
    	if (nFD < MIN_CORE_FILEDESCRIPTORS)
        	return edcInitError(_("Not enough file descriptors available."));
	    nMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS, nMaxConnections );

    	if ( nMaxConnections < nUserMaxConnections)
        	edcInitWarning(strprintf(_("Reducing -eb_maxconnections from %d to %d,"
				" because of system limitations."), 
				nUserMaxConnections, nMaxConnections ));

    	// ******************************** Step 3: parameter-to-internal-flags
    	theApp.debug( !params.debug.empty() );

    	// Special-case: if -eb_debug=0/-eb_nodebug is set, turn off debugging 
		// messages
    	const std::vector<std::string>& categories = params.debug;

    	if ( params.nodebug || find( categories.begin(), categories.end(), 
		std::string("0")) != categories.end())
        	theApp.debug( false );

    	const CEDCChainParams & chainparams = edcParams();

    	// Checkmempool and checkblockindex default to true in regtest mode
		params.checkmempool = chainparams.DefaultConsistencyChecks() ? 1 : 0;

	    int ratio = std::min<int>(std::max<int>(params.checkmempool, 0), 
			1000000);

    	if (ratio != 0) 
		{
        	theApp.mempool().setSanityCheck(1.0 / ratio);
    	}
    	params.checkblockindex = chainparams.DefaultConsistencyChecks();

    	// -eb_par=0 means autodetect, but scriptCheckThreads==0 means no 
		// concurrency
    	theApp.scriptCheckThreads( params.par );
    	if ( theApp.scriptCheckThreads() <= 0)
        	theApp.scriptCheckThreads( theApp.scriptCheckThreads() + GetNumCores() );
    	if ( theApp.scriptCheckThreads() <= 1)
	        theApp.scriptCheckThreads( 0 );
    	else if ( theApp.scriptCheckThreads() > EDC_MAX_SCRIPTCHECK_THREADS)
        	theApp.scriptCheckThreads( EDC_MAX_SCRIPTCHECK_THREADS );

    	edcRegisterAllCoreRPCCommands(edcTableRPC);

#ifdef ENABLE_WALLET
       	edcRegisterWalletRPCCommands(edcTableRPC);
#endif
	    theApp.connectTimeout( params.timeout );
   	 	if ( theApp.connectTimeout() <= 0)
        	theApp.connectTimeout( EDC_DEFAULT_CONNECT_TIMEOUT );

    	// Fee-per-kilobyte amount considered the same as "free"
	    // If you are mining, be careful setting this;
   	 	// if you set it to zero then
    	// a transaction spammer can cheaply fill blocks using
    	// 1-satoshi-fee transactions. It should be set above the real
    	// cost to you of processing a transaction.
    	if (params.minrelaytxfee.size() > 0 )
    	{
        	CAmount n = 0;
        	if (ParseMoney(params.minrelaytxfee, n) && n > 0)
            	theApp.minRelayTxFee( CFeeRate(n) );
        	else
            	return edcInitError(AmountErrMsg("eb_minrelaytxfee", params.minrelaytxfee));
    	}
#ifdef ENABLE_WALLET
		if (!CEDCWallet::ParameterInteraction())
   			return false;
#endif

	    ServiceFlags nLocalServices = NODE_NETWORK;
    	ServiceFlags nRelevantServices = NODE_NETWORK;

	    if ( params.peerbloomfilters )
   	    	nLocalServices = ServiceFlags( nLocalServices | NODE_BLOOM );

    	if (!params.bip9params.empty()) 
		{
        	// Allow overriding BIP9 parameters for testing
        	if (!edcParams().MineBlocksOnDemand()) 
			{
            	return edcInitError("BIP9 parameters may only be overridden on regtest.");
        	}

	        const std::vector<std::string> & deployments = params.bip9params;

        	for (auto i : deployments) 
			{
            	std::vector<std::string> vDeploymentParams;
            	boost::split(vDeploymentParams, i, boost::is_any_of(":"));

            	if (vDeploymentParams.size() != 3) 
				{
                	return edcInitError("BIP9 parameters malformed, expecting deployment:start:end");
            	}

	            int64_t nStartTime, nTimeout;
   	         	if (!ParseInt64(vDeploymentParams[1], &nStartTime)) 
				{
                	return edcInitError(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
            	}

            	if (!ParseInt64(vDeploymentParams[2], &nTimeout)) 
				{
                	return edcInitError(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
            	}

            	bool found = false;
            	for (int j=0; j<(int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j)
            	{
                	if (vDeploymentParams[0].compare(VersionBitsDeploymentInfo[j].name) == 0) 
					{
                    	edcUpdateRegtestBIP9Parameters(Consensus::DeploymentPos(j), nStartTime, 
							nTimeout);
                    	found = true;
                    	edcLogPrintf("Setting BIP9 activation parameters for %s to start=%ld, "
							"timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                    	break;
                	}
            	}
            	if (!found) 
				{
                	return edcInitError(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
            	}
        	}
    	}

    	// ** Step 4:app initialization: dir lock, daemonize, pidfile, debug log

    	std::string strDataDir = edcGetDataDir().string();

	    // Make sure only a single Equibit process is using the data directory.
   	 	boost::filesystem::path pathLockFile = edcGetDataDir() / ".lock";

		// empty lock file; created if it doesn't exist.
    	FILE * file = fopen(pathLockFile.string().c_str(), "a" ); 
	    if (file) 
			fclose(file);

   	 	try 
		{
        	static boost::interprocess::file_lock lock(
				pathLockFile.string().c_str());

        	if (!lock.try_lock())
            	return edcInitError(strprintf(_("Cannot obtain a lock on data "
					"directory %s. %s is probably already running."), 
					strDataDir, _(PACKAGE_NAME)));
    	} 
		catch( const boost::interprocess::interprocess_exception & e ) 
		{
        	return edcInitError(strprintf(_("Cannot obtain a lock on data "
				"directory %s. %s is probably already running.") + " %s.", 
				strDataDir, _(PACKAGE_NAME), e.what()));
    	}

    	CreatePidFile(edcGetPidFile(), getpid());

    	if (params.debug.size() > 0 )
        	edcShrinkDebugFile();

    	if (fPrintToDebugLog)
        	edcOpenDebugLog();

    	if (!params.logtimestamps)
        	edcLogPrintf("Startup time: %s\n", 
				DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));

    	edcLogPrintf("Default data directory %s\n", 
			edcGetDefaultDataDir().string());

    	edcLogPrintf("Using data directory %s\n", edcGetDataDir() );
    	edcLogPrintf("Using config file %s\n", edcGetConfigFile().string());
    	edcLogPrintf("Using at most %i connections (%i file descriptors "
			"available)\n", nMaxConnections, nFD);

    	edcLogPrintf("Using %u threads for script verification\n", theApp.scriptCheckThreads() );
    	if ( theApp.scriptCheckThreads() ) 
		{
        	for (int i=0; i < theApp.scriptCheckThreads(); ++i )
            	threadGroup.create_thread( &edcThreadScriptCheck );
    	}

    	// Start the lightweight task scheduler thread
    	CScheduler::Function serviceLoop = 
			boost::bind(&CScheduler::serviceQueue, &scheduler);
	    threadGroup.create_thread(boost::bind(
			&edcTraceThread<CScheduler::Function>, "scheduler", serviceLoop));

        /* Start the RPC server already.  It will be started in "warmup" mode
         * and not really process calls already (but it will signify connections
         * that the server is there and will be ready later).  Warmup mode will
         * be disabled when initialisation is finished.
         */
        if (params.server)
        {
            edcUiInterface.InitMessage.connect(edcSetRPCWarmupStatus);
            if (!edcAppInitServers(threadGroup))
                return edcInitError(_("Unable to start HTTP server. See debug log for details."));
        }

    	// **************************** Step 5: verify wallet database integrity
#ifdef ENABLE_WALLET
       	if (!CEDCWallet::Verify())
           	return false;
#endif

    	// ************************************* Step 6: network initialization

		assert(!theApp.connman());
		theApp.connman(new CEDCConnman(GetRand(std::numeric_limits<uint64_t>::max()), GetRand(std::numeric_limits<uint64_t>::max())));
		CEDCConnman & connman = *theApp.connman();

	    RegisterNodeSignals(edcGetNodeSignals());

    	// sanitize comments per BIP-0014, format user agent and check total siz
    	std::vector<std::string> uacomments;
	    BOOST_FOREACH(std::string cmt, params.uacomment)
   	 	{
        	if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            	return edcInitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        	uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT));
    	}
    	theApp.strSubVersion( FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments) );
    	if (theApp.strSubVersion().size() > EDC_MAX_SUBVERSION_LENGTH) 
		{
        	return edcInitError(strprintf(_("Total length of network version "
				"string (%i) exceeds maximum length (%i). Reduce the number or "
				"size of uacomments."),
            	theApp.strSubVersion().size(), EDC_MAX_SUBVERSION_LENGTH));
    	}

	    if ( params.onlynet.size() > 0 ) 
		{
	        std::set<enum Network> nets;
	        BOOST_FOREACH(const std::string& snet, params.onlynet ) 
			{
	            enum Network net = ParseNetwork(snet);
	            if (net == NET_UNROUTABLE)
	                return edcInitError(strprintf(_("Unknown network specified "
						"in -eb_onlynet: '%s'"), snet));
	            nets.insert(net);
	        }
	        for (int n = 0; n < NET_MAX; n++) 
			{
	            enum Network net = (enum Network)n;
	            if (!nets.count(net))
	                edcSetLimited(net, true );
	        }
	    }
	
    	if (params.whitelist.size() > 0 ) 
		{
        	BOOST_FOREACH(const std::string& net, params.whitelist) 
			{
            	CSubNet subnet;
            	LookupSubNet(net.c_str(), subnet);
            	if (!subnet.IsValid())
                	return edcInitError(strprintf(_("Invalid netmask specified "
						"in -eb_whitelist: '%s'"), net));
            	connman.AddWhitelistedRange(subnet);
        	}
    	}

    	bool proxyRandomize = params.proxyrandomize;

    	// -eb_proxy sets a proxy for all outgoing network traffic
    	// -eb_noproxy (or -eb_proxy=0) as well as the empty string can be used to 
		// not set a proxy, this is the default
    	std::string proxyArg = params.proxy;
    	edcSetLimited(NET_TOR, true );

    	if (proxyArg != "" && proxyArg != "0") 
		{
        	CService resolved(LookupNumeric(proxyArg.c_str(), 9050));
        	proxyType addrProxy = proxyType(resolved, proxyRandomize);

        	if (!addrProxy.IsValid())
            	return edcInitError(strprintf(_("Invalid -eb_proxy address: '%s'"),
					proxyArg));

        	edcSetProxy(NET_IPV4, addrProxy);
        	edcSetProxy(NET_IPV6, addrProxy);
        	edcSetProxy(NET_TOR, addrProxy);
        	edcSetNameProxy(addrProxy);

        	edcSetLimited(NET_TOR, false); // by default, -eb_proxy sets onion as 
										// reachable, unless -eb_noonion later
    	}

	    // -eb_onion can be used to set only a proxy for .onion, or override 
		// normal proxy for .onion addresses
		// -eb_noonion (or -eb_onion=0) disables connecting to .onion entirely
	    // An empty string is used to not override the onion proxy (in which 
		// case it defaults to -eb_proxy set above, or none)
	    std::string onionArg = params.onion;
	    if (onionArg != "") 
		{
	        if (onionArg == "0") 
			{ 
				// Handle -eb_noonion/-eb_onion=0
	            edcSetLimited(NET_TOR, true ); // set onions as unreachable
	        } 
			else 
			{
            	CService resolved(LookupNumeric(onionArg.c_str(), 9050));
            	proxyType addrOnion = proxyType(resolved, proxyRandomize);

	            if (!addrOnion.IsValid())
	                return edcInitError(strprintf(_("Invalid -eb_onion address: "
						"'%s'"), onionArg));
	            edcSetProxy(NET_TOR, addrOnion);
	            edcSetLimited(NET_TOR, false);
	        }
	    }
	
    	// see Step 2: parameter interactions for more information about these
	    if (params.listen) 
		{
	    	bool fBound = false;
	        if (params.bind.size() > 0 || params.whitebind.size() > 0 ) 
			{
	            BOOST_FOREACH(const std::string & strBind, params.bind) 
				{
	                CService addrBind;

	                if (!Lookup(strBind.c_str(), addrBind, edcGetListenPort(), false))
	                    return edcInitError(ResolveErrMsg("bind", strBind));
	                fBound |= Bind(connman, addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));

					if(theApp.sslEnabled() )
					{
	                	if (!Lookup(strBind.c_str(), addrBind, edcGetListenSecurePort(), false))
	                    	return edcInitError(ResolveErrMsg("bind", strBind));
	                	fBound |= Bind(connman, addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));
					}
	            }
	            BOOST_FOREACH(const std::string& strBind, params.whitebind) 
				{
	                CService addrBind;
	                if (!Lookup(strBind.c_str(), addrBind, 0, false))
	                    return edcInitError(ResolveErrMsg("whitebind", strBind));
	                if (addrBind.GetPort() == 0)
	                    return edcInitError(strprintf(_("Need to specify a port with -eb_whitebind: '%s'"), strBind));

	                fBound |= Bind(connman, addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
	            }
	        }
	        else 
			{
	            struct in_addr inaddr_any;
	            inaddr_any.s_addr = INADDR_ANY;

	            fBound |= Bind(connman, CService(in6addr_any, edcGetListenPort()), BF_NONE);
	            fBound |= Bind(connman, CService(inaddr_any, edcGetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE);

				if(theApp.sslEnabled() )
				{
		            fBound |= Bind(connman, CService(in6addr_any, edcGetListenSecurePort()), BF_NONE);
		            fBound |= Bind(connman, CService(inaddr_any, edcGetListenSecurePort()), !fBound ? BF_REPORT_ERROR : BF_NONE);
				}
	        }
	        if (!fBound)
	            return edcInitError(_("Failed to listen on any port. Use -eb_listen=0 if you want this."));
	    }
	
    	if (params.externalip.size() > 0 ) 
		{
   	     	BOOST_FOREACH(const std::string& strAddr, params.externalip )
			{
            	CService addrLocal;
            	if (Lookup(strAddr.c_str(), addrLocal, edcGetListenPort(), 
				params.dns) && addrLocal.IsValid())
                	edcAddLocal(addrLocal, LOCAL_MANUAL);
            	else
                	return edcInitError(ResolveErrMsg("externalip", strAddr));
        	}
    	}

    	BOOST_FOREACH(const std::string& strDest, params.seednode)
        	theApp.connman()->AddOneShot(strDest);

	    uint64_t nMaxOutboundLimit = 0; //unlimited unless -maxuploadtarget is set
    	uint64_t nMaxOutboundTimeframe = EDC_MAX_UPLOAD_TIMEFRAME;

    	if (params.maxuploadtarget > 0 ) 
		{
			nMaxOutboundLimit = params.maxuploadtarget *1024*1024;
    	}

    	// ******************************************** Step 7: load block chain

	    theApp.reindex( params.reindex );

        // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/
        boost::filesystem::path blocksDir = edcGetDataDir() / "blocks";
        if (!boost::filesystem::exists(blocksDir))
        {
            boost::filesystem::create_directories(blocksDir);
            bool linked = false;
            for (unsigned int i = 1; i < 10000; i++) 
    		{
                boost::filesystem::path source = edcGetDataDir() / strprintf("blk%04u.dat", i);
                if (!boost::filesystem::exists(source)) break;
                boost::filesystem::path dest = blocksDir / strprintf("blk%05u.dat", i-1);
                try 
    			{
                    boost::filesystem::create_hard_link(source, dest);
                    edcLogPrintf("Hardlinked %s -> %s\n", source.string(), dest.string());
                    linked = true;
                } 
    			catch (const boost::filesystem::filesystem_error& e) 
    			{
                    // Note: hardlink creation failing is not a disaster, it just means
                    // blocks will get re-downloaded from peers.
                    edcLogPrintf("Error hardlinking blk%04u.dat: %s\n", i, e.what());
                    break;
                }
            }
            if (linked)
            {
                theApp.reindex( true );
            }
        }
    
    	// cache size calculations
    	int64_t nTotalCache = (params.dbcache << 20);

		// total cache cannot be less than EDC_MIN_DB_CACHE
    	nTotalCache = std::max(nTotalCache, EDC_MIN_DB_CACHE << 20); 

		// total cache cannot be greater than EDC_MAX_DB_CACHE
    	nTotalCache = std::min(nTotalCache, EDC_MAX_DB_CACHE << 20); 

	    int64_t nBlockTreeDBCache = nTotalCache / 8;
		nBlockTreeDBCache = std::min(nBlockTreeDBCache, (params.txindex ? nMaxBlockDBAndTxIndexCache : nMaxBlockDBCache) << 20);
	    nTotalCache -= nBlockTreeDBCache;
	    int64_t nCoinDBCache = std::min(nTotalCache / 2, (nTotalCache / 4) + (1 << 23)); // use 25%-50% of the remainder for disk cache
		nCoinDBCache = std::min(nCoinDBCache, nMaxCoinsDBCache << 20); // cap total coins db cache
	    nTotalCache -= nCoinDBCache;
	    theApp.coinCacheUsage( nTotalCache ); // the rest goes to in-memory cache
	    edcLogPrintf("Cache configuration:\n");
	    edcLogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
	    edcLogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
	    edcLogPrintf("* Using %.1fMiB for in-memory UTXO set\n", theApp.coinCacheUsage() * (1.0 / 1024 / 1024));
	
	    bool fLoaded = false;
	    int64_t nStart;
	
	    while (!fLoaded) 
		{
	        bool fReset = theApp.reindex();
	        std::string strLoadError;
	
	        edcUiInterface.InitMessage(_("Loading block index..."));
	
	        nStart = GetTimeMillis();
	        do 
			{
	            try 
				{
	                edcUnloadBlockIndex();
	                delete theApp.coinsTip();
	                delete pcoinsdbview;
	                delete pcoinscatcher;
	                delete theApp.blocktree();
	
	                theApp.blocktree( new CEDCBlockTreeDB(nBlockTreeDBCache, false, theApp.reindex() ) );
	                pcoinsdbview = new CEDCCoinsViewDB(nCoinDBCache, false, theApp.reindex() || params.reindex_chainstate );
	                pcoinscatcher = new CEDCCoinsViewErrorCatcher(pcoinsdbview);
	                theApp.coinsTip( new CEDCCoinsViewCache(pcoinscatcher) );
	
	                if (theApp.reindex()) 
					{
	                    theApp.blocktree()->WriteReindexing(true);
	                    //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
	                    if (theApp.pruneMode())
	                        edcCleanupBlockRevFiles();
	                }

	                if (!edcLoadBlockIndex()) 
					{
	                    strLoadError = _("Error loading block database");
	                    break;
	                }

	                // If the loaded chain has a wrong genesis, bail out 
					// immediately (we're likely using a testnet datadir, or 
					// the other way around).
	                if (!theApp.mapBlockIndex().empty() && 
						theApp.mapBlockIndex().count(chainparams.GetConsensus().
							hashGenesisBlock) == 0)
	                    return edcInitError(_("Incorrect or no genesis block "
							"found. Wrong datadir for network?"));
	
	                // Initialize the block index (no-op if non-empty database 
					// was already loaded)
	                if (!edcInitBlockIndex(chainparams)) 
					{
	                    strLoadError = _("Error initializing block database");
	                    break;
	                }
	
	                // Check for changed -eb_txindex state
	                if ( theApp.txIndex() != params.txindex) 
					{
	                    strLoadError = _("You need to rebuild the database using -eb_reindex-chainstate to change -eb_txindex");
	                    break;
	                }
	
	                // Check for changed -eb_prune state.  What we are concerned about is a user who has pruned blocks
	                // in the past, but is now trying to run unpruned.
	                if (theApp.havePruned() && !theApp.pruneMode()) 
					{
	                    strLoadError = _("You need to rebuild the database using -eb_reindex to go back to unpruned mode.  This will redownload the entire blockchain");
	                    break;
	                }
	
					if (!theApp.reindex() && theApp.chainActive().Tip() != NULL)
					{
                    	edcUiInterface.InitMessage(_("Rewinding blocks..."));

                    	if (!edcRewindBlockIndex(chainparams)) 
						{
                        	strLoadError = _("Unable to rewind the database to a pre-fork state. "
								"You will need to redownload the blockchain");
                        	break;
                    	}
                	}

	                edcUiInterface.InitMessage(_("Verifying blocks..."));
	                if (theApp.havePruned() && params.checkblocks > EDC_MIN_BLOCKS_TO_KEEP) 
					{
	                    edcLogPrintf("Prune: pruned datadir may not have more than %d blocks; only checking available blocks",
	                        EDC_MIN_BLOCKS_TO_KEEP );
	                }
	
	                {
	                    LOCK(EDC_cs_main);
	                    CBlockIndex* tip = theApp.chainActive().Tip();
						edcRPCNotifyBlockChange(true, tip);
	                    if (tip && tip->nTime > edcGetAdjustedTime() + 2 * 60 * 60) 
						{
	                        strLoadError = _("The block database contains a block which appears to be from the future. "
	                                "This may be due to your computer's date and time being set incorrectly. "
	                                "Only rebuild the block database if you are sure that your computer's date and time are correct");
	                        break;
	                    }
	                }
	
	                if (!CEDCVerifyDB().VerifyDB(chainparams, pcoinsdbview, 
							params.checklevel,
	                        params.checkblocks )) 
					{
	                    strLoadError = _("Corrupted block database detected");
	                    break;
	                }
	            } 
				catch (const std::exception & e ) 
				{
	                if (params.debug.size() > 0 )
						edcLogPrintf("%s\n", e.what());
	                strLoadError = _("Error opening block database");
	                break;
	            }
	            fLoaded = true;
	        } while(false);
	
	        if (!fLoaded) 
			{
	            // first suggest a reindex
	            if (!fReset) 
				{
	                bool fRet = edcUiInterface.ThreadSafeQuestion(
						strLoadError +".\n\n" + _("Do you want to rebuild the block database now?"),
	                    strLoadError + 
						".\nPlease restart with -reindex or -reindex-chainstate to recover.",
	                    "", CEDCClientUIInterface::MSG_ERROR | CEDCClientUIInterface::BTN_ABORT);
	                if (fRet) 
					{
	                    theApp.reindex( true );
		                fRequestShutdown = false;
	                } 
					else 
					{
	                    edcLogPrintf(
							"Aborted block database rebuild. Exiting.\n");
	                    return false;
	                }
	            } 
				else 
				{
	                return edcInitError(strLoadError);
	            }
	        }
	    }

    	// As LoadBlockIndex can take several minutes, it's possible the user
	    // requested to kill the GUI during the last operation. If so, exit.
   	 	// As the program has not fully started yet, Shutdown() is possibly 
		// overkill.
    	if (fRequestShutdown)
    	{
        	edcLogPrintf("Shutdown requested. Exiting.\n");
        	return false;
    	}
    	edcLogPrintf(" block index %15dms\n", GetTimeMillis() - nStart);

    	boost::filesystem::path est_path = edcGetDataDir() / 
			FEE_ESTIMATES_FILENAME;
    	CAutoFile est_filein(fopen(est_path.string().c_str(), "rb"), SER_DISK, 
			CLIENT_VERSION);

    	// Allowed to fail as this file IS missing on first startup.
    	if (!est_filein.IsNull())
        	theApp.mempool().ReadFeeEstimates(est_filein);
    	fFeeEstimatesInitialized = true;

    	// ************************************************* Step 8: load wallet
#ifdef ENABLE_WALLET
       	if(!CEDCWallet::InitLoadWallet())
           	return false;
#else 
    	edcLogPrintf("No wallet support compiled in!\n");
#endif 
    	// ********************************** Step 9: data directory maintenance

    	// if pruning, unset the service bit and perform the initial blockstore
		//  prune after any wallet rescanning has taken place.
    	if (theApp.pruneMode()) 
		{
        	edcLogPrintf("Unsetting NODE_NETWORK on prune mode\n");
        	nLocalServices = ServiceFlags( nLocalServices  & ~NODE_NETWORK );
        	if (!theApp.reindex()) 
			{
            	edcUiInterface.InitMessage(_("Pruning blockstore..."));
            	edcPruneAndFlush();
        	}
    	}

    	if (edcParams().GetConsensus().vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) 
		{
       		// Only advertize witness capabilities if they have a reasonable start time.
        	// This allows us to have the code merged without a defined softfork, by setting its
        	// end time to 0.
        	// Note that setting NODE_WITNESS is never required: the only downside from not
        	// doing so is that after activation, no upgraded nodes will fetch from you.
        	nLocalServices = ServiceFlags( nLocalServices | NODE_WITNESS);

        	// Only care about others providing witness capabilities if there is a softfork
        	// defined.
        	nRelevantServices = ServiceFlags( nRelevantServices | NODE_WITNESS);
    	}

    	// ********************************************* Step 10: import blocks

	    if (!edcCheckDiskSpace())
        	return false;

    	// Either install a handler to notify us when genesis activates, or set 
		// fHaveGenesis directly. No locking, as this happens before any background thread is 
		// started.
    	if (theApp.chainActive().Tip() == NULL) 
		{
        	edcUiInterface.NotifyBlockTip.connect(BlockNotifyGenesisWait);
    	} 
		else 
		{
        	fHaveGenesis = true;
    	}

    	if (params.blocknotify.size() > 0 )
        	edcUiInterface.NotifyBlockTip.connect(BlockNotifyCallback);

    	std::vector<boost::filesystem::path> vImportFiles;
    	if (params.loadblock.size() > 0 )
	    {
        	BOOST_FOREACH(const std::string& strFile, params.loadblock )
            	vImportFiles.push_back(strFile);
    	}

    	threadGroup.create_thread(boost::bind(&edcThreadImport, vImportFiles));

		// Wait for genesis block to be processed
		{
        	boost::unique_lock<boost::mutex> lock(cs_GenesisWait);
        	while (!fHaveGenesis) 
			{
            	condvar_GenesisWait.wait(lock);
         	}
        	edcUiInterface.NotifyBlockTip.disconnect(BlockNotifyGenesisWait);
        }

    	// ************************************************* Step 11: start node

    	//// debug print
    	edcLogPrintf("mapBlockIndex.size() = %u\n", theApp.mapBlockIndex().size());
    	edcLogPrintf("nBestHeight = %d\n", theApp.chainActive().Height());

		if(params.listenonion )
			edcStartTorControl( threadGroup, scheduler );

	    edcDiscover(threadGroup);

 		// Map ports with UPnP
		edcMapPort(params.upnp);

		std::string strNodeError;
		CEDCConnman::Options connOptions;
		connOptions.nLocalServices = nLocalServices;
		connOptions.nRelevantServices = nRelevantServices;
		connOptions.nMaxConnections = nMaxConnections;
		connOptions.nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, connOptions.nMaxConnections);
		connOptions.nMaxFeeler = 1;
		connOptions.nBestHeight = theApp.chainActive().Height();
		connOptions.uiInterface = &edcUiInterface;
		connOptions.nSendBufferMaxSize = 1000*params.maxsendbuffer;
		connOptions.nReceiveFloodSize = 1000*params.maxreceivebuffer;
	    connOptions.nMaxOutboundTimeframe = nMaxOutboundTimeframe;
   		connOptions.nMaxOutboundLimit = nMaxOutboundLimit;

		if(!connman.Start(threadGroup, scheduler, strNodeError, connOptions))
        	return InitError(strNodeError);

		// *************************************************** Step 12: finished
		edcSetRPCWarmupFinished();

    	edcUiInterface.InitMessage(_("Done loading"));

#ifdef ENABLE_WALLET
    	if (theApp.walletMain()) 
		{
        	// Run a thread to flush wallet periodically
        	threadGroup.create_thread(
				boost::bind(&edcThreadFlushWalletDB, 
				boost::ref(theApp.walletMain()->strWalletFile)));
    	}
#endif
		params.dumpToLog();
		params.checkParams();

#ifdef USE_HSM
		if(params.usehsm)
		{
			if( GetBoolArg("-daemon", false) )
			{
        		return edcInitError( "Only one of parameters -daemon and -eb_usehsm can be specified" );
			}

			rc = NFast::init(theApp.nfApp(), 
					theApp.nfSecWorld(), 
					theApp.nfHardServer(),
					theApp.nfCardLoadingLib(),
					theApp.nfModule() );
		}
#endif
	}
	catch( const std::exception & e )
	{
        edcPrintExceptionContinue(&e, "EdcAppInit()");
		rc = false;
    } 
	catch (...) 
	{
        edcPrintExceptionContinue(NULL, "EdcAppInit()");
		rc = false;
    }

	return rc;
}

void edcInterrupt(boost::thread_group& threadGroup)
{
    edcInterruptHTTPServer();
    edcInterruptHTTPRPC();
    edcInterruptRPC();
    edcInterruptREST();
    edcInterruptTorControl();
    threadGroup.interrupt_all();
}

void edcShutdown()
{
	EDCapp & theApp = EDCapp::singleton();

    edcLogPrintf("%s: In progress...\n", __func__);

    static CCriticalSection cs_Shutdown;

    TRY_LOCK(cs_Shutdown, lockShutdown);

    if (!lockShutdown)
        return;

    /// Note: Shutdown() must be able to handle cases in which AppInit2() 
	/// failed part of the way, for example if the data directory was found to 
	/// be locked. Be sure that anything that writes files or flushes caches 
	/// only does this if the respective module was initialized.
    RenameThread("equibit-shutoff");

    theApp.mempool().AddTransactionsUpdated(1);

    edcStopHTTPRPC();
    edcStopREST();
    edcStopRPC();
    edcStopHTTPServer();

#ifdef ENABLE_WALLET
    if (theApp.walletMain())
        theApp.walletMain()->Flush(false);
#endif
	edcMapPort(false);
	theApp.connman().reset();

    edcStopTorControl();
	UnregisterNodeSignals(edcGetNodeSignals());

    if (fFeeEstimatesInitialized)
    {
        boost::filesystem::path est_path = edcGetDataDir() / 
			FEE_ESTIMATES_FILENAME;

        CAutoFile est_fileout(fopen(est_path.string().c_str(), "wb"), SER_DISK, CLIENT_VERSION);
        if (!est_fileout.IsNull())
            theApp.mempool().WriteFeeEstimates(est_fileout);
        else
            edcLogPrintf("%s: Failed to write fee estimates to %s\n", 
				__func__, est_path.string());
        fFeeEstimatesInitialized = false;
    }

    {
        LOCK(EDC_cs_main);

        if (theApp.coinsTip() != NULL) 
		{
            edcFlushStateToDisk();
        }

        delete theApp.coinsTip();
        theApp.coinsTip( NULL );

        delete pcoinscatcher;
        pcoinscatcher = NULL;

        delete pcoinsdbview;
        pcoinsdbview = NULL;

        delete theApp.blocktree();
        theApp.blocktree( NULL );
    }
#ifdef ENABLE_WALLET
    if (theApp.walletMain())
        theApp.walletMain()->Flush(true);
#endif

#if ENABLE_ZMQ
    if (pzmqNotificationInterface) 
	{
        UnregisterValidationInterface(pzmqNotificationInterface);
        delete pzmqNotificationInterface;
        pzmqNotificationInterface = NULL;
    }
#endif

#ifndef WIN32
    try 
	{
        boost::filesystem::remove(edcGetPidFile());
    } 
	catch (const boost::filesystem::filesystem_error& e) 
	{
        edcLogPrintf("%s: Unable to remove pidfile: %s\n", __func__, e.what());
    }
#endif
    edcUnregisterAllValidationInterfaces();

#ifdef ENABLE_WALLET
    delete theApp.walletMain();
    theApp.walletMain( NULL );
#endif

    ECC_Stop();
    edcLogPrintf("%s: done\n", __func__);
}
