// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcparams.h"
#include "edcutil.h"
#include "edcchainparams.h"
#include "edc/wallet/edcwallet.h"
#include "edcapp.h"
#include "utilmoneystr.h"
#include "policy/policy.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/foreach.hpp>
#include <sys/types.h>
#include <sys/stat.h>


namespace
{

const int64_t      EDC_DEFAULT_DB_CACHE               = 300;
const unsigned int EDC_MAX_OP_RETURN_RELAY            = 83;
const uint64_t     EDC_MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024;


const bool         EDC_DEFAULT_ACCEPT_DATACARRIER      = true;
const unsigned int EDC_DEFAULT_ANCESTOR_LIMIT          = 25;
const unsigned int EDC_DEFAULT_ANCESTOR_SIZE_LIMIT     = 101;

const unsigned int EDC_DEFAULT_BANSCORE_THRESHOLD      = 100;
const unsigned int EDC_DEFAULT_BLOCK_MAX_SIZE          = 750000;
const unsigned int EDC_DEFAULT_BLOCK_PRIORITY_SIZE     = 0;
const bool         EDC_DEFAULT_BLOCKSONLY              = false;
const unsigned int EDC_DEFAULT_BYTES_PER_SIGOP         = 20;

const signed int   EDC_DEFAULT_CHECKBLOCKS             = 6;
const unsigned int EDC_DEFAULT_CHECKLEVEL              = 3;
const bool         EDC_DEFAULT_CHECKPOINTS_ENABLED     = true;
const char * const EDC_DEFAULT_CONF_FILENAME           = "equibit.conf";

const unsigned int EDC_DEFAULT_DESCENDANT_LIMIT        = 25;
const unsigned int EDC_DEFAULT_DESCENDANT_SIZE_LIMIT   = 101;
const bool         EDC_DEFAULT_DISABLE_SAFEMODE        = false;
const bool         EDC_DEFAULT_DISABLE_WALLET          = false;

const bool         EDC_DEFAULT_ENABLE_REPLACEMENT      = true;

const bool         EDC_DEFAULT_FEEFILTER               = true;
const bool         EDC_DEFAULT_FLUSHWALLET             = true;
const bool         EDC_DEFAULT_FORCEDNSSEED            = false;

const int          EDC_DEFAULT_HTTP_SERVER_TIMEOUT     = 30;
const int          EDC_DEFAULT_HTTP_THREADS            = 4;
const int          EDC_DEFAULT_HTTP_WORKQUEUE          = 16;

const unsigned int EDC_DEFAULT_LIMITFREERELAY          = 15;
const bool         EDC_DEFAULT_LISTEN                  = true;
const bool         EDC_DEFAULT_LISTEN_ONION            = true;
const bool         EDC_DEFAULT_LOGIPS                  = false;
const bool         EDC_DEFAULT_LOGTIMESTAMPS           = true;
const bool         EDC_DEFAULT_LOGTIMEMICROS           = false;

const unsigned int EDC_DEFAULT_MAX_MEMPOOL_SIZE        = 300;
const unsigned int EDC_DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
const unsigned int EDC_DEFAULT_MAX_PEER_CONNECTIONS    = 125;
const unsigned int EDC_DEFAULT_MAX_SIG_CACHE_SIZE      = 40;
const int64_t      EDC_DEFAULT_MAX_TIME_ADJUSTMENT     = 70 * 60;
const int64_t      EDC_DEFAULT_MAX_TIP_AGE             = 24 * 60 * 60;
const uint64_t     EDC_DEFAULT_MAX_UPLOAD_TARGET       = 0;
const uint64_t     EDC_DEFAULT_MAX_VERIFY_DEPTH        = 1;
const size_t       EDC_DEFAULT_MAXRECEIVEBUFFER        = 5 * 1000;
const size_t       EDC_DEFAULT_MAXSENDBUFFER           = 1 * 1000;
const unsigned int EDC_DEFAULT_MEMPOOL_EXPIRY          = 72;
const unsigned int EDC_DEFAULT_MISBEHAVING_BANTIME     = 60 * 60 * 24;  // Default 24-hour ban

const bool         EDC_DEFAULT_PEERBLOOMFILTERS        = true;
const bool         EDC_DEFAULT_PERMIT_BAREMULTISIG     = true;
const bool         EDC_DEFAULT_PRINTPRIORITY           = false;
const bool         EDC_DEFAULT_PROXYRANDOMIZE          = true;

const bool         EDC_DEFAULT_RELAYPRIORITY           = true;
const bool         EDC_DEFAULT_REST_ENABLE             = false;

const int          EDC_DEFAULT_SCRIPTCHECK_THREADS     = 0;
const bool         EDC_DEFAULT_SEND_FREE_TRANSACTIONS  = false;
const bool         EDC_DEFAULT_SPEND_ZEROCONF_CHANGE   = true;
const bool         EDC_DEFAULT_STOPAFTERBLOCKIMPORT    = false;

const bool         EDC_DEFAULT_TESTSAFEMODE            = false;
const char * const EDC_DEFAULT_TOR_CONTROL             = "127.0.0.1:9051";
const unsigned int EDC_DEFAULT_TX_CONFIRM_TARGET       = 2;
const bool         EDC_DEFAULT_TXINDEX                 = false;

const bool         EDC_DEFAULT_UPNP                    = false;

const char *       EDC_DEFAULT_WALLET_DAT              = "wallet.dat";
const bool         EDC_DEFAULT_WHITELISTFORCERELAY     = true;
const bool         EDC_DEFAULT_WHITELISTRELAY          = true;

const std::string  COOKIEAUTH_FILE                     = ".cookie";
const char * const EQUIBIT_PID_FILENAME                = "equibit.pid";


bool InterpretBool(const std::string& strValue)
{
    if (strValue.empty())
        return true;
    return (atoi(strValue) != 0);
}

void InterpretNegativeSetting(
	std::string& strKey, 
	std::string& strValue)
{
    if (strKey.length()>3 && strKey[0]=='-' && strKey[1]=='n' && strKey[2]=='o')
    {
        strKey = "-" + strKey.substr(3);
        strValue = InterpretBool(strValue) ? "0" : "1";
    }
}

boost::filesystem::path GetConfigFile( 
	const std::string & dataDir, 
	const std::string & confFile )
{
    boost::filesystem::path pathConfigFile( confFile );

    if (!pathConfigFile.is_complete())
        pathConfigFile = dataDir / pathConfigFile;

    return pathConfigFile;
}

void ReadEquibitConfigFile(
                                   const std::string & dataDir,
                                   const std::string & confFile,
	              std::map<std::string, std::string> & mapSettingsRet,
    std::map<std::string, std::vector<std::string> > & mapMultiSettingsRet )
{
    boost::filesystem::ifstream streamConfig(GetConfigFile(dataDir, confFile));
    if (!streamConfig.good())
        return; // No equibit.conf file is OK

    std::set<std::string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, 
	setOptions), end; it != end; ++it)
    {
        // Don't overwrite existing settings so command line settings override 
		// equibit.conf
		//
        std::string strKey = std::string("-") + it->string_key;
        std::string strValue = it->value[0];
        InterpretNegativeSetting(strKey, strValue);

        if (mapSettingsRet.count(strKey) == 0)
            mapSettingsRet[strKey] = strValue;

        mapMultiSettingsRet[strKey].push_back(strValue);
    }
    // If datadir is changed in .conf file:
    edcClearDatadirCache();
}

}

EDCparams::EDCparams()
{
	datadir = GetArg( "-eb_datadir", edcGetDefaultDataDir().string() );

	// First load the config file, which may contain more settings
	//
	conf = GetArg( "-eb_conf", EDC_DEFAULT_CONF_FILENAME );

	try
	{
		ReadEquibitConfigFile( datadir, conf, mapArgs, mapMultiArgs );
	}
	catch(const std::exception& e) 
	{
        fprintf(stderr,"Error reading configuration file: %s\n", e.what());
        configFileReadFailed = true;
    }
    configFileReadFailed = false;

	regtest  = GetBoolArg( "-eb_regtest", false );
	testnet  = GetBoolArg( "-eb_testnet", false );

	std::string network = regtest?
		(CBaseChainParams::REGTEST):
		(testnet?CBaseChainParams::TESTNET:CBaseChainParams::MAIN);

	// Bool parameters
	acceptnonstdtxn     = GetBoolArg( "-eb_acceptnonstdtxn", 
		!edcParams(network).RequireStandard() );
	blocksonly          = GetBoolArg( "-eb_blocksonly", EDC_DEFAULT_BLOCKSONLY );
	checkblockindex     = GetBoolArg( "-eb_checkblockindex", regtest );
	checkmempool        = GetBoolArg( "-eb_checkmempool", regtest );
	checkparams         = GetBoolArg( "-eb_checkparams", true );
	checkpoints         = GetBoolArg( "-eb_checkpoints", EDC_DEFAULT_CHECKPOINTS_ENABLED );
	datacarrier         = GetBoolArg( "-eb_datacarrier", EDC_DEFAULT_ACCEPT_DATACARRIER );
	disablesafemode     = GetBoolArg( "-eb_disablesafemode", EDC_DEFAULT_DISABLE_SAFEMODE );
	disablewallet       = GetBoolArg( "-eb_disablewallet", EDC_DEFAULT_DISABLE_WALLET );
	discover            = GetBoolArg( "-eb_discover", true );
	dns                 = GetBoolArg( "-eb_dns", true );
	dnsseed             = GetBoolArg( "-eb_dnsseed", true );
	feefilter           = GetBoolArg( "-eb_feefilter", EDC_DEFAULT_FEEFILTER );
	flushwallet         = GetBoolArg( "-eb_flushwallet",EDC_DEFAULT_FLUSHWALLET);
	forcednsseed        = GetBoolArg( "-eb_forcednsseed", EDC_DEFAULT_FORCEDNSSEED );
	listen              = GetBoolArg( "-eb_listen", EDC_DEFAULT_LISTEN );
	listenonion         = GetBoolArg( "-eb_listenonion",EDC_DEFAULT_LISTEN_ONION);
	logips              = GetBoolArg( "-eb_logips", EDC_DEFAULT_LOGIPS );
	logtimemicros       = GetBoolArg( "-eb_logtimemicros", EDC_DEFAULT_LOGTIMEMICROS );
	logtimestamps       = GetBoolArg( "-eb_logtimestamps", EDC_DEFAULT_LOGTIMESTAMPS );
	mempoolreplacement  = GetBoolArg( "-eb_mempoolreplacement", EDC_DEFAULT_ENABLE_REPLACEMENT );
	nodebug             = GetBoolArg( "-eb_nodebug", false );
	printpriority       = GetBoolArg( "-eb_printpriority", EDC_DEFAULT_PRINTPRIORITY );
	printtoconsole      = GetBoolArg( "-eb_printtoconsole", false );
	privdb              = GetBoolArg( "-eb_privdb", EDC_DEFAULT_WALLET_PRIVDB );
	prematurewitness	= GetBoolArg( "-eb_prematurewitness", false );
	proxyrandomize      = GetBoolArg( "-eb_proxyrandomize", EDC_DEFAULT_PROXYRANDOMIZE );
	reindex             = GetBoolArg( "-eb_reindex", false );
	reindex_chainstate  = GetBoolArg( "-eb_reindex-chainstate", false );
	relaypriority       = GetBoolArg( "-eb_relaypriority", EDC_DEFAULT_RELAYPRIORITY );
	rescan              = GetBoolArg( "-eb_rescan", false );
	rest                = GetBoolArg( "-eb_rest", EDC_DEFAULT_REST_ENABLE );
	salvagewallet       = GetBoolArg( "-eb_salvagewallet", false );
	sendfreetransactions= GetBoolArg( "-eb_sendfreetransactions", EDC_DEFAULT_SEND_FREE_TRANSACTIONS );
	server              = GetBoolArg( "-eb_server", false );
	shrinkdebugfile     = GetBoolArg( "-eb_shrinkdebugfile", debug.size() > 0 );
	spendzeroconfchange = GetBoolArg( "-eb_spendzeroconfchange", EDC_DEFAULT_SPEND_ZEROCONF_CHANGE );
	stopafterblockimport= GetBoolArg( "-eb_stopafterblockimport", EDC_DEFAULT_STOPAFTERBLOCKIMPORT );
	testsafemode        = GetBoolArg( "-eb_testsafemode", EDC_DEFAULT_TESTSAFEMODE );
	txindex             = GetBoolArg( "-eb_txindex", EDC_DEFAULT_TXINDEX );
	upgradewallet       = GetBoolArg( "-eb_upgradewallet", false );
	upnp                = GetBoolArg( "-eb_upnp", EDC_DEFAULT_UPNP );
	usehd               = GetBoolArg( "-eb_usehd", EDC_DEFAULT_USE_HD_WALLET );
	usehsm              = GetBoolArg( "-eb_usehsm", true );
	walletbroadcast     = GetBoolArg( "-eb_walletbroadcast", EDC_DEFAULT_WALLETBROADCAST );
	walletprematurewitness
						= GetBoolArg( "-eb_walletprematurewitness", false );
	walletrbf		    = GetBoolArg( "-eb_walletrbf", EDC_DEFAULT_WALLET_RBF);
	whitelistrelay      = GetBoolArg( "-eb_whitelistrelay", EDC_DEFAULT_WHITELISTRELAY );
	whitelistforcerelay = GetBoolArg( "-eb_whitelistforcerelay", EDC_DEFAULT_WHITELISTFORCERELAY );
	zapwallettxes       = GetBoolArg( "-eb_zapwallettxes", false );

	// Int parameters
	banscore            = GetArg( "-eb_banscore", EDC_DEFAULT_BANSCORE_THRESHOLD );
	bantime             = GetArg( "-eb_bantime", EDC_DEFAULT_MISBEHAVING_BANTIME );
	blockmaxsize        = GetArg( "-eb_blockmaxsize", EDC_DEFAULT_BLOCK_MAX_SIZE );
	blockmaxweight      = GetArg( "-eb_blockmaxweight", EDC_DEFAULT_BLOCK_MAX_WEIGHT );
	blockprioritysize   = GetArg( "-eb_blockprioritysize", EDC_DEFAULT_BLOCK_PRIORITY_SIZE );
	blockversion        = GetArg( "-eb_blockversion", 0 );
	bytespersigop       = GetArg( "-eb_bytespersigop", EDC_DEFAULT_BYTES_PER_SIGOP );
	checkblocks         = GetArg( "-eb_checkblocks", EDC_DEFAULT_CHECKBLOCKS );
	checklevel          = GetArg( "-eb_checklevel", EDC_DEFAULT_CHECKLEVEL );
	datacarriersize     = GetArg( "-eb_datacarriersize", EDC_MAX_OP_RETURN_RELAY );
	dbcache             = GetArg( "-eb_dbcache", EDC_DEFAULT_DB_CACHE );
	dblogsize           = GetArg( "-eb_dblogsize", EDC_DEFAULT_WALLET_DBLOGSIZE );
	dropmessagestest    = GetArg( "-eb_dropmessagestest", 0 );
	fuzzmessagestest    = GetArg( "-eb_fuzzmessagestest", 0 );
	hsmkeypool          = GetArg( "-eb_hsmkeypool", EDC_DEFAULT_HSMKEYPOOL_SIZE );
	keypool             = GetArg( "-eb_keypool", EDC_DEFAULT_KEYPOOL_SIZE );
	limitancestorcount  = GetArg( "-eb_limitancestorcount", EDC_DEFAULT_ANCESTOR_LIMIT );
	limitancestorsize   = GetArg( "-eb_limitancestorsize", EDC_DEFAULT_ANCESTOR_SIZE_LIMIT );
	limitdescendantcount= GetArg( "-eb_limitdescendantcount", EDC_DEFAULT_DESCENDANT_LIMIT );
	limitdescendantsize = GetArg( "-eb_limitdescendantsize", EDC_DEFAULT_DESCENDANT_SIZE_LIMIT );
	limitfreerelay      = GetArg( "-eb_limitfreerelay", EDC_DEFAULT_LIMITFREERELAY );
	maxconnections      = GetArg( "-eb_maxconnections", EDC_DEFAULT_MAX_PEER_CONNECTIONS );
	maxmempool          = GetArg( "-eb_maxmempool", EDC_DEFAULT_MAX_MEMPOOL_SIZE );
	maxorphantx         = GetArg( "-eb_maxorphantx", EDC_DEFAULT_MAX_ORPHAN_TRANSACTIONS );
	maxreceivebuffer    = GetArg( "-eb_maxreceivebuffer", EDC_DEFAULT_MAXRECEIVEBUFFER );
	maxsendbuffer       = GetArg( "-eb_maxsendbuffer", EDC_DEFAULT_MAXSENDBUFFER );
	maxsigcachesize     = GetArg( "-eb_maxsigcachesize", EDC_DEFAULT_MAX_SIG_CACHE_SIZE );
	maxtimeadjustment   = GetArg( "-eb_maxtimeadjustment", EDC_DEFAULT_MAX_TIME_ADJUSTMENT );
	maxtipage           = GetArg( "-eb_maxtipage", EDC_DEFAULT_MAX_TIP_AGE );
	maxtxfee            = GetArg( "-eb_maxtxfee", 0 );
	maxuploadtarget     = GetArg( "-eb_maxuploadtarget", EDC_DEFAULT_MAX_UPLOAD_TARGET );
	maxverdepth         = GetArg( "-eb_maxverdepth", EDC_DEFAULT_MAX_VERIFY_DEPTH );
	mempoolexpiry       = GetArg( "-eb_mempoolexpiry", EDC_DEFAULT_MEMPOOL_EXPIRY );
	par                 = GetArg( "-eb_par", EDC_DEFAULT_SCRIPTCHECK_THREADS );
	peerbloomfilters    = GetArg( "-eb_peerbloomfilters", EDC_DEFAULT_PEERBLOOMFILTERS );
	permitbaremultisig  = GetArg( "-eb_permitbaremultisig", EDC_DEFAULT_PERMIT_BAREMULTISIG );
	port                = GetArg( "-eb_port", edcParams(network).GetDefaultPort() );
	promiscuousmempoolflags
						= GetArg( "-eb_prematurewitness", STANDARD_SCRIPT_VERIFY_FLAGS );
	prune               = GetArg( "-eb_prune", 0 );
	rpcport             = GetArg( "-eb_rpcport", BaseParams(network).edcRPCPort() );
	rpcservertimeout    = GetArg( "-eb_rpcservertimeout", EDC_DEFAULT_HTTP_SERVER_TIMEOUT );
	rpcthreads          = GetArg( "-eb_rpcthreads", EDC_DEFAULT_HTTP_THREADS );
	rpcworkqueue        = GetArg( "-eb_rpcworkqueue", EDC_DEFAULT_HTTP_WORKQUEUE );
	sport               = GetArg( "-eb_sport", edcParams(network).GetDefaultSecurePort() );
	timeout             = GetArg( "-eb_timeout", EDC_DEFAULT_CONNECT_TIMEOUT );
	txconfirmtarget     = GetArg( "-eb_txconfirmtarget", EDC_DEFAULT_TX_CONFIRM_TARGET );

	// String parameters
	alertnotify         = GetArg( "-eb_alertnotify", "" );
	blocknotify         = GetArg( "-eb_blocknotify", "" );
	cacert              = GetArg( "-eb_cacert", "" );
	cert                = GetArg( "-eb_cert", "" );
	fallbackfee         = GetArg( "-eb_fallbackfee", "" );
	minrelaytxfee       = GetArg( "-eb_minrelaytxfee", "" );
	mintxfee            = GetArg( "-eb_mintxfee", "" );
	onion               = GetArg( "-eb_onion", "" );
	pid                 = GetArg( "-eb_pid", EQUIBIT_PID_FILENAME );
	paytxfee            = GetArg( "-eb_paytxfee", "" );
	privkey             = GetArg( "-eb_privkey", "" );
	proxy               = GetArg( "-eb_proxy", "" );
	rpccookiefile       = GetArg( "-eb_rpccookiefile", COOKIEAUTH_FILE );
	rpcpassword         = GetArg( "-eb_rpcpassword", "" );
	rpcuser             = GetArg( "-eb_rpcuser", "" );
	torcontrol          = GetArg( "-eb_torcontrol", EDC_DEFAULT_TOR_CONTROL );
	torpassword         = GetArg( "-eb_torpassword", "" );
	wallet              = GetArg( "-eb_wallet", EDC_DEFAULT_WALLET_DAT );
	walletnotify        = GetArg( "-eb_walletnotify", "" );

	// Vector of strings
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_addnode"])
		addnode.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_bind"])
		bind.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_bip9params"])
		bip9params.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_connect"])
		connect.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_debug"])
		debug.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_externalip"])
		externalip.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_loadblock"])
		loadblock.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_onlynet"])
		onlynet.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_rpcallowip"])
		rpcallowip.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_rpcauth"])
		rpcauth.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_rpcbind"])
		rpcbind.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_seednode"])
		seednode.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_uacomment"])
		uacomment.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_whitebind"])
		whitebind.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-eb_whitelist"])
		whitelist.push_back(e);
}

std::string EDCparams::helpMessage(HelpMessageMode mode)
{
    const bool showDebug = GetBoolArg("-eb_help-debug", false );

	////////////////////////////////////////////////////////////////////////
    std::string strUsage = HelpMessageGroup(_("Equibit Options:"));

    strUsage += HelpMessageOpt("-eb_alertnotify=<cmd>", 
		_("Execute command when a relevant alert is received or we see a really long fork (%s in cmd is replaced by message)"));
    strUsage += HelpMessageOpt("-eb_blocknotify=<cmd>", 
		_("Execute command when the best block changes (%s in cmd is replaced by block hash)"));

    if (showDebug)
        strUsage += HelpMessageOpt("-eb_blocksonly", 
			strprintf(_("Whether to operate in a blocks only mode (default: %u)"), EDC_DEFAULT_BLOCKSONLY));
    strUsage += HelpMessageOpt("-eb_checkblocks=<n>", 
		strprintf(_("How many blocks to check at startup (default: %u, 0 = all)"), EDC_DEFAULT_CHECKBLOCKS));
    strUsage += HelpMessageOpt("-eb_checkparams", 
		strprintf(_("Verify all command line options are valid (default: %s)"), "true" ));
    strUsage += HelpMessageOpt("-eb_checklevel=<n>", 
		strprintf(_("How thorough the block verification of -eb_checkblocks is (0-4, default: %u)"), EDC_DEFAULT_CHECKLEVEL));
    strUsage += HelpMessageOpt("-eb_conf=<file>", 
		strprintf(_("Specify configuration file (default: %s)"), EDC_DEFAULT_CONF_FILENAME));
    strUsage += HelpMessageOpt("-eb_datadir=<dir>", 
		_("Specify data directory"));
    strUsage += HelpMessageOpt("-eb_dbcache=<n>", 
		strprintf(_("Set database cache size in megabytes (%d to %d, default: %d)"), EDC_MIN_DB_CACHE, EDC_MAX_DB_CACHE, EDC_DEFAULT_DB_CACHE));
	if(showDebug)
	    strUsage += HelpMessageOpt("-eb_feefilter", 
			strprintf(_("Tell other nodes to filter invs to us by our mempool min fee (default: %u)"), EDC_DEFAULT_FEEFILTER));
    strUsage += HelpMessageOpt("-eb_loadblock=<file>", 
		_("Imports blocks from external blk000??.dat file on startup"));
    strUsage += HelpMessageOpt("-eb_maxorphantx=<n>", 
		strprintf(_("Keep at most <n> unconnectable transactions in memory (default: %u)"), EDC_DEFAULT_MAX_ORPHAN_TRANSACTIONS));
    strUsage += HelpMessageOpt("-eb_maxmempool=<n>", 
		strprintf(_("Keep the transaction memory pool below <n> megabytes (default: %u)"), EDC_DEFAULT_MAX_MEMPOOL_SIZE));
    strUsage += HelpMessageOpt("-eb_mempoolexpiry=<n>", 
		strprintf(_("Do not keep transactions in the mempool longer than <n> hours (default: %u)"), EDC_DEFAULT_MEMPOOL_EXPIRY));
    strUsage += HelpMessageOpt("-eb_par=<n>", 
		strprintf(_("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)"),
        -GetNumCores(), EDC_MAX_SCRIPTCHECK_THREADS, EDC_DEFAULT_SCRIPTCHECK_THREADS));
#ifndef WIN32
    strUsage += HelpMessageOpt("-eb_pid=<file>", 
		strprintf(_("Specify pid file (default: %s)"), EQUIBIT_PID_FILENAME));
#endif
	strUsage += HelpMessageOpt("-eb_promiscuousmempoolflags=<n>",
		strprintf(_("Script verification options (default: %u)"), STANDARD_SCRIPT_VERIFY_FLAGS ));
    strUsage += HelpMessageOpt("-eb_prune=<n>", 
		strprintf(_("Reduce storage requirements by pruning (deleting) old blocks. This mode is incompatible with -eb_txindex and -eb_rescan. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, >%u = target size in MiB to use for block files)"), EDC_MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
	strUsage += HelpMessageOpt("-eb_reindex-chainstate", _("Rebuild chain state from the currently indexed blocks"));
	strUsage += HelpMessageOpt("-eb_reindex", _("Rebuild chain state and block index from the blk*.dat files on disk"));

    strUsage += HelpMessageOpt("-eb_txindex", 
		strprintf(_("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)"), EDC_DEFAULT_TXINDEX));

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Connection options:"));

    strUsage += HelpMessageOpt("-eb_addnode=<ip>", 
		_("Add a node to connect to and attempt to keep the connection open"));
    strUsage += HelpMessageOpt("-eb_banscore=<n>", 
		strprintf(_("Threshold for disconnecting misbehaving peers (default: %u)"), EDC_DEFAULT_BANSCORE_THRESHOLD));
    strUsage += HelpMessageOpt("-eb_bantime=<n>", 
		strprintf(_("Number of seconds to keep misbehaving peers from reconnecting (default: %u)"), EDC_DEFAULT_MISBEHAVING_BANTIME));
    strUsage += HelpMessageOpt("-eb_bind=<addr>", 
		_("Bind to given address and always listen on it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-eb_connect=<ip>", 
		_("Connect only to the specified node(s)"));
    strUsage += HelpMessageOpt("-eb_discover", 
		_("Discover own IP addresses (default: 1 when listening and no -eb_externalip or -eb_proxy)"));
    strUsage += HelpMessageOpt("-eb_dns", _("Allow DNS lookups for -eb_addnode, "
		"-eb_seednode and -eb_connect") + " " + strprintf(_("(default: %u)"), true));
    strUsage += HelpMessageOpt("-eb_dnsseed", 
		_("Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -eb_connect)"));
    strUsage += HelpMessageOpt("-eb_externalip=<ip>", 
		_("Specify your own public address"));
    strUsage += HelpMessageOpt("-eb_forcednsseed", 
		strprintf(_("Always query for peer addresses via DNS lookup (default: %u)"), EDC_DEFAULT_FORCEDNSSEED));
    strUsage += HelpMessageOpt("-eb_listen", 
		_("Accept connections from outside (default: 1 if no -eb_proxy or -eb_connect)"));
    strUsage += HelpMessageOpt("-eb_listenonion", 
		strprintf(_("Automatically create Tor hidden service (default: %d)"), EDC_DEFAULT_LISTEN_ONION));
    strUsage += HelpMessageOpt("-eb_maxconnections=<n>", 
		strprintf(_("Maintain at most <n> connections to peers (default: %u)"), EDC_DEFAULT_MAX_PEER_CONNECTIONS));
    strUsage += HelpMessageOpt("-eb_maxreceivebuffer=<n>", 
		strprintf(_("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)"), EDC_DEFAULT_MAXRECEIVEBUFFER));
    strUsage += HelpMessageOpt("-eb_maxsendbuffer=<n>", 
		strprintf(_("Maximum per-connection send buffer, <n>*1000 bytes (default: %u)"), EDC_DEFAULT_MAXSENDBUFFER));
    strUsage += HelpMessageOpt("-eb_maxtimeadjustment", 
		strprintf(_("Maximum allowed median peer time offset adjustment. Local perspective of time may be influenced by peers forward or backward by this amount. (default: %u seconds)"), EDC_DEFAULT_MAX_TIME_ADJUSTMENT));
    strUsage += HelpMessageOpt("-eb_onion=<ip:port>", 
		strprintf(_("Use separate SOCKS5 proxy to reach peers via Tor hidden services (default: %s)"), "-eb_proxy"));
    strUsage += HelpMessageOpt("-eb_onlynet=<net>", 
		_("Only connect to nodes in network <net> (ipv4, ipv6 or onion)"));
    strUsage += HelpMessageOpt("-eb_permitbaremultisig", 
		strprintf(_("Relay non-P2SH multisig (default: %u)"), EDC_DEFAULT_PERMIT_BAREMULTISIG));
    strUsage += HelpMessageOpt("-eb_peerbloomfilters", 
		strprintf(_("Support filtering of blocks and transaction with bloom filters (default: %u)"), EDC_DEFAULT_PEERBLOOMFILTERS));
    strUsage += HelpMessageOpt("-eb_port=<port>", 
		strprintf(_("Listen for connections on <port> (default: %u or testnet: %u)"), edcParams(CBaseChainParams::MAIN).GetDefaultPort(), edcParams(CBaseChainParams::TESTNET).GetDefaultPort()));
    strUsage += HelpMessageOpt("-eb_proxy=<ip:port>", 
		_("Connect through SOCKS5 proxy"));
    strUsage += HelpMessageOpt("-eb_proxyrandomize", 
		strprintf(_("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)"), EDC_DEFAULT_PROXYRANDOMIZE));
    strUsage += HelpMessageOpt("-eb_seednode=<ip>", 
		_("Connect to a node to retrieve peer addresses, and disconnect"));
    strUsage += HelpMessageOpt("-eb_sport=<port>", 
		strprintf(_("Listen for secure connections on <sport> (default: %u or testnet: %u)"), edcParams(CBaseChainParams::MAIN).GetDefaultSecurePort(), edcParams(CBaseChainParams::TESTNET).GetDefaultSecurePort()));
    strUsage += HelpMessageOpt("-eb_timeout=<n>", 
		strprintf(_("Specify connection timeout in milliseconds (minimum: 1, default: %d)"), EDC_DEFAULT_CONNECT_TIMEOUT));
    strUsage += HelpMessageOpt("-eb_torcontrol=<ip>:<port>", 
		strprintf(_("Tor control port to use if onion listening enabled (default: %s)"), EDC_DEFAULT_TOR_CONTROL));
    strUsage += HelpMessageOpt("-eb_torpassword=<pass>", 
		_("Tor control port password (default: empty)"));
#ifdef USE_UPNP
#if USE_UPNP
    strUsage += HelpMessageOpt("-eb_upnp", 
		_("Use UPnP to map the listening port (default: 1 when listening and no -eb_proxy)"));
#else
    strUsage += HelpMessageOpt("-eb_upnp", 
		strprintf(_("Use UPnP to map the listening port (default: %u)"), 0));
#endif
#endif
	strUsage += HelpMessageOpt("-eb_usehsm",
		_("Use HSM for security operations (default: true)"));
    strUsage += HelpMessageOpt("-eb_whitebind=<addr>", 
		_("Bind to given address and whitelist peers connecting to it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-eb_whitelist=<netmask>", 
		_("Whitelist peers connecting from the given netmask or IP address. Can be specified multiple times.") +
        " " + _("Whitelisted peers cannot be DoS banned and their transactions are always relayed, even if they are already in the mempool, useful e.g. for a gateway"));
    strUsage += HelpMessageOpt("-eb_whitelistrelay", 
		strprintf(_("Accept relayed transactions received from whitelisted peers even when not relaying transactions (default: %d)"), EDC_DEFAULT_WHITELISTRELAY));
    strUsage += HelpMessageOpt("-eb_whitelistforcerelay", 
		strprintf(_("Force relay of transactions from whitelisted peers even if they violate local relay policy (default: %d)"), EDC_DEFAULT_WHITELISTFORCERELAY));
    strUsage += HelpMessageOpt("-eb_maxuploadtarget=<n>", 
		strprintf(_("Tries to keep outbound traffic under the given target (in MiB per 24h), 0 = no limit (default: %d)"), EDC_DEFAULT_MAX_UPLOAD_TARGET));

#ifdef ENABLE_WALLET
    strUsage += CEDCWallet::GetWalletHelpString(showDebug);
#endif

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Debugging/Testing options:"));

    strUsage += HelpMessageOpt("-eb_uacomment=<cmt>", 
		_("Append comment to the user agent string"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-eb_checkblockindex", 
			strprintf("Do a full consistency check for mapBlockIndex, setBlockIndexCandidates, chainActive and mapBlocksUnlinked occasionally. Also sets -eb_checkmempool (default: %u)", edcParams(CBaseChainParams::MAIN).DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-eb_checkmempool=<n>", 
			strprintf("Run checks every <n> transactions (default: %u)", edcParams(CBaseChainParams::MAIN).DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-eb_checkpoints", 
			strprintf("Disable expensive verification for known chain history (default: %u)", EDC_DEFAULT_CHECKPOINTS_ENABLED));
        strUsage += HelpMessageOpt("-eb_disablesafemode", 
			strprintf("Disable safemode, override a real safe mode event (default: %u)", EDC_DEFAULT_DISABLE_SAFEMODE));
        strUsage += HelpMessageOpt("-eb_testsafemode", 
			strprintf("Force safe mode (default: %u)", EDC_DEFAULT_TESTSAFEMODE));
        strUsage += HelpMessageOpt("-eb_dropmessagestest=<n>", "Randomly drop 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-eb_fuzzmessagestest=<n>", "Randomly fuzz 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-eb_stopafterblockimport", 
			strprintf("Stop running after importing blocks from disk (default: %u)", EDC_DEFAULT_STOPAFTERBLOCKIMPORT));
        strUsage += HelpMessageOpt("-eb_limitancestorcount=<n>", 
			strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)", EDC_DEFAULT_ANCESTOR_LIMIT));
        strUsage += HelpMessageOpt("-eb_limitancestorsize=<n>", 
			strprintf("Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)", EDC_DEFAULT_ANCESTOR_SIZE_LIMIT));
        strUsage += HelpMessageOpt("-eb_limitdescendantcount=<n>", 
			strprintf("Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)", EDC_DEFAULT_DESCENDANT_LIMIT));
        strUsage += HelpMessageOpt("-eb_limitdescendantsize=<n>", 
			strprintf("Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).", EDC_DEFAULT_DESCENDANT_SIZE_LIMIT));
        strUsage += HelpMessageOpt("-eb_bip9params=deployment:start:end", "Use given start/end times for specified BIP9 deployment (regtest-only)");
    }
	std::string debugCategories = "addrman, alert, bench, coindb, db, http, libevent, lock, mempool, mempoolrej, net, proxy, prune, rand, reindex, rpc, selectcoins, tor, zmq"; // Don't translate these and qt below
    if (mode == HMM_BITCOIN_QT)
        debugCategories += ", qt";
    strUsage += HelpMessageOpt("-eb_debug=<category>", 
		strprintf(_("Output debugging information (default: %u, supplying <category> is optional)"), 0) + ". " +
        _("If <category> is not supplied or if <category> = 1, output all debugging information.") + _("<category> can be:") + " " + debugCategories + ".");
    if (showDebug)
        strUsage += HelpMessageOpt("-eb_nodebug", "Turn off debugging messages, same as -eb_debug=0");
	strUsage += HelpMessageOpt("-eb_help-debug", _("Show all debugging options (usage: -eb_help -eb_help-debug)"));
	strUsage += HelpMessageOpt("-eb_logips", 
		strprintf(_("Include IP addresses in debug output (default: %u)"), EDC_DEFAULT_LOGIPS));
    strUsage += HelpMessageOpt("-eb_logtimestamps", 
		strprintf(_("Prepend debug output with timestamp (default: %u)"), EDC_DEFAULT_LOGTIMESTAMPS));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-eb_logtimemicros", 
			strprintf("Add microsecond precision to debug timestamps (default: %u)", EDC_DEFAULT_LOGTIMEMICROS));
        strUsage += HelpMessageOpt("-eb_limitfreerelay=<n>", 
			strprintf("Continuously rate-limit free transactions to <n>*1000 bytes per minute (default: %u)", EDC_DEFAULT_LIMITFREERELAY));
        strUsage += HelpMessageOpt("-eb_relaypriority", 
			strprintf("Require high priority for relaying free or low-fee transactions (default: %u)", EDC_DEFAULT_RELAYPRIORITY));
        strUsage += HelpMessageOpt("-eb_maxsigcachesize=<n>", 
			strprintf("Limit size of signature cache to <n> MiB (default: %u)", EDC_DEFAULT_MAX_SIG_CACHE_SIZE));
        strUsage += HelpMessageOpt("-eb_maxtipage=<n>", 
			strprintf("Maximum tip age in seconds to consider node in initial block download (default: %u)", EDC_DEFAULT_MAX_TIP_AGE));
    }
    strUsage += HelpMessageOpt("-eb_minrelaytxfee=<amt>", 
		strprintf(_("Fees (in %s/kB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)"),
        CURRENCY_UNIT, FormatMoney(EDC_DEFAULT_MIN_RELAY_TX_FEE)));
    strUsage += HelpMessageOpt("-eb_maxtxfee=<amt>", 
		strprintf(_("Maximum total fees (in %s) to use in a single wallet transaction or raw transaction; setting this too low may abort large transactions (default: %s)"),
        CURRENCY_UNIT, FormatMoney(EDC_DEFAULT_TRANSACTION_MAXFEE)));
    strUsage += HelpMessageOpt("-eb_printtoconsole", _("Send trace/debug info to console instead of debug.log file"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-eb_printpriority", 
			strprintf("Log transaction priority and fee per kB when mining blocks (default: %u)", EDC_DEFAULT_PRINTPRIORITY));
    }
    strUsage += HelpMessageOpt("-eb_shrinkdebugfile", _("Shrink debug.log file on client startup (default: 1 when no -eb_debug)"));

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Chain selection options:"));
    strUsage += HelpMessageOpt("-eb_regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                               "This is intended for regression testing tools and app development.");
    strUsage += HelpMessageOpt("-eb_testnet", _("Use the test chain"));

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Node relay options:"));
    if (showDebug)
        strUsage += HelpMessageOpt("-eb_acceptnonstdtxn", 
			strprintf("Relay and mine \"non-standard\" transactions (%sdefault: %u)", "testnet/regtest only; ", !edcParams(CBaseChainParams::TESTNET).RequireStandard()));
    strUsage += HelpMessageOpt("-eb_bytespersigop", 
		strprintf(_("Equivalent bytes per sigop in transactions we relay and mining (default: %u)"), EDC_DEFAULT_BYTES_PER_SIGOP));
    strUsage += HelpMessageOpt("-eb_cacert=<CA certificate file>", _("Name of the CA certificate file"));
    strUsage += HelpMessageOpt("-eb_cert=<certificate file>", _("Name of the certificate file"));
    strUsage += HelpMessageOpt("-eb_datacarrier", 
		strprintf(_("Relay and mine data carrier transactions (default: %u)"), EDC_DEFAULT_ACCEPT_DATACARRIER));
    strUsage += HelpMessageOpt("-eb_datacarriersize", 
		strprintf(_("Maximum size of data in data carrier transactions we relay and mine (default: %u)"), EDC_MAX_OP_RETURN_RELAY));
	strUsage += HelpMessageOpt("-eb_maxverdepth",
		strprintf(_("Maximum CA chain depth (default: %u)"), EDC_DEFAULT_MAX_VERIFY_DEPTH));
    strUsage += HelpMessageOpt("-eb_mempoolreplacement", 
		strprintf(_("Enable transaction replacement in the memory pool (default: %u)"), EDC_DEFAULT_ENABLE_REPLACEMENT));
    strUsage += HelpMessageOpt("-eb_privkey=<private key file>", _("Name of the private key file. If specified, then at start up, the pass phrase will be requested."));

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Block creation options:"));
    strUsage += HelpMessageOpt("-eb_blockmaxweight=<n>", 
		strprintf(_("Set maximum BIP141 block weight in bytes (default: %d)"), EDC_DEFAULT_BLOCK_MAX_WEIGHT));
    strUsage += HelpMessageOpt("-eb_blockmaxsize=<n>", 
		strprintf(_("Set maximum block size in bytes (default: %d)"), EDC_DEFAULT_BLOCK_MAX_SIZE));
    strUsage += HelpMessageOpt("-eb_blockprioritysize=<n>", 
		strprintf(_("Set maximum size of high-priority/low-fee transactions in bytes (default: %d)"), EDC_DEFAULT_BLOCK_PRIORITY_SIZE));
    if (showDebug)
        strUsage += HelpMessageOpt("-eb_blockversion=<n>", "Override block version to test forking scenarios");


	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit RPC server options:"));

    strUsage += HelpMessageOpt("-eb_rest", 
		strprintf(_("Accept public REST requests (default: %u)"), EDC_DEFAULT_REST_ENABLE));
    strUsage += HelpMessageOpt("-eb_rpcbind=<addr>", 
		_("Bind to given address to listen for JSON-RPC connections. Use [host]:port notation for IPv6. This option can be specified multiple times (default: bind to all interfaces)"));
    strUsage += HelpMessageOpt("-eb_rpccookiefile=<loc>", 
		_("Location of the auth cookie (default: data dir)"));
    strUsage += HelpMessageOpt("-eb_rpcuser=<user>", 
		_("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-eb_rpcpassword=<pw>", 
		_("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-eb_rpcauth=<userpw>", 
		_("Username and hashed password for JSON-RPC connections. The field <userpw> comes in the format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in share/rpcuser. This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-eb_rpcport=<port>", 
		strprintf(_("Listen for JSON-RPC connections on <port> (default: %u or testnet: %u)"), BaseParams(CBaseChainParams::MAIN).edcRPCPort(), BaseParams(CBaseChainParams::TESTNET).edcRPCPort()));
    strUsage += HelpMessageOpt("-eb_rpcallowip=<ip>", 
		_("Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-eb_rpcthreads=<n>", 
		strprintf(_("Set the number of threads to service RPC calls (default: %d)"), EDC_DEFAULT_HTTP_THREADS));
    if (showDebug) 
	{
        strUsage += HelpMessageOpt("-eb_rpcworkqueue=<n>", 
			strprintf("Set the depth of the work queue to service RPC calls (default: %d)", EDC_DEFAULT_HTTP_WORKQUEUE));
        strUsage += HelpMessageOpt("-eb_rpcservertimeout=<n>", 
			strprintf("Timeout during HTTP requests (default: %d)", EDC_DEFAULT_HTTP_SERVER_TIMEOUT));
    }
    strUsage += HelpMessageOpt("-eb_server", _("Accept command line and JSON-RPC commands"));

    return strUsage;
}


EDCparams & EDCparams::singleton()
{
	static EDCparams theOneAndOnly;

	return theOneAndOnly;
}


bool EDCparams::validate() 
{
	if (!boost::filesystem::is_directory(edcGetDataDir(false)))
    {
		fprintf(stderr, "Error: Specified data directory \"%s\" does not "
			"exist.\n", datadir.c_str() );
        return false;
    }
	if( configFileReadFailed )
		return false;

    // Check for -eb_testnet or -eb_regtest parameter (edcParams() calls are 
    // only valid after this clause)
    if (testnet && regtest)
	{
        fprintf( stderr, "Error: Invalid combination of -eb_regtest and -eb_testnet.");
		return false;
	}

    // when specifying an explicit binding address, you want to listen on it
    // even when -eb_connect or -eb_proxy is specified
    if (bind.size() > 0) 
	{
		if( mapArgs.count( "-eb_listen" ) == 0 )
		{
        	listen = true;
	        edcLogPrintf("%s: parameter interaction: -eb_bind set -> setting -eb_listen=1\n", __func__);
		}
    }
    if (whitebind.size() > 0) 
	{
		if( mapArgs.count( "-eb_listen" ) == 0 )
		{
        	listen = true;
	        edcLogPrintf("%s: parameter interaction: -eb_whitebind set -> setting -eb_listen=1\n", __func__);
		}
    }

    if ( connect.size() > 0 ) 
	{
        // when only connecting to trusted nodes, do not seed via DNS, or 
		// listen by default
		if( mapArgs.count( "-eb_dnsseed" ) == 0 )
		{
        	dnsseed = false;
	        edcLogPrintf("%s: parameter interaction: -eb_dbconnect set -> setting -eb_dbdnsseed=false\n", __func__);
		}
		if( mapArgs.count( "-eb_listen" ) == 0 )
		{
        	listen = false;
        	edcLogPrintf("%s: parameter interaction: -eb_dbconnect set -> setting -eb_dblisten=0\n", __func__);
		}
    }

    if (proxy.size() > 0 ) 
	{
        // to protect privacy, do not listen by default if a default proxy 
		// server is specified
		if( mapArgs.count( "-eb_listen" ) == 0 )
		{
        	listen = false;
        	edcLogPrintf("%s: parameter interaction: -eb_proxy set -> setting -eb_listen=0\n", __func__);
		}

        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -eb_listen=1
        // to listen locally, so don't rely on this happening through -eb_listen below.
		if( mapArgs.count("-eb_upnp") == 0 )
		{
			upnp = false;
        	edcLogPrintf("%s: parameter interaction: -eb_proxy set -> setting -eb_upnp=0\n", __func__);
		}

        // to protect privacy, do not discover addresses by default
		if( mapArgs.count( "-eb_discover" ) == 0 )
		{
        	discover = false;
        	edcLogPrintf("%s: parameter interaction: -eb_proxy set -> setting -eb_discover=0\n", __func__);
		}
    }

    if (!listen) 
	{
        // do not map ports or try to retrieve public IP when not listening (pointless)
		if( mapArgs.count("-eb_upnp") == 0 )
		{
			upnp = false;
        	edcLogPrintf("%s: parameter interaction: -eb_listen=0 -> setting -eb_upnp=0\n", __func__);
		}

		if( mapArgs.count( "-eb_discover" ) == 0 )
		{
        	discover = false;
        	edcLogPrintf("%s: parameter interaction: -eb_listen=0 -> setting -eb_discover=0\n", __func__);
		}

		if( mapArgs.count( "-eb_listenonion" ) == 0 )
		{
        	listenonion = false;
        	edcLogPrintf("%s: parameter interaction: -eb_listen=0 -> setting -eb_listenonion=0\n", __func__);
		}
    }

    if (externalip.size() > 0 )
	{
        // if an explicit public IP is specified, do not try to find others
		if( mapArgs.count( "-eb_discover" ) == 0 )
		{
	        discover = false;
   	    	edcLogPrintf("%s: parameter interaction: -eb_externalip set -> setting -eb_discover=0\n", __func__);
		}
    }

    if (salvagewallet) 
	{
        // Rewrite just private keys: rescan to find transactions
		if( mapArgs.count( "-eb_rescan" ) == 0 )
		{
        	rescan = true;
	        edcLogPrintf("%s: parameter interaction: -eb_salvagewallet=1 -> setting -eb_rescan=1\n", __func__);
		}
    }

    // -eb_zapwallettx implies a rescan
    if (zapwallettxes) 
	{
		if( mapArgs.count( "-eb_rescan" ) == 0 )
		{
        	rescan = true;
	        edcLogPrintf("%s: parameter interaction: -eb_zapwallettxes=<mode> -> setting -eb_rescan=1\n", __func__);
		}
    }

    // disable walletbroadcast and whitelistrelay in blocksonly mode
    if (blocksonly) 
	{
		if( mapArgs.count( "-eb_whitelistrelay" ) == 0 )
		{
        	whitelistrelay = false;
	        edcLogPrintf("%s: parameter interaction: -eb_blocksonly=1 -> setting -eb_whitelistrelay=0\n", __func__);
		}
		// walletbroadcast is disabled in CEDCWallet::ParameterInteraction()
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place.
    if (whitelistforcerelay) 
	{
		if( mapArgs.count( "-eb_whitelistrelay" ) == 0 )
		{
        	whitelistrelay = true;
	        edcLogPrintf("%s: parameter interaction: -eb_whitelistforcerelay=1 -> setting -eb_whitelistrelay=1\n", __func__);
		}
    }

	if (!GetBoolArg( "-sysperms", false))
    {
        umask(077);
    }

    // if using block pruning, then disallow txindex
    if ( prune ) 
	{
        if (txindex)
            return edcInitError(_("Prune mode is incompatible with -eb_txindex."));
    }

    // mempool limits
    int64_t nMempoolSizeMax = maxmempool * 1000000;
    int64_t nMempoolSizeMin = limitdescendantsize * 1000 * 40;
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return edcInitError(strprintf(_("-eb_maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));

    // block pruning; get the amount of disk space (in MiB) to allot for 
	// block & undo files
    int64_t nSignedPruneTarget = prune * 1024 * 1024;
    if (nSignedPruneTarget < 0) 
	{
        return edcInitError(_("Prune cannot be configured with a negative "
			"value."));
    }

	EDCapp & theApp = EDCapp::singleton();

    theApp.pruneTarget( (uint64_t) nSignedPruneTarget );
    if ( theApp.pruneTarget())
    {
        if ( theApp.pruneTarget() < EDC_MIN_DISK_SPACE_FOR_BLOCK_FILES)
        {
            return edcInitError(strprintf(_("Prune configured below the "
				"minimum of %d MiB.  Please use a higher number."), 
				EDC_MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
        }
        edcLogPrintf("Prune configured to target %uMiB on disk for block and "
			"undo files.\n", theApp.pruneTarget() / 1024 / 1024);
        theApp.pruneMode( true );
    }

	return true;
}

inline const char * toString( bool b )	{ return b?"true":"false"; }

void printStrVec( const char * n, const std::vector<std::string> & sv )
{
	auto i = sv.begin();
	auto e = sv.end();

	edcLogPrintf( "%s {", n );
	bool first = true;

	while( i != e )
	{
		if(!first)
			edcLogPrintf( "," );
		else
			first = false;

        edcLogPrintf( "\"%s\"", i->c_str() );

		++i;
	}
	edcLogPrintf( "}\n" );
}

void EDCparams::dumpToLog() const
{
	edcLogPrintf( ">>>>>>>>>>>>>>>>>> Equibit Options <<<<<<<<<<<<<<<<<<\n" );

	edcLogPrintf( "eb_acceptnonstdtxn        %s\n", toString(acceptnonstdtxn) );
	printStrVec( "eb_addnode               ", addnode );
	edcLogPrintf( "eb_alertnotify            \"%s\"\n", alertnotify.c_str() );

	edcLogPrintf( "eb_banscore               %lld\n", banscore );
	edcLogPrintf( "eb_bantime                %lld\n", bantime );
	printStrVec( "eb_bind                  ", bind );
	printStrVec( "eb_bip9params            ", bip9params );
	edcLogPrintf( "eb_blockmaxweight         %lld\n", blockmaxweight );
	edcLogPrintf( "eb_blockmaxsize           %lld\n", blockmaxsize );
	edcLogPrintf( "eb_blocknotify            \"%s\"\n", blocknotify.c_str() );
	edcLogPrintf( "eb_blockprioritysize      %lld\n", blockprioritysize );
	edcLogPrintf( "eb_blocksonly             %s\n", toString(blocksonly) );
	edcLogPrintf( "eb_blockversion           %lld\n", blockversion );
	edcLogPrintf( "eb_bytespersigop          %lld\n", bytespersigop );

	edcLogPrintf( "eb_cacert                 %s\n", cacert.c_str() );
	edcLogPrintf( "eb_cert                   %s\n", cert.c_str() );
	edcLogPrintf( "eb_checkblockindex        %s\n", toString(checkblockindex) );
	edcLogPrintf( "eb_checkblocks            %lld\n", checkblocks );
	edcLogPrintf( "eb_checklevel             %lld\n", checklevel );
	edcLogPrintf( "eb_checkmempool           %s\n", toString(checkmempool) );
	edcLogPrintf( "eb_checkpoints            %s\n", toString(checkpoints) );
	edcLogPrintf( "eb_conf                   \"%s\"\n", conf.c_str() );
	printStrVec( "eb_connect               ", connect );

	edcLogPrintf( "eb_datacarrier            %s\n", toString(datacarrier) );
	edcLogPrintf( "eb_datacarriersize        %lld\n", datacarriersize );
	edcLogPrintf( "eb_datadir                \"%s\"\n", datadir.c_str() );
	edcLogPrintf( "eb_dbcache                %lld\n", dbcache );
	edcLogPrintf( "eb_dblogsize              %lld\n", dblogsize );
	printStrVec( "eb_debug                 ", debug );
	edcLogPrintf( "eb_disablesafemode        %s\n", toString(disablesafemode) );
	edcLogPrintf( "eb_disablewallet          %s\n", toString(disablewallet) );
	edcLogPrintf( "eb_discover               %s\n", toString(discover) );
	edcLogPrintf( "eb_dns                    %s\n", toString(dns) );
	edcLogPrintf( "eb_dnsseed                %s\n", toString(dnsseed) );
	edcLogPrintf( "eb_dropmessagestest       %lld\n", dropmessagestest );

	printStrVec( "eb_externalip            ", externalip );

	edcLogPrintf( "eb_fallbackfee            \"%s\"\n", fallbackfee.c_str() );
	edcLogPrintf( "eb_feefilter              %s\n", toString(feefilter) );
	edcLogPrintf( "eb_flushwallet            %s\n", toString(flushwallet) );
	edcLogPrintf( "eb_forcednsseed           %s\n", toString(forcednsseed) );
	edcLogPrintf( "eb_fuzzmessagestest       %lld\n", fuzzmessagestest );

	edcLogPrintf( "eb_hsmkeypool             %lld\n", hsmkeypool );

	edcLogPrintf( "eb_keypool                %lld\n", keypool );

	edcLogPrintf( "eb_limitancestorcount     %lld\n", limitancestorcount );
	edcLogPrintf( "eb_limitancestorsize      %lld\n", limitancestorsize );
	edcLogPrintf( "eb_limitdescendantcount   %lld\n", limitdescendantcount );
	edcLogPrintf( "eb_limitdescendantsize    %lld\n", limitdescendantsize );
	edcLogPrintf( "eb_limitfreerelay         %lld\n", limitfreerelay );
	edcLogPrintf( "eb_listen                 %s\n", toString(listen) );
	edcLogPrintf( "eb_listenonion            %s\n", toString(listenonion) );
	printStrVec( "eb_loadblock             ", loadblock );
	edcLogPrintf( "eb_logips                 %s\n", toString(logips) );
	edcLogPrintf( "eb_logtimemicros          %s\n", toString(logtimemicros) );
	edcLogPrintf( "eb_logtimestamps          %s\n", toString(logtimestamps) );

	edcLogPrintf( "eb_maxconnections         %lld\n", maxconnections );
	edcLogPrintf( "eb_maxmempool             %lld\n", maxmempool );
	edcLogPrintf( "eb_maxorphantx            %lld\n", maxorphantx );
	edcLogPrintf( "eb_maxreceivebuffer       %lld\n", maxreceivebuffer );
	edcLogPrintf( "eb_maxsendbuffer          %lld\n", maxsendbuffer );
	edcLogPrintf( "eb_maxsigcachesize        %lld\n", maxsigcachesize );
	edcLogPrintf( "eb_maxtimeadjustment      %lld\n", maxtimeadjustment );
	edcLogPrintf( "eb_maxtipage              %lld\n", maxtipage );
	edcLogPrintf( "eb_maxtxfee               %lld\n", maxtxfee );
	edcLogPrintf( "eb_maxuploadtarget        %lld\n", maxuploadtarget );
	edcLogPrintf( "eb_maxverdepth            %lld\n", maxverdepth );
	edcLogPrintf( "eb_mempoolexpiry          %lld\n", mempoolexpiry );
	edcLogPrintf( "eb_mempoolreplacement     %s\n", toString(mempoolreplacement) );
	edcLogPrintf( "eb_minrelaytxfee          \"%s\"\n", minrelaytxfee.c_str() );
	edcLogPrintf( "eb_mintxfee               \"%s\"\n", mintxfee.c_str() );

	edcLogPrintf( "eb_nodebug                %s\n", toString(nodebug) );

	edcLogPrintf( "eb_onion                  \"%s\"\n", onion.c_str() );
	printStrVec( "eb_onlynet               ", onlynet );

	edcLogPrintf( "eb_par                    %lld\n", par );
	edcLogPrintf( "eb_paytxfee               \"%s\"\n", paytxfee.c_str() );
	edcLogPrintf( "eb_peerbloomfilters       %s\n", toString(peerbloomfilters) );
	edcLogPrintf( "eb_permitbaremultisig     %s\n", toString(permitbaremultisig) );
	edcLogPrintf( "eb_pid                    \"%s\"\n", pid.c_str() );
	edcLogPrintf( "eb_port                   %lld\n", port );
	edcLogPrintf( "eb_printpriority          %s\n", toString(printpriority) );
	edcLogPrintf( "eb_printtoconsole         %s\n", toString(printtoconsole) );
	edcLogPrintf( "eb_privdb                 %s\n", toString(privdb) );
	edcLogPrintf( "eb_privkey                %s\n", privkey.c_str() );
	edcLogPrintf( "eb_proxy                  \"%s\"\n", proxy.c_str() );
	edcLogPrintf( "eb_proxyrandomize         %s\n", toString(proxyrandomize) );
	edcLogPrintf( "eb_prune                  %lld\n", prune );

	edcLogPrintf( "eb_regtest                %s\n", toString(regtest) );
	edcLogPrintf( "eb_reindex                %s\n", toString(reindex) );
	edcLogPrintf( "eb_reindex-chainstate     %s\n", toString(reindex_chainstate) );
	edcLogPrintf( "eb_relaypriority          %s\n", toString(relaypriority) );
	edcLogPrintf( "eb_rescan                 %s\n", toString(rescan) );
	edcLogPrintf( "eb_rest                   %s\n", toString(rest) );
	printStrVec( "eb_rpcallowip            ", rpcallowip );
	printStrVec( "eb_rpcauth               ", rpcauth );
	printStrVec( "eb_rpcbind               ", rpcbind );
	edcLogPrintf( "eb_rpccookiefile          \"%s\"\n", rpccookiefile.c_str() );
	edcLogPrintf( "eb_rpcpassword            \"%s\"\n", rpcpassword.c_str() );
	edcLogPrintf( "eb_rpcport                %lld\n", rpcport );
	edcLogPrintf( "eb_rpcservertimeout       %lld\n", rpcservertimeout );
	edcLogPrintf( "eb_rpcthreads             %lld\n", rpcthreads );
	edcLogPrintf( "eb_rpcuser                \"%s\"\n", rpcuser.c_str() );
	edcLogPrintf( "eb_rpcworkqueue           %lld\n", rpcworkqueue );

	edcLogPrintf( "eb_salvagewallet          %s\n", toString( salvagewallet) );
	printStrVec( "eb_seednode              ", seednode );
	edcLogPrintf( "eb_sendfreetransactions   %s\n", toString(sendfreetransactions) );
	edcLogPrintf( "eb_server                 %s\n", toString(server) );
	edcLogPrintf( "eb_shrinkdebugfile        %s\n", toString( shrinkdebugfile) );
	edcLogPrintf( "eb_spendzeroconfchange    %s\n", toString( spendzeroconfchange) );
	edcLogPrintf( "eb_sport                  %lld\n", sport );
	edcLogPrintf( "eb_stopafterblockimport   %s\n", toString( stopafterblockimport));

	edcLogPrintf( "eb_testnet                %s\n", toString(testnet) );
	edcLogPrintf( "eb_testsafemode           %s\n", toString( testsafemode) );
	edcLogPrintf( "eb_timeout                %lld\n", timeout );
	edcLogPrintf( "eb_torcontrol             \"%s\"\n", torcontrol.c_str() );
	edcLogPrintf( "eb_torpassword            \"%s\"\n", torpassword.c_str() );
	edcLogPrintf( "eb_txconfirmtarget        %lld\n", txconfirmtarget );
	edcLogPrintf( "eb_txindex                %s\n", toString( txindex) );

	printStrVec( "eb_uacomment             ", uacomment );
	edcLogPrintf( "eb_upgradewallet          %s\n", toString( upgradewallet) );
	edcLogPrintf( "eb_upnp                   %s\n", toString( upnp) );
	edcLogPrintf( "eb_usehd                  %s\n", toString( usehd) );
	edcLogPrintf( "eb_usehsm                 %s\n", toString( usehsm) );

	edcLogPrintf( "eb_wallet                 \"%s\"\n", wallet.c_str() );
	edcLogPrintf( "eb_walletbroadcast        %s\n", toString( walletbroadcast) );
	edcLogPrintf( "eb_walletnotify           \"%s\"\n", walletnotify.c_str() );
	edcLogPrintf( "eb_walletprematurewitness %s\n", toString( walletprematurewitness ) );
	edcLogPrintf( "eb_walletrbf              %s\n", toString(walletrbf) );
	printStrVec( "eb_whitebind             ", whitebind );
	printStrVec( "eb_whitelist             ", whitelist );
	edcLogPrintf( "eb_whitelistforcerelay    %s\n", toString( whitelistforcerelay) );
	edcLogPrintf( "eb_whitelistrelay         %s\n", toString( whitelistrelay) );

	edcLogPrintf( "eb_zapwallettxes          %lld\n", zapwallettxes );

	edcLogPrintf( ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n" );
}

void EDCparams::checkParams() const
{
	if( !checkparams )
		return;

	std::set<std::string> validparams;

	validparams.insert("-acceptnonstdtxn");
	validparams.insert("-addnode");
	validparams.insert("-alertnotify");
	validparams.insert("-banscore");
	validparams.insert("-bantime");
	validparams.insert("-bind");
	validparams.insert("-bip9params");
	validparams.insert("-blockmaxweight");
	validparams.insert("-blockmaxsize");
	validparams.insert("-blocknotify");
	validparams.insert("-blockprioritysize");
	validparams.insert("-blocksonly");
	validparams.insert("-blockversion");
	validparams.insert("-bytespersigop");
	validparams.insert("-checkblockindex");
	validparams.insert("-checkblocks");
	validparams.insert("-checklevel");
	validparams.insert("-checkmempool");
	validparams.insert("-checkpoints");
	validparams.insert("-conf");
	validparams.insert("-connect");
	validparams.insert("-daemon");
	validparams.insert("-datacarrier");
	validparams.insert("-datacarriersize");
	validparams.insert("-datadir");
	validparams.insert("-dbcache");
	validparams.insert("-dblogsize");
	validparams.insert("-debug");
	validparams.insert("-disablesafemode");
	validparams.insert("-disablewallet");
	validparams.insert("-discover");
	validparams.insert("-dns");
	validparams.insert("-dnsseed");
	validparams.insert("-dropmessagestest");
	validparams.insert("-externalip");
	validparams.insert("-fallbackfee");
	validparams.insert("-feefilter");
	validparams.insert("-flushwallet");
	validparams.insert("-forcednsseed");
	validparams.insert("-fuzzmessagestest");
	validparams.insert("-hsmkeypool");
	validparams.insert("-keypool");
	validparams.insert("-limitancestorcount");
	validparams.insert("-limitancestorsize");
	validparams.insert("-limitdescendantcount");
	validparams.insert("-limitdescendantsize");
	validparams.insert("-limitfreerelay");
	validparams.insert("-listen");
	validparams.insert("-listenonion");
	validparams.insert("-loadblock");
	validparams.insert("-logips");
	validparams.insert("-logtimemicros");
	validparams.insert("-logtimestamps");
	validparams.insert("-maxconnections");
	validparams.insert("-maxmempool");
	validparams.insert("-maxorphantx");
	validparams.insert("-maxreceivebuffer");
	validparams.insert("-maxsendbuffer");
	validparams.insert("-maxsigcachesize");
	validparams.insert("-maxtimeadjustment");
	validparams.insert("-maxtipage");
	validparams.insert("-maxtxfee");
	validparams.insert("-maxuploadtarget");
	validparams.insert("-mempoolexpiry");
	validparams.insert("-mempoolreplacement");
	validparams.insert("-minrelaytxfee");
	validparams.insert("-mintxfee");
	validparams.insert("-nodebug");
	validparams.insert("-onion");
	validparams.insert("-onlynet");
	validparams.insert("-par");
	validparams.insert("-paytxfee");
	validparams.insert("-peerbloomfilters");
	validparams.insert("-permitbaremultisig");
	validparams.insert("-pid");
	validparams.insert("-port");
	validparams.insert("-prematurewitness");
	validparams.insert("-promiscuousmempoolflags");
	validparams.insert("-printpriority");
	validparams.insert("-printtoconsole");
	validparams.insert("-privdb");
	validparams.insert("-proxy");
	validparams.insert("-proxyrandomize");
	validparams.insert("-prune");
	validparams.insert("-regtest");
	validparams.insert("-reindex");
	validparams.insert("-reindex-chainsate");
	validparams.insert("-relaypriority");
	validparams.insert("-rescan");
	validparams.insert("-rest");
	validparams.insert("-rpcallowip");
	validparams.insert("-rpcauth");
	validparams.insert("-rpcbind");
	validparams.insert("-rpccookiefile");
	validparams.insert("-rpcpassword");
	validparams.insert("-rpcport");
	validparams.insert("-rpcservertimeout");
	validparams.insert("-rpcthreads");
	validparams.insert("-rpcuser");
	validparams.insert("-rpcworkqueue");
	validparams.insert("-salvagewallet");
	validparams.insert("-seednode");
	validparams.insert("-sendfreetransactions");
	validparams.insert("-server");
	validparams.insert("-shrinkdebugfile");
	validparams.insert("-spendzeroconfchange");
	validparams.insert("-stopafterblockimport");
	validparams.insert("-sysperms");
	validparams.insert("-testnet");
	validparams.insert("-testsafemode");
	validparams.insert("-timeout");
	validparams.insert("-torcontrol");
	validparams.insert("-torpassword");
	validparams.insert("-txconfirmtarget");
	validparams.insert("-txindex");
	validparams.insert("-uacomment");
	validparams.insert("-upgradewallet");
	validparams.insert("-upnp");
	validparams.insert("-usehsm");
	validparams.insert("-usehd");
	validparams.insert("-wallet");
	validparams.insert("-walletbroadcast");
	validparams.insert("-walletnotify");
	validparams.insert("-walletprematurewitness");
	validparams.insert("-walletrbf");
	validparams.insert("-whitebind");
	validparams.insert("-whitelist");
	validparams.insert("-whitelistforcerelay");
	validparams.insert("-whitelistrelay");
	validparams.insert("-zapwallettxes");
	validparams.insert("-eb_acceptnonstdtxn");
	validparams.insert("-eb_addnode");
	validparams.insert("-eb_alertnotify");
	validparams.insert("-eb_banscore");
	validparams.insert("-eb_bantime");
	validparams.insert("-eb_bind");
	validparams.insert("-eb_bip9params");
	validparams.insert("-eb_blockmaxweight");
	validparams.insert("-eb_blockmaxsize");
	validparams.insert("-eb_blocknotify");
	validparams.insert("-eb_blockprioritysize");
	validparams.insert("-eb_blocksonly");
	validparams.insert("-eb_blockversion");
	validparams.insert("-eb_bytespersigop");
	validparams.insert("-eb_cacert");
	validparams.insert("-eb_cert");
	validparams.insert("-eb_checkblockindex");
	validparams.insert("-eb_checkblocks");
	validparams.insert("-eb_checklevel");
	validparams.insert("-eb_checkmempool");
	validparams.insert("-eb_checkparams");
	validparams.insert("-eb_checkpoints");
	validparams.insert("-eb_conf");
	validparams.insert("-eb_connect");
	validparams.insert("-eb_datacarrier");
	validparams.insert("-eb_datacarriersize");
	validparams.insert("-eb_datadir");
	validparams.insert("-eb_dbcache");
	validparams.insert("-eb_dblogsize");
	validparams.insert("-eb_debug");
	validparams.insert("-eb_disablesafemode");
	validparams.insert("-eb_disablewallet");
	validparams.insert("-eb_discover");
	validparams.insert("-eb_dns");
	validparams.insert("-eb_dnsseed");
	validparams.insert("-eb_dropmessagestest");
	validparams.insert("-eb_externalip");
	validparams.insert("-eb_fallbackfee");
	validparams.insert("-eb_feefilter");
	validparams.insert("-eb_flushwallet");
	validparams.insert("-eb_forcednsseed");
	validparams.insert("-eb_fuzzmessagestest");
	validparams.insert("-eb_hsmkeypool");
	validparams.insert("-eb_keypool");
	validparams.insert("-eb_limitancestorcount");
	validparams.insert("-eb_limitancestorsize");
	validparams.insert("-eb_limitdescendantcount");
	validparams.insert("-eb_limitdescendantsize");
	validparams.insert("-eb_limitfreerelay");
	validparams.insert("-eb_listen");
	validparams.insert("-eb_listenonion");
	validparams.insert("-eb_loadblock");
	validparams.insert("-eb_logips");
	validparams.insert("-eb_logtimemicros");
	validparams.insert("-eb_logtimestamps");
	validparams.insert("-eb_maxconnections");
	validparams.insert("-eb_maxmempool");
	validparams.insert("-eb_maxorphantx");
	validparams.insert("-eb_maxreceivebuffer");
	validparams.insert("-eb_maxsendbuffer");
	validparams.insert("-eb_maxsigcachesize");
	validparams.insert("-eb_maxtimeadjustment");
	validparams.insert("-eb_maxtipage");
	validparams.insert("-eb_maxtxfee");
	validparams.insert("-eb_maxuploadtarget");
	validparams.insert("-eb_maxverdepth");
	validparams.insert("-eb_mempoolexpiry");
	validparams.insert("-eb_mempoolreplacement");
	validparams.insert("-eb_minrelaytxfee");
	validparams.insert("-eb_mintxfee");
	validparams.insert("-eb_nodebug");
	validparams.insert("-eb_onion");
	validparams.insert("-eb_onlynet");
	validparams.insert("-eb_par");
	validparams.insert("-eb_paytxfee");
	validparams.insert("-eb_peerbloomfilters");
	validparams.insert("-eb_permitbaremultisig");
	validparams.insert("-eb_pid");
	validparams.insert("-eb_port");
	validparams.insert("-eb_prematurewitness");
	validparams.insert("-eb_promiscuousmempoolflags");
	validparams.insert("-eb_printpriority");
	validparams.insert("-eb_printtoconsole");
	validparams.insert("-eb_privdb");
	validparams.insert("-eb_privkey");
	validparams.insert("-eb_proxy");
	validparams.insert("-eb_proxyrandomize");
	validparams.insert("-eb_prune");
	validparams.insert("-eb_regtest");
	validparams.insert("-eb_reindex");
	validparams.insert("-eb_reindex-chainstate");
	validparams.insert("-eb_relaypriority");
	validparams.insert("-eb_rescan");
	validparams.insert("-eb_rest");
	validparams.insert("-eb_rpcallowip");
	validparams.insert("-eb_rpcauth");
	validparams.insert("-eb_rpcbind");
	validparams.insert("-eb_rpccookiefile");
	validparams.insert("-eb_rpcpassword");
	validparams.insert("-eb_rpcport");
	validparams.insert("-eb_rpcservertimeout");
	validparams.insert("-eb_rpcthreads");
	validparams.insert("-eb_rpcuser");
	validparams.insert("-eb_rpcworkqueue");
	validparams.insert("-eb_salvagewallet");
	validparams.insert("-eb_seednode");
	validparams.insert("-eb_sendfreetransactions");
	validparams.insert("-eb_server");
	validparams.insert("-eb_shrinkdebugfile");
	validparams.insert("-eb_spendzeroconfchange");
	validparams.insert("-eb_sport");
	validparams.insert("-eb_stopafterblockimport");
	validparams.insert("-eb_testnet");
	validparams.insert("-eb_testsafemode");
	validparams.insert("-eb_timeout");
	validparams.insert("-eb_torcontrol");
	validparams.insert("-eb_torpassword");
	validparams.insert("-eb_txconfirmtarget");
	validparams.insert("-eb_txindex");
	validparams.insert("-eb_uacomment");
	validparams.insert("-eb_upgradewallet");
	validparams.insert("-eb_upnp");
	validparams.insert("-eb_usehd");
	validparams.insert("-eb_usehsm");
	validparams.insert("-eb_wallet");
	validparams.insert("-eb_walletbroadcast");
	validparams.insert("-eb_walletnotify");
	validparams.insert("-eb_walletprematurewitness");
	validparams.insert("-eb_walletrbf");
	validparams.insert("-eb_whitebind");
	validparams.insert("-eb_whitelist");
	validparams.insert("-eb_whitelistforcerelay");
	validparams.insert("-eb_whitelistrelay");
	validparams.insert("-eb_zapwallettxes");

	auto i = mapArgs.begin();
	auto e = mapArgs.end();

	while( i != e )
	{
		auto key = i->first;

		if( validparams.find(key) == validparams.end() )
		{
			std::string msg = "Invalid option ";
			msg += key;

			throw std::runtime_error( msg );
		}

		++i;
	}
}
