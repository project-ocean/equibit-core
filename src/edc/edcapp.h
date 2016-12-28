// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "edctxmempool.h"
#include "limitedmap.h"
#include "addrman.h"
#include "main.h"
#include "edcnet.h"
#include "edc/wallet/edcdb.h"
#include "versionbits.h"
#include <openssl/ssl.h>

#ifdef USE_HSM
namespace NFast
{
class App;
class CardLoadingLib;
class HardServer;
class Module;
class SecurityWorld;
};
#endif


class CEDCBlockTreeDB;
class CEDCNode;
class CEDCSSLNode;
class CEDCCoinsViewCache;
class CEDCWallet;
struct event_base;

/** Relay map, protected by cs_main. */
typedef std::map<uint256, std::shared_ptr<const CEDCTransaction>> MapRelay;


/**
 * The application object. It manages all global data.
 */
class EDCapp
{
public:
	static EDCapp & singleton();

	~EDCapp();

	int debug() const				{ return debug_; }
	void debug( int b )				{ debug_ = b; }

	CEDCTxMemPool & mempool() 		{ return mempool_; }

    CFeeRate & minRelayTxFee()		{ return minRelayTxFee_; }
    void minRelayTxFee( CFeeRate r ){ minRelayTxFee_ = r; }

	int scriptCheckThreads() const	{ return scriptCheckThreads_; }
	void scriptCheckThreads( int n ){ scriptCheckThreads_ = n; }

	uint64_t pruneTarget() const	{ return pruneTarget_; }
	void pruneTarget( uint64_t p )	{ pruneTarget_ = p; }

	bool pruneMode() const			{ return pruneMode_; }
	void pruneMode( bool p )		{ pruneMode_ = p; }

	int connectTimeout() const		{ return connectTimeout_; }
	void connectTimeout( int c )	{ connectTimeout_ = c; }

	CAmount maxTxFee() const		{ return maxTxFee_; }
	void maxTxFee( CAmount & m )	{ maxTxFee_ = m; }

	CEDCBlockTreeDB * blocktree() const		{ return blocktree_; }
	void blocktree( CEDCBlockTreeDB * bt )	{ blocktree_ = bt; }

	uint64_t lastBlockWeight() const		{ return lastBlockWeight_; }
	void lastBlockWeight( uint64_t l )	{ lastBlockWeight_ = l; }

	uint64_t lastBlockSize() const		{ return lastBlockSize_; }
	void lastBlockSize( uint64_t l )	{ lastBlockSize_ = l; }

	const CScript & coinbaseFlags() const	{ return COINBASE_FLAGS_; }
	CScript & coinbaseFlags()				{ return COINBASE_FLAGS_; }

	size_t coinCacheUsage() const	{ return coinCacheUsage_; }
	void coinCacheUsage( size_t c )	{ coinCacheUsage_ = c; }

	int64_t walletUnlockTime() const	{ return walletUnlockTime_; }
	void walletUnlockTime( int64_t w )  { walletUnlockTime_ = w; }

	uint64_t lastBlockTx() const		{ return lastBlockTx_; }
	void lastBlockTx( uint64_t ui )		{ lastBlockTx_ = ui; }

	const std::string	& strSubVersion() const		{ return strSubVersion_; }
	void strSubVersion( const std::string & ssv )	{ strSubVersion_ = ssv; }

	bool txIndex() const	{ return txIndex_; }
	void txIndex( bool b )	{ txIndex_ = b; }

	MapRelay & mapRelay()						{ return mapRelay_; }
	CCriticalSection & mapRelayCS()				{ return mapRelayCS_; }

	bool havePruned() const		{ return havePruned_; }
	void havePruned( bool b )	{ havePruned_ = b; }

	limitedmap<uint256, int64_t> & mapAlreadyAskedFor() 
	{ 
		return mapAlreadyAskedFor_; 
	}

	std::vector<std::string> & addedNodes()	{ return addedNodes_; }
	CCriticalSection & addedNodesCS()		{ return addedNodesCS_; }

	CCriticalSection & mapLocalHostCS()		{ return mapLocalHostCS_; }
	std::map<CNetAddr, LocalServiceInfo> & mapLocalHost() { return mapLocalHost_; }

	BlockMap & mapBlockIndex()	{ return mapBlockIndex_; }

	bool importing() const	{ return importing_; }
	void importing( bool b ){ importing_ = b; }

	bool reindex() const	{ return reindex_; }
	void reindex( bool r )	{ reindex_ = r; }

	CChain & chainActive() { return chainActive_; }

	CEDCCoinsViewCache * coinsTip()			{ return coinsTip_; }
	void coinsTip( CEDCCoinsViewCache * p ) { coinsTip_ = p; }

	CBlockIndex * & indexBestHeader()		{ return indexBestHeader_; }
	void indexBestHeader( CBlockIndex * i )	{ indexBestHeader_ = i; }

	CEDCWallet * walletMain()			{ return walletMain_; }
	void walletMain( CEDCWallet * p ) 	{ walletMain_ = p; }

	CFeeRate & payTxFee()				{ return payTxFee_; }
	void payTxFee( const CFeeRate & p )	{ payTxFee_ = p; }

	unsigned int walletDBUpdated() const	{ return walletDBUpdated_; }
	void incWalletDBUpdated()				{ ++walletDBUpdated_; }

	CEDCDBEnv & bitdb()	{ return bitdb_; }

	CConditionVariable & blockChange() 		{ return blockChange_; }
	VersionBitsCache & versionbitscache() 	{ return versionbitscache_; }

	event_base * eventBase()				{ return eventBase_; }
	void	eventBase( event_base * eb )	{ eventBase_ = eb; }

	SSL_CTX	* sslCtx()	{ return sslCtx_; }

	bool	initSSL(const std::string & caCert, const std::string & cert, 
					const std::string & privKey, const char * passPhrase,
					int verDepth );

	bool sslEnabled() const { return sslEnabled_; }

	std::unique_ptr<CEDCConnman> & connman()	{ return connman_; }
	void connman( CEDCConnman * connman)		{ connman_.reset(connman); }

#ifdef USE_HSM
	NFast::App              * & nfApp() 			{ return nfApp_; }
	NFast::SecurityWorld    * & nfSecWorld()		{ return nfSecWorld_; }
	NFast::HardServer       * & nfHardServer()		{ return nfHardServer_; }
	NFast::CardLoadingLib   * & nfCardLoadingLib()	{ return nfCardLoadingLib_;}
	NFast::Module           * & nfModule()			{ return nfModule_; }
#endif

private:
	EDCapp();

	EDCapp( const EDCapp & );
	EDCapp & operator = ( const EDCapp & );

	bool debug_;
	bool discover_;

	/* True if any block files have ever been pruned. */
	bool havePruned_;

	bool listen_;

	/* True if we're running in -prune mode. */
	bool pruneMode_;
	bool spendZeroConfChange_;
	bool txIndex_;
	bool isBareMultisigStd_;
	bool requireStandard_;
	bool importing_;
	bool reindex_;
	bool sslEnabled_;

	int connectTimeout_;

	/** Maximum number of connections to simultaneously allow (aka connection 
	 *  slots) 
	 */
	int scriptCheckThreads_;

	int64_t walletUnlockTime_;

	unsigned int txConfirmTarget_;

	size_t coinCacheUsage_;

	/** Number of MiB of block files that we're trying to stay below. */
	uint64_t pruneTarget_;
	uint64_t lastBlockSize_;
	uint64_t lastBlockWeight_;
	uint64_t lastBlockTx_;

	/** Absolute maximum transaction fee (in satoshis) used by wallet
	 *  and mempool (rejects high fee in sendrawtransaction) 
	 */
	CAmount maxTxFee_;

	/* A fee rate smaller than this is considered zero fee (for relaying, 
     * mining and transaction creation) 
	 */
    CFeeRate minRelayTxFee_;

	CEDCTxMemPool mempool_;

	/* points to the active block tree (protected by EDC_cs_main) */
	CEDCBlockTreeDB * blocktree_;

	/* Constant stuff for coinbase transactions we create: */
	CScript COINBASE_FLAGS_;

	/* Subversion as sent to the P2P network in `version` messages */
	std::string	strSubVersion_;

	MapRelay mapRelay_;
	CCriticalSection mapRelayCS_;

	limitedmap<uint256, int64_t> mapAlreadyAskedFor_;

	std::vector<std::string> addedNodes_;
	CCriticalSection addedNodesCS_;

	CCriticalSection mapLocalHostCS_;
	std::map<CNetAddr, LocalServiceInfo> mapLocalHost_;

	BlockMap mapBlockIndex_;

	CChain chainActive_;

	/** Global variable that points to the active CEDCCoinsView (protected by EDC_cs_main) */
	CEDCCoinsViewCache * coinsTip_;

	/** Best header we've seen so far (used for getheaders queries' starting points). */
	CBlockIndex * indexBestHeader_;

	CEDCWallet * walletMain_;

	/** Transaction fee set by the user */
	CFeeRate	payTxFee_;

	unsigned int walletDBUpdated_;

	CEDCDBEnv bitdb_;

	CConditionVariable blockChange_;

	event_base	* eventBase_;

	SSL_CTX	* sslCtx_;

	VersionBitsCache versionbitscache_;

	std::unique_ptr<CEDCConnman> connman_;

#ifdef USE_HSM
	NFast::App              * nfApp_;
	NFast::SecurityWorld    * nfSecWorld_;
	NFast::HardServer       * nfHardServer_;
	NFast::CardLoadingLib   * nfCardLoadingLib_;
	NFast::Module           * nfModule_;
#endif
};
