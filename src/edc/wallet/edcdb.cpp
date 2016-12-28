// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcdb.h"

#include "addrman.h"
#include "hash.h"
#include "protocol.h"
#include "edc/edcutil.h"
#include "utilstrencodings.h"
#include "edc/edcapp.h"
#include "edc/edcparams.h"


#include <stdint.h>

#ifndef WIN32
#include <sys/stat.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <boost/version.hpp>

using namespace std;


void CEDCDBEnv::EnvShutdown()
{
    if (!fDbEnvInit)
        return;

    fDbEnvInit = false;
    int ret = dbenv->close(0);
    if (ret != 0)
        edcLogPrintf("CEDCDBEnv::EnvShutdown: Error %d shutting down database "
			"environment: %s\n", ret, DbEnv::strerror(ret));
    if (!fMockDb)
        DbEnv((u_int32_t)0).remove(strPath.c_str(), 0);
}

void CEDCDBEnv::Reset()
{
    delete dbenv;
    dbenv = new DbEnv(DB_CXX_NO_EXCEPTIONS);
    fDbEnvInit = false;
    fMockDb = false;
}

CEDCDBEnv::CEDCDBEnv() : dbenv(NULL)
{
    Reset();
}

CEDCDBEnv::~CEDCDBEnv()
{
    EnvShutdown();
    delete dbenv;
    dbenv = NULL;
}

void CEDCDBEnv::Close()
{
    EnvShutdown();
}

bool CEDCDBEnv::Open(const boost::filesystem::path& pathIn)
{
	EDCparams & params = EDCparams::singleton();

    if (fDbEnvInit)
        return true;

    boost::this_thread::interruption_point();

    strPath = pathIn.string();
    boost::filesystem::path pathLogDir = pathIn / "database";
    TryCreateDirectory(pathLogDir);
    boost::filesystem::path pathErrorFile = pathIn / "db.log";
    edcLogPrintf("CEDCDBEnv::Open: LogDir=%s ErrorFile=%s\n", 
		pathLogDir.string(), pathErrorFile.string());

    unsigned int nEnvFlags = 0;
    if (params.privdb)
        nEnvFlags |= DB_PRIVATE;

    dbenv->set_lg_dir(pathLogDir.string().c_str());
    dbenv->set_cachesize(0, 0x100000, 1); // 1 MiB should be enough for just the wallet
    dbenv->set_lg_bsize(0x10000);
    dbenv->set_lg_max(1048576);
    dbenv->set_lk_max_locks(40000);
    dbenv->set_lk_max_objects(40000);
    dbenv->set_errfile(fopen(pathErrorFile.string().c_str(), "a")); /// debug
    dbenv->set_flags(DB_AUTO_COMMIT, 1);
    dbenv->set_flags(DB_TXN_WRITE_NOSYNC, 1);
    dbenv->log_set_config(DB_LOG_AUTO_REMOVE, 1);
    int ret = dbenv->open(strPath.c_str(),
                         DB_CREATE |
                             DB_INIT_LOCK |
                             DB_INIT_LOG |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN |
                             DB_THREAD |
                             DB_RECOVER |
                             nEnvFlags,
                         S_IRUSR | S_IWUSR);
    if (ret != 0)
        return edcError("CEDCDBEnv::Open: Error %d opening database environment: %s\n", 
			ret, DbEnv::strerror(ret));

    fDbEnvInit = true;
    fMockDb = false;

    return true;
}

void CEDCDBEnv::MakeMock()
{
    if (fDbEnvInit)
        throw runtime_error("CEDCDBEnv::MakeMock: Already initialized");

    boost::this_thread::interruption_point();

    edcLogPrint("db", "CEDCDBEnv::MakeMock\n");

    dbenv->set_cachesize(1, 0, 1);
    dbenv->set_lg_bsize(10485760 * 4);
    dbenv->set_lg_max(10485760);
    dbenv->set_lk_max_locks(10000);
    dbenv->set_lk_max_objects(10000);
    dbenv->set_flags(DB_AUTO_COMMIT, 1);
    dbenv->log_set_config(DB_LOG_IN_MEMORY, 1);
    int ret = dbenv->open(NULL,
                         DB_CREATE |
                             DB_INIT_LOCK |
                             DB_INIT_LOG |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN |
                             DB_THREAD |
                             DB_PRIVATE,
                         S_IRUSR | S_IWUSR);
    if (ret > 0)
        throw runtime_error(strprintf("CEDCDBEnv::MakeMock: Error %d opening database environment.", ret));

    fDbEnvInit = true;
    fMockDb = true;
}

CEDCDBEnv::VerifyResult CEDCDBEnv::Verify(
	const std::string & strFile, 
				bool (* recoverFunc)(CEDCDBEnv& dbenv, const std::string& strFile))
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    Db db(dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, NULL, 0);
    if (result == 0)
        return VERIFY_OK;
    else if (recoverFunc == NULL)
        return RECOVER_FAIL;

    // Try to recover:
    bool fRecovered = (*recoverFunc)(*this, strFile);
    return (fRecovered ? RECOVER_OK : RECOVER_FAIL);
}

/* End of headers, beginning of key/value data */
static const char *HEADER_END = "HEADER=END";

/* End of key/value data */
static const char *DATA_END = "DATA=END";

bool CEDCDBEnv::Salvage(
					 const std::string & strFile, 
									bool fAggressive, 
	std::vector<CEDCDBEnv::KeyValPair> & vResult)
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    u_int32_t flags = DB_SALVAGE;
    if (fAggressive)
        flags |= DB_AGGRESSIVE;

    stringstream strDump;

    Db db(dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, &strDump, flags);
    if (result == DB_VERIFY_BAD) 
	{
        edcLogPrintf("CEDCDBEnv::Salvage: Database salvage found errors, all data may not be recoverable.\n");
        if (!fAggressive) 
		{
            edcLogPrintf("CEDCDBEnv::Salvage: Rerun with aggressive mode to ignore errors and continue.\n");
            return false;
        }
    }
    if (result != 0 && result != DB_VERIFY_BAD) 
	{
        edcLogPrintf("CEDCDBEnv::Salvage: Database salvage failed with result %d.\n", result);
        return false;
    }

    // Format of bdb dump is ascii lines:
    // header lines...
    // HEADER=END
    //  hexadecimal key
    //  hexadecimal value
    //  ... repeated
    // DATA=END

    string strLine;
    while (!strDump.eof() && strLine != HEADER_END)
        getline(strDump, strLine); // Skip past header

    std::string keyHex, valueHex;
    while (!strDump.eof() && keyHex != DATA_END) 
	{
        getline(strDump, keyHex);
        if (keyHex != DATA_END) 
		{
            if (strDump.eof())
                break;
            getline(strDump, valueHex);
            if (valueHex == DATA_END) 
			{
                edcLogPrintf("CEDCDBEnv::Salvage: WARNING: Number of keys in data does not match number of values.\n");
                break;
            }
            vResult.push_back(make_pair(ParseHex(keyHex), ParseHex(valueHex)));
        }
    }

    if (keyHex != DATA_END) 
	{
        edcLogPrintf("CEDCDBEnv::Salvage: WARNING: Unexpected end of file while reading salvage output.\n");
        return false;
    }

    return (result == 0);
}


void CEDCDBEnv::CheckpointLSN(const std::string& strFile)
{
    dbenv->txn_checkpoint(0, 0, 0);
    if (fMockDb)
        return;
    dbenv->lsn_reset(strFile.c_str(), 0);
}


CEDCDB::CEDCDB(
	 const std::string & strFilename, 
			const char * pszMode, 
					bool fFlushOnCloseIn) : pdb(NULL), activeTxn(NULL)
{
	EDCapp & theApp = EDCapp::singleton();

    int ret;
    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    fFlushOnClose = fFlushOnCloseIn;
    if (strFilename.empty())
        return;

    bool fCreate = strchr(pszMode, 'c') != NULL;
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    {
        LOCK(theApp.bitdb().cs_db);
        if (!theApp.bitdb().Open(edcGetDataDir()))
            throw runtime_error("CEDCDB: Failed to open database environment.");

        strFile = strFilename;
        ++theApp.bitdb().mapFileUseCount[strFile];
        pdb = theApp.bitdb().mapDb[strFile];
        if (pdb == NULL) 
		{
            pdb = new Db(theApp.bitdb().dbenv, 0);

            bool fMockDb = theApp.bitdb().IsMock();
            if (fMockDb) 
			{
                DbMpoolFile* mpf = pdb->get_mpf();
                ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
                if (ret != 0)
                    throw runtime_error(strprintf("CEDCDB: Failed to configure for no temp file backing for database %s", strFile));
            }

            ret = pdb->open(NULL,                               // Txn pointer
                            fMockDb ? NULL : strFile.c_str(),   // Filename
                            fMockDb ? strFile.c_str() : "main", // Logical db name
                            DB_BTREE,                           // Database type
                            nFlags,                             // Flags
                            0);

            if (ret != 0) 
			{
                delete pdb;
                pdb = NULL;
                --theApp.bitdb().mapFileUseCount[strFile];
                strFile = "";
                throw runtime_error(strprintf("CEDCDB: Error %d, can't open database %s", ret, strFilename));
            }

            if (fCreate && !Exists(string("version"))) 
			{
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(CLIENT_VERSION);
                fReadOnly = fTmp;
            }

            theApp.bitdb().mapDb[strFile] = pdb;
        }
    }
}

void CEDCDB::Flush()
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    if (activeTxn)
        return;

    // Flush database activity from memory pool to disk log
    unsigned int nMinutes = 0;
    if (fReadOnly)
        nMinutes = 1;

    theApp.bitdb().dbenv->txn_checkpoint(nMinutes ? params.dblogsize * 1024 : 0, nMinutes, 0);
}

void CEDCDB::Close()
{
	EDCapp & theApp = EDCapp::singleton();

    if (!pdb)
        return;

    if (activeTxn)
        activeTxn->abort();

    activeTxn = NULL;
    pdb = NULL;

    if (fFlushOnClose)
        Flush();
    {
        LOCK(theApp.bitdb().cs_db);
        --theApp.bitdb().mapFileUseCount[strFile];
    }
}

void CEDCDBEnv::CloseDb(const string& strFile)
{
    {
        LOCK(cs_db);
        if (mapDb[strFile] != NULL) 
		{
            // Close the database handle
            Db* pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = NULL;
        }
    }
}

bool CEDCDBEnv::RemoveDb(const string& strFile)
{
    this->CloseDb(strFile);

    LOCK(cs_db);
    int rc = dbenv->dbremove(NULL, strFile.c_str(), NULL, DB_AUTO_COMMIT);
    return (rc == 0);
}

bool CEDCDB::Rewrite(const string& strFile, const char* pszSkip)
{
	EDCapp & theApp = EDCapp::singleton();

    while (true) 
	{
        {
            LOCK(theApp.bitdb().cs_db);

            if (!theApp.bitdb().mapFileUseCount.count(strFile) || 
			theApp.bitdb().mapFileUseCount[strFile] == 0) 
			{
                // Flush log data to the dat file
                theApp.bitdb().CloseDb(strFile);
                theApp.bitdb().CheckpointLSN(strFile);
                theApp.bitdb().mapFileUseCount.erase(strFile);

                bool fSuccess = true;
                edcLogPrintf("CEDCDB::Rewrite: Rewriting %s...\n", strFile);

                string strFileRes = strFile + ".rewrite";
                { 
					// surround usage of db with extra {}
                    CEDCDB db(strFile.c_str(), "r");
                    Db* pdbCopy = new Db(theApp.bitdb().dbenv, 0);

                    int ret = pdbCopy->open(NULL,               // Txn pointer
                                            strFileRes.c_str(), // Filename
                                            "main",             // Logical db name
                                            DB_BTREE,           // Database type
                                            DB_CREATE,          // Flags
                                            0);
                    if (ret > 0) 
					{
                        edcLogPrintf("CEDCDB::Rewrite: Can't create database file %s\n", strFileRes);
                        fSuccess = false;
                    }

                    Dbc* pcursor = db.GetCursor();
                    if (pcursor)
					{
                        while (fSuccess) 
						{
                            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
                            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                            int ret1 = db.ReadAtCursor(pcursor, ssKey, ssValue);
                            if (ret1 == DB_NOTFOUND)
							{
                                pcursor->close();
                                break;
                            } 
							else if (ret1 != 0) 
							{
                                pcursor->close();
                                fSuccess = false;
                                break;
                            }
                            if (pszSkip &&
                                strncmp(&ssKey[0], pszSkip, std::min(ssKey.size(), strlen(pszSkip))) == 0)
                                continue;
                            if (strncmp(&ssKey[0], "\x07version", 8) == 0) 
							{
                                // Update version:
                                ssValue.clear();
                                ssValue << CLIENT_VERSION;
                            }
                            Dbt datKey(&ssKey[0], ssKey.size());
                            Dbt datValue(&ssValue[0], ssValue.size());
                            int ret2 = pdbCopy->put(NULL, &datKey, &datValue, DB_NOOVERWRITE);
                            if (ret2 > 0)
                                fSuccess = false;
                        }
					}
                    if (fSuccess) 
					{
                        db.Close();
                        theApp.bitdb().CloseDb(strFile);
                        if (pdbCopy->close(0))
                            fSuccess = false;
                        delete pdbCopy;
                    }
                }
                if (fSuccess) 
				{
                    Db dbA(theApp.bitdb().dbenv, 0);
                    if (dbA.remove(strFile.c_str(), NULL, 0))
                        fSuccess = false;
                    Db dbB(theApp.bitdb().dbenv, 0);
                    if (dbB.rename(strFileRes.c_str(), NULL, strFile.c_str(), 0))
                        fSuccess = false;
                }
                if (!fSuccess)
                    edcLogPrintf("CEDCDB::Rewrite: Failed to rewrite database file %s\n", strFileRes);
                return fSuccess;
            }
        }
        MilliSleep(100);
    }
    return false;
}


void CEDCDBEnv::Flush(bool fShutdown)
{
    int64_t nStart = GetTimeMillis();

    // Flush log data to the actual data file on all files that are not in use
    edcLogPrint("db", "CEDCDBEnv::Flush: Flush(%s)%s\n", 
		fShutdown ? "true" : "false", fDbEnvInit ? "" : " database not started");

    if (!fDbEnvInit)
        return;

    {
        LOCK(cs_db);
        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end()) 
		{
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            edcLogPrint("db", "CEDCDBEnv::Flush: Flushing %s (refcount = %d)...\n", strFile, nRefCount);
            if (nRefCount == 0) 	
			{
                // Move log data to the dat file
                CloseDb(strFile);
                edcLogPrint("db", "CEDCDBEnv::Flush: %s checkpoint\n", strFile);
                dbenv->txn_checkpoint(0, 0, 0);
                edcLogPrint("db", "CEDCDBEnv::Flush: %s detach\n", strFile);
                if (!fMockDb)
                    dbenv->lsn_reset(strFile.c_str(), 0);
                edcLogPrint("db", "CEDCDBEnv::Flush: %s closed\n", strFile);
                mapFileUseCount.erase(mi++);
            } 
			else
                mi++;
        }

        edcLogPrint("db", "CEDCDBEnv::Flush: Flush(%s)%s took %15dms\n", 
			fShutdown ? "true" : "false", 
			fDbEnvInit ? "" : " database not started", GetTimeMillis() - nStart);

        if (fShutdown) 
		{
            char** listp;
            if (mapFileUseCount.empty()) 
			{
                dbenv->log_archive(&listp, DB_ARCH_REMOVE);
                Close();
                if (!fMockDb)
                    boost::filesystem::remove_all(boost::filesystem::path(strPath) / "database");
            }
        }
    }
}


bool CEDCDB::TxnBegin()
{
    EDCapp & theApp = EDCapp::singleton();

    if (!pdb || activeTxn)
        return false;

    DbTxn* ptxn = theApp.bitdb().TxnBegin();

    if (!ptxn)
        return false;
    activeTxn = ptxn;

    return true;
}

