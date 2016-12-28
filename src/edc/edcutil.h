// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

/**
 * Server/client environment: argument handling, config file parsing,
 * logging, thread wrappers
 */

#include "util.h"


extern std::string edcstrMiscWarning;


/** Send a string to the log output */
int edcLogPrintStr(const std::string &str);

#define edcLogPrintf(...) edcLogPrint(NULL, __VA_ARGS__)

/** Return true if log accepts specified category */
bool edcLogAcceptCategory(const char* category);


template<typename... Args>
static inline int edcLogPrint(
	const char* category, 
	const char* fmt, 
	const Args&... args)
{
    if(!edcLogAcceptCategory(category)) return 0;                            \
    return edcLogPrintStr(tfm::format(fmt, args...));
}

template<typename... Args>
bool edcError(const char* fmt, const Args&... args)
{
    edcLogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
    return false;
}

void edcPrintExceptionContinue(const std::exception *pex, const char* pszThread);

/**
 * .. and a wrapper that just calls func once
 */
template <typename Callable> 
void edcTraceThread(const char* name,  Callable func)
{
    std::string s = strprintf("equibit-%s", name);
    RenameThread(s.c_str());
    try
    {
        edcLogPrintf("%s thread start\n", name);
        func();
        edcLogPrintf("%s thread exit\n", name);
    }
    catch (const boost::thread_interrupted&)
    {
        edcLogPrintf("%s thread interrupt\n", name);
        throw;
    }
    catch (const std::exception& e) 
	{
        edcPrintExceptionContinue(&e, name);
        throw;
    }
    catch (...) 
	{
        edcPrintExceptionContinue(NULL, name);
        throw;
    }
}

void edcOpenDebugLog();
void edcShrinkDebugFile();
void edcRunCommand(const std::string& strCommand);
const boost::filesystem::path & edcGetDataDir( bool = true );
boost::filesystem::path edcGetDefaultDataDir();
boost::filesystem::path edcGetPidFile();
boost::filesystem::path edcGetConfigFile();
void edcClearDatadirCache();

