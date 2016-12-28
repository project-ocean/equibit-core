// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "edcutil.h"
#include "edcparams.h"

#include "chainparamsbase.h"
#include "random.h"
#include "serialize.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utiltime.h"

#include <stdarg.h>

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <pthread_np.h>
#endif

#ifndef WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#else

#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h> /* for _commit */
#include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/foreach.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost 
{

    namespace program_options 
	{
        std::string to_internal(const std::string&);
    }

} // namespace boost

using namespace std;

string edcstrMiscWarning;

#if 0
bool fDaemon = false;
CTranslationInterface translationInterface;
#endif

/**
 * edcLogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */

static boost::once_flag debugPrintInitFlag = BOOST_ONCE_INIT;

/**
 * We use boost::call_once() to make sure mutexDebugLog and
 * vMsgsBeforeOpenLog are initialized in a thread-safe manner.
 *
 * NOTE: fileout, mutexDebugLog and sometimes vMsgsBeforeOpenLog
 * are leaked on exit. This is ugly, but will be cleaned up by
 * the OS/libc. When the shutdown sequence is fully audited and
 * tested, explicit destruction of these objects can be implemented.
 */
static FILE* fileout = NULL;
static boost::mutex* mutexDebugLog = NULL;
static list<string> *vMsgsBeforeOpenLog;

static int FileWriteStr(const std::string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp);
}

static void DebugPrintInit()
{
    assert(mutexDebugLog == NULL);
    mutexDebugLog = new boost::mutex();
    vMsgsBeforeOpenLog = new list<string>;
}

void edcOpenDebugLog()
{
    boost::call_once(&DebugPrintInit, debugPrintInitFlag);
    boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

    assert(fileout == NULL);
    assert(vMsgsBeforeOpenLog);

    boost::filesystem::path pathDebug = edcGetDataDir(true) / "debug.log";
    fileout = fopen(pathDebug.string().c_str(), "a");
    if (fileout) setbuf(fileout, NULL); // unbuffered

    // dump buffered messages from before we opened the log
    while (!vMsgsBeforeOpenLog->empty()) 
	{
        FileWriteStr(vMsgsBeforeOpenLog->front(), fileout);
        vMsgsBeforeOpenLog->pop_front();
    }

    delete vMsgsBeforeOpenLog;
    vMsgsBeforeOpenLog = NULL;
}

bool edcLogAcceptCategory(const char* category)
{
	EDCparams & params = EDCparams::singleton();

    if (category != NULL)
    {
        if (params.debug.size() == 0)
            return false;

        // Give each thread quick access to -eb_debug settings.
        // This helps prevent issues debugging global destructors,
        // where mapMultiArgs might be deleted before another
        // global destructor calls edcLogPrint()
        static boost::thread_specific_ptr<set<string> > ptrCategory;
        if (ptrCategory.get() == NULL)
        {
			EDCparams & params = EDCparams::singleton();
            const vector<string>& categories = params.debug;
            ptrCategory.reset(new set<string>(categories.begin(), categories.end()));
            // thread_specific_ptr automatically deletes the set when the thread ends.
        }
        const set<string>& setCategories = *ptrCategory.get();

        // if not debugging everything and not debugging specific category, edcLogPrint does nothing.
        if (setCategories.count(string("")) == 0 &&
            setCategories.count(string("1")) == 0 &&
            setCategories.count(string(category)) == 0)
            return false;
    }
    return true;
}

/**
 * fStartedNewLine is a state variable held by the calling context that will
 * suppress printing of the timestamp when multiple calls are made that don't
 * end in a newline. Initialize it to true, and hold it, in the calling context.
 */
static std::string LogTimestampStr(const std::string &str, bool *fStartedNewLine)
{
    string strStamped;

	EDCparams & params = EDCparams::singleton();
    if (!params.logtimestamps)
        return str;

    if (*fStartedNewLine) 
	{
        int64_t nTimeMicros = GetLogTimeMicros();
        strStamped = DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nTimeMicros/1000000);
        if (params.logtimemicros)
            strStamped += strprintf(".%06d", nTimeMicros%1000000);
        strStamped += ' ' + str;
    } else
        strStamped = str;

    if (!str.empty() && str[str.size()-1] == '\n')
        *fStartedNewLine = true;
    else
        *fStartedNewLine = false;

    return strStamped;
}

int edcLogPrintStr(const std::string &str)
{
    int ret = 0; // Returns total number of characters written
    static bool fStartedNewLine = true;

    string strTimestamped = LogTimestampStr(str, &fStartedNewLine);

	EDCparams & params = EDCparams::singleton();
    if (params.printtoconsole)
    {
        // print to console
        ret = fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    else if (fPrintToDebugLog)
    {
        boost::call_once(&DebugPrintInit, debugPrintInitFlag);
        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        // buffer if we haven't opened the log yet
        if (fileout == NULL) 
		{
            assert(vMsgsBeforeOpenLog);
            ret = strTimestamped.length();
            vMsgsBeforeOpenLog->push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (fReopenDebugLog) 
			{
                fReopenDebugLog = false;
                boost::filesystem::path pathDebug = 
					edcGetDataDir(true)/"debug.log";
                if (freopen(pathDebug.string().c_str(),"a",fileout) != NULL)
                    setbuf(fileout, NULL); // unbuffered
            }

            ret = FileWriteStr(strTimestamped, fileout);
        }
    }
    return ret;
}

static const int screenWidth = 79;
static const int optIndent = 2;
static const int msgIndent = 7;

static std::string FormatException(const std::exception* pex, const char* pszThread)
{
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "equibit";
#endif
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void edcPrintExceptionContinue(const std::exception* pex, const char* pszThread)
{
    std::string message = FormatException(pex, pszThread);
    edcLogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
}

void edcShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big
    boost::filesystem::path pathLog = edcGetDataDir(true) / "debug.log";
    FILE* file = fopen(pathLog.string().c_str(), "r");

    if (file && boost::filesystem::file_size(pathLog) > 10 * 1000000)
    {
        // Restart the file with some of the end
        std::vector <char> vch(200000,0);
        fseek(file, -((long)vch.size()), SEEK_END);
        int nBytes = fread(begin_ptr(vch), 1, vch.size(), file);
        fclose(file);

        file = fopen(pathLog.string().c_str(), "w");
        if (file)
        {
            fwrite(begin_ptr(vch), 1, nBytes, file);
            fclose(file);
        }
    }
    else if (file != NULL)
        fclose(file);
}

void edcRunCommand(const std::string& strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr)
        edcLogPrintf("edcRunCommand error: system(%s) returned %d\n", strCommand, nErr);
}

boost::filesystem::path edcGetDefaultDataDir()
{
    namespace fs = boost::filesystem;

    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Equibit
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Equibit
    // Mac: ~/Library/Application Support/Equibit
    // Unix: ~/.equibit
#ifdef WIN32
    // Windows
    return GetSpecialFolderPath(CSIDL_APPDATA) / "Equibit";
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    return pathRet / "Library/Application Support/Equibit";
#else
    // Unix
    return pathRet / ".equibit";
#endif
#endif
}

namespace
{
boost::filesystem::path pathCached;
boost::filesystem::path pathCachedNetSpecific;
CCriticalSection csPathCached;
}

void edcClearDatadirCache()
{
    pathCached = boost::filesystem::path();
    pathCachedNetSpecific = boost::filesystem::path();
}

const boost::filesystem::path & edcGetDataDir(bool fNetSpecific)
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached);

    fs::path &path = fNetSpecific ? pathCachedNetSpecific : pathCached;

    // This can be called during exceptions by edcLogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (!path.empty())
        return path;

	EDCparams & params = EDCparams::singleton();
    if (params.datadir.size() > 0 )
    {
        path = fs::system_complete( params.datadir );

    	fs::create_directories(path);

        if (!fs::is_directory(path))
        {
            path = "";
            return path;
        }
    }
    else
    {
        path = edcGetDefaultDataDir();
    }
    if (fNetSpecific)
        path /= BaseParams().DataDir();

    fs::create_directories(path);

    return path;
}

#ifndef WIN32
boost::filesystem::path edcGetPidFile()
{
	EDCparams & params = EDCparams::singleton();
    boost::filesystem::path pathPidFile( params.pid );

    if (!pathPidFile.is_complete()) 
		pathPidFile = edcGetDataDir() / pathPidFile;
    return pathPidFile;
}
#endif

boost::filesystem::path edcGetConfigFile()
{
    EDCparams & params = EDCparams::singleton();

    boost::filesystem::path pathConfigFile( params.conf );

    if (!pathConfigFile.is_complete())
        pathConfigFile = edcGetDataDir(false) / pathConfigFile;

    return pathConfigFile;
}

