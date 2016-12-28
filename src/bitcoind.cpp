// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "chainparams.h"
#include "clientversion.h"
#include "rpc/server.h"
#include "init.h"
#include "edc/edcinit.h"		// EDC
#include "noui.h"
#include "edc/edcnoui.h"		// EDC
#include "scheduler.h"
#include "util.h"
#include "httpserver.h"
#include "httprpc.h"
#include "utilstrencodings.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <stdio.h>
#include <termios.h>

/* Introduction text for doxygen: */

/*! \mainpage Developer documentation
 *
 * \section intro_sec Introduction
 *
 * This is the developer documentation of the reference client for an experimental new digital currency called Bitcoin (https://www.bitcoin.org/),
 * which enables instant payments to anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *
 * The software is a community-driven open source project, released under the MIT license.
 *
 * \section Navigation
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 */

void WaitForShutdown(boost::thread_group* threadGroup, boost::thread_group * edcThreadGroup )
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown)
    {
        MilliSleep(200);
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
// EDC BEGIN
        edcInterrupt(*edcThreadGroup);
        edcThreadGroup->join_all();
// EDC END
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
bool AppInit(int argc, char* argv[])
{
    boost::thread_group threadGroup;
// EDC BEGIN
    boost::thread_group edcThreadGroup;
// EDC END
    CScheduler scheduler;

    bool fRet = false;

    //
    // Parameters
    //
    // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
    ParseParameters(argc, argv);

    // Process help and version before taking care about datadir
// EDC BEGIN
    if (mapArgs.count("-?") || mapArgs.count("-h") ||  mapArgs.count("-help") || mapArgs.count("-version") || mapArgs.count("-eb_help") || mapArgs.count("-eb_version"))
// EDC END
    {
        std::string strUsage = strprintf(_("%s Daemon"), _(PACKAGE_NAME)) + " " + _("version") + " " + FormatFullVersion() + "\n";

// EDC BEGIN
        if (mapArgs.count("-version") || mapArgs.count("-eb_version"))
// EDC END
        {
            strUsage += FormatParagraph(LicenseInfo());
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  bitcoind [options]                     " + strprintf(_("Start %s Daemon"), _(PACKAGE_NAME)) + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND);
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return false;
    }

// EDC BEGIN
	const int MAX_PP = 100;
	char passPhrase[MAX_PP+1];
// EDC END

    try
    {
        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }
        try
        {
            ReadConfigFile(mapArgs, mapMultiArgs);
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
        try {
            SelectParams(ChainNameFromCommandLine());
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
            return false;
        }

        // Command-line RPC
        bool fCommandLine = false;
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "bitcoin:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            fprintf(stderr, "Error: There is no RPC client functionality in bitcoind anymore. Use the bitcoin-cli utility instead.\n");
            exit(1);
        }

// EDC BEGIN
		// If a SSL private key file is specified, then get the pass phrase
		if( mapArgs.count( "-eb_privkey" ) > 0 )
		{
			fputs( "Enter private key pass phrase:", stdout );

			/* Turn echoing off and fail if we can’t. */
			struct termios old;
			if (tcgetattr (fileno (stdin), &old) != 0)
				return -1;
			struct termios noEcho = old;
  			noEcho.c_lflag &= ~ECHO;

			if (tcsetattr (fileno (stdin), TCSAFLUSH, &noEcho ) != 0)
   		 		return -1;

			/* Read the password. */
			char * ptr = fgets( passPhrase, MAX_PP, stdin);

			/* Restore terminal. */
			(void) tcsetattr (fileno (stdin), TCSAFLUSH, &old);

			fputc('\n', stdout );

			if( ptr == passPhrase )
			{
				// Remove carriage return
				passPhrase[strlen(passPhrase)-1]=0;
			}
			else
				fputs( "\nNo pass phrase. Secure, intra-node communications "
					"has been disabled\n", stdout );
		}
// EDC END

#ifndef WIN32
        if (GetBoolArg("-daemon", false))
        {
            fprintf(stdout, "Bitcoin server starting\n");

            // Daemonize
            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }
            if (pid > 0) // Parent process, pid is child process id
            {
                return true;
            }
            // Child process falls through to rest of initialization

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        SoftSetBoolArg("-server", true);

        // Set this early so that parameter interactions go to console
        InitLogging();
        InitParameterInteraction();
        fRet = AppInit2(threadGroup, scheduler);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

// EDC BEGIN
	try
	{
		fRet = EdcAppInit( edcThreadGroup, scheduler, passPhrase );
	}
	catch( const std::exception & ex )
	{
        PrintExceptionContinue(&ex, "EdcAppInit()");
		fRet = false;
	}
	catch( ... )
	{
        PrintExceptionContinue( NULL, "EdcAppInit()");
		fRet = false;
	}
	memset( passPhrase, 0, MAX_PP );

// EDC END

    if (!fRet)
    {
        Interrupt(threadGroup);
// EDC BEGIN
        edcInterrupt(edcThreadGroup);
// EDC END
        // threadGroup.join_all(); was left out intentionally here, because we didn't re-test all of
        // the startup-failure cases to make sure they don't result in a hang due to some
        // thread-blocking-waiting-for-another-thread-during-startup case
    } else {
        WaitForShutdown(&threadGroup, &edcThreadGroup);
    }
    Shutdown();

    return fRet;
}

int main(int argc, char* argv[])
{
    SetupEnvironment();

    // Connect bitcoind signal handlers
    noui_connect();
// EDC BEGIN
    edcnoui_connect();
// EDC END

    return (AppInit(argc, argv) ? 0 : 1);
}
