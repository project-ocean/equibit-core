// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/rpc/edcprotocol.h"
#include "edc/edcparams.h"

#include "random.h"
#include "tinyformat.h"
#include "edc/edcutil.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "version.h"

#include <stdint.h>
#include <fstream>


using namespace std;


/** Username used when cookie authentication is in use (arbitrary, only for
 * recognizability in debugging/logging purposes)
 */
static const std::string COOKIEAUTH_USER = "__cookie__";

/** Default name for auth cookie file */
static const std::string COOKIEAUTH_FILE = ".cookie";

boost::filesystem::path edcGetAuthCookieFile()
{
	EDCparams & params = EDCparams::singleton();
    boost::filesystem::path path(params.rpccookiefile);

    if (!path.is_complete()) 
		path = edcGetDataDir() / path;

    return path;
}

bool edcGenerateAuthCookie(std::string *cookie_out)
{
    unsigned char rand_pwd[32];
    GetRandBytes(rand_pwd, 32);
    std::string cookie = COOKIEAUTH_USER + ":" + EncodeBase64(&rand_pwd[0],32);

    /** the umask determines what permissions are used to create this file -
     * these are set to 077 in init.cpp unless overridden with -sysperms.
     */
    std::ofstream file;
    boost::filesystem::path filepath = edcGetAuthCookieFile();
    file.open(filepath.string().c_str());

    if (!file.is_open()) 
	{
        edcLogPrintf("Unable to open cookie authentication file %s for "
			"writing\n", filepath.string());
        return false;
    }

    file << cookie;
    file.close();
    edcLogPrintf("Generated RPC authentication cookie %s\n", filepath.string());

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

bool edcGetAuthCookie(std::string *cookie_out)
{
    std::ifstream file;
    std::string cookie;

    boost::filesystem::path filepath = edcGetAuthCookieFile();
    file.open(filepath.string().c_str());

    if (!file.is_open())
        return false;

    std::getline(file, cookie);
    file.close();

    if (cookie_out)
        *cookie_out = cookie;

    return true;
}

void edcDeleteAuthCookie()
{
    try 
	{
        boost::filesystem::remove(edcGetAuthCookieFile());
    } 
	catch (const boost::filesystem::filesystem_error& e) 
	{
        edcLogPrintf("%s: Unable to remove random auth cookie file: %s\n", 
			__func__, e.what());
    }
}

