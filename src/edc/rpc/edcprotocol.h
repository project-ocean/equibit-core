// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <list>
#include <map>
#include <stdint.h>
#include <string>
#include <boost/filesystem.hpp>

#include <univalue.h>

#include "rpc/protocol.h"

/** Get name of RPC authentication cookie file */
boost::filesystem::path edcGetAuthCookieFile();

/** Generate a new RPC authentication cookie and write it to disk */
bool edcGenerateAuthCookie(std::string *cookie_out);

/** Read the RPC authentication cookie from disk */
bool edcGetAuthCookie(std::string *cookie_out);

/** Delete RPC authentication cookie from disk */
void edcDeleteAuthCookie();
