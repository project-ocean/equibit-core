// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "protocol.h"

/**
 * Equibit protocol message types. When adding new message types, don't forget
 * to update allNetMessageTypes in edcprotocol.cpp.
 */
namespace NetMsgType {

/**
 * The User messages are directed at end users. Examples include all forms
 * of corporate actions and responses.
 */
extern const char *USER;
};

/* Get a vector of all valid message types (see above) */
const std::vector<std::string> & edcgetAllNetMessageTypes();
