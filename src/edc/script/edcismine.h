// Copyright (c) 2016 Equibit Development Corporation
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once 

#include "script/standard.h"
#include "script/ismine.h"

#include <stdint.h>

class CKeyStore;
class CScript;

isminetype edcIsMine( const CKeyStore & keystore, const CScript & scriptPubKey );
isminetype edcIsMine( const CKeyStore & keystore, const CTxDestination & dest );
