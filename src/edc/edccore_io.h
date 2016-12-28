// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once 

#include <string>
#include <vector>
#include "core_io.h"

class CEDCBlock;
class CScript;
class CEDCTransaction;
class uint256;
class UniValue;

// core_read.cpp
CScript edcParseScript(const std::string& s);
bool DecodeHexTx(CEDCTransaction& tx, const std::string& strHexTx, bool fTryNoWitness = false);
bool DecodeHexBlk(CEDCBlock&, const std::string& strHexBlk);
uint256 edcParseHashStr(const std::string&, const std::string& strName);
std::vector<unsigned char> ParseHexUV(const UniValue& v, const std::string& strName);

// core_write.cpp
std::string edcFormatScript(const CScript& script);
std::string EncodeHexTx(const CEDCTransaction& tx);
void edcScriptPubKeyToUniv(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex);
void TxToUniv(const CEDCTransaction& tx, const uint256& hashBlock, UniValue& entry);

