// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "addrdb.h"

/** Access to the (IP) address database (peers.dat) */
class CEDCAddrDB
{
private:
    boost::filesystem::path pathAddr;

public:
    CEDCAddrDB();
    bool Write(const CAddrMan& addr);
    bool Read(CAddrMan& addr);
       bool Read(CAddrMan& addr, CDataStream& ssPeers);
};

/** Access to the banlist database (banlist.dat) */
class CEDCBanDB
{
private:
    boost::filesystem::path pathBanlist;
public:
    CEDCBanDB();
    bool Write(const banmap_t& banSet);
    bool Read(banmap_t& banSet);
};
