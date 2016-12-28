// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once 

#include "netbase.h"

bool edcSetProxy(enum Network net, const proxyType &addrProxy);
bool edcGetProxy(enum Network net, proxyType &proxyInfoOut);
bool edcIsProxy(const CNetAddr &addr);
bool edcSetNameProxy(const proxyType &addrProxy);
bool edcHaveNameProxy();

bool edcConnectSocket(const CService &addr, SOCKET& hSocketRet, int nTimeout, bool *outProxyConnectionFailed = 0);
bool edcConnectSocketByName(CService &addr, SOCKET& hSocketRet, const char *pszDest, int portDefault, int nTimeout, bool *outProxyConnectionFailed = 0);
