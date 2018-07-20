// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "txmempool.h"
#include "limitedmap.h"
#include "addrman.h"
#include "validation.h"
#include "net.h"
#include "wallet/db.h"
#include "versionbits.h"
#include <openssl/ssl.h>

struct event_base;


#define theApp EDCapp::singleton()

class CBlockTreeDB;
class CNode;
class CSSLNode;
class CCoinsViewCache;
class CWallet;

/**
 * The application object. It manages all global data.
 */
class EDCapp
{
public:
    static EDCapp & singleton();

    ~EDCapp();

    SSL_CTX	* sslCtx() { return sslCtx_; }

    bool initSSL(const std::string & caCert, const std::string & cert,
                 const std::string & privKey, const char * passPhrase,
                 int verDepth);

    bool sslEnabled() const { return sslEnabled_; }

private:
    EDCapp();

    EDCapp(const EDCapp &);
    EDCapp & operator = (const EDCapp &);

    bool discover_;

public:
    bool sslEnabled_;

    SSL_CTX	* sslCtx_;

};
