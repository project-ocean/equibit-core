// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <openssl/err.h>

#include "edcapp.h"
#include "net.h"
#include "util.h"

EDCapp::EDCapp() :
    sslEnabled_(false)
    , sslCtx_(NULL)
{
    //TODO: Does maxConnects_ need to take into account the bitcoin connections?
}

EDCapp::~EDCapp()
{
    if (sslCtx_)
        SSL_CTX_free(sslCtx_);
}

EDCapp & EDCapp::singleton()
{
    static EDCapp theOneAndOnly;

    return theOneAndOnly;
}

namespace
{
int password_cb(char *buf, int size, int rwflag, void *passwd)
{
    strncpy(buf, (char *)passwd, size);
    buf[size - 1] = '\0';
    return (int)(strlen(buf));
}
}

bool EDCapp::initSSL(
    const std::string & caCert,
    const std::string & cert,
    const std::string & privKey,
    const char * passPhrase,
    int verifyDepth)
{
    // Secure communications are only permited if the certificate and
    // private key files are specified
    if (caCert.size() == 0 || cert.size() == 0 || privKey.size() == 0)
    {
        LogPrintf("ERROR:CA certificate, certificate or private key file "
                  "name parameter not set. Secure communications will be disabled.\n");
        return false;
    }

    /* Load encryption & hashing algorithms for the SSL program */
    SSL_library_init();

    /* Load the error strings for SSL & CRYPTO APIs */
    SSL_load_error_strings();

    /* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
    const SSL_METHOD * meth = TLS_method();

    /* Create a SSL_CTX structure */
    sslCtx_ = SSL_CTX_new(meth);

    SSL_CTX_set_mode(sslCtx_,
                     SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_AUTO_RETRY);

    int secp256k1 = NID_secp256k1;
    SSL_CTX_set1_curves(sslCtx_, &secp256k1, 1);

    if (!sslCtx_)
    {
        int err = ERR_get_error();
        char buf[120];
        LogPrintf("ERROR:SSL CTX creation failed:%s\n", ERR_error_string(err, buf));
        return false;
    }

    /* Load the server certificate into the SSL_CTX structure */
    if (SSL_CTX_use_certificate_file(sslCtx_, cert.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        int err = ERR_get_error();
        char buf[120];
        LogPrintf("ERROR:SSL failed to load certificate file:%s\n", ERR_error_string(err, buf));
        return false;
    }

    /*Load the password for the Private Key*/
    SSL_CTX_set_default_passwd_cb_userdata(sslCtx_, const_cast<char *>(passPhrase));
    SSL_CTX_set_default_passwd_cb(sslCtx_, password_cb);

    /* Load the private-key corresponding to the server certificate */
    if (SSL_CTX_use_PrivateKey_file(sslCtx_, privKey.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        int err = ERR_get_error();
        char buf[120];
        LogPrintf("ERROR:SSL failed to load private key file:%s\n", ERR_error_string(err, buf));
        return false;
    }

    /* Check if the server certificate and private-key matches */
    if (!SSL_CTX_check_private_key(sslCtx_))
    {
        int err = ERR_get_error();
        char buf[120];
        LogPrintf("ERROR:SSL private key check failed:%s\n", ERR_error_string(err, buf));
        return false;
    }

    /* Load the RSA CA certificate into the SSL_CTX structure */
    if (!SSL_CTX_load_verify_locations(sslCtx_, caCert.c_str(), NULL))
    {
        int err = ERR_get_error();
        char buf[120];
        LogPrintf("ERROR:SSL failed to load CA certificate file:%s\n", ERR_error_string(err, buf));
        return false;
    }

    /* Set to require peer (client) certificate verification */
    SSL_CTX_set_verify(sslCtx_, SSL_VERIFY_PEER, NULL);

    /* Set the verification depth */
    SSL_CTX_set_verify_depth(sslCtx_, verifyDepth);

    sslEnabled_ = true;
    return true;
}
