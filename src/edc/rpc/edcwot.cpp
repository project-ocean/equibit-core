// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "univalue.h"
#include "edc/edcapp.h"
#include "rpc/server.h"
#include "utilstrencodings.h"
#include "base58.h"
#include "net.h"
#include "validation.h"
#include "wallet/wallet.h"
#include "edc/message/edcmessage.h"
#include "edc/rpc/edcwot.h"


namespace
{

void addressToPubKey(
    const std::string & addr,
    CPubKey & pubkey,
    EDCapp &)
{
    CBitcoinAddress pkAddr(addr);
    if (!pkAddr.IsValid())
    {
        std::string msg = "invalid address " + addr;
        throw JSONRPCError(RPC_TYPE_ERROR, msg);
    }

    CKeyID pkeyID;
    if (!pkAddr.GetKeyID(pkeyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address of public key does not refer to key");

    if (!pwalletMain->GetPubKey(pkeyID, pubkey))
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Address of public key does not refer to key");
    }
}

}

void WoTCertificate::sign(CPubKey & pubkey, CPubKey & sPubkey)
{
    addressToPubKey(saddr, pubkey, theApp);

    // Sign the certificate
    //
    CBitcoinAddress addr(saddr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CHashWriter ss(SER_GETHASH, 0);
    ss << pubkey
        << saddr
        << oname
        << ogaddr
        << ophone
        << oemail
        << ohttp
        << sname
        << sgaddr
        << sphone
        << semail
        << shttp
        << expire;

    CKey key;

    if (pwalletMain->GetKey(keyID, key))
    {
        pwalletMain->GetPubKey(keyID, sPubkey);

        if (!key.Sign(ss.GetHash(), signature))
            throw JSONRPCError(RPC_MISC_ERROR, "Sign failed");
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not refer to key");
    }
}

char * toChar(unsigned char uc, char * out)
{
    char u = uc >> 4;
    char l = uc & 0xf;

    if (u > 9)
        out[0] = u - 10 + 'a';
    else
        out[0] = u + '0';

    if (l > 9)
        out[1] = l - 10 + 'a';
    else
        out[1] = l + '0';

    return out;
}

std::string WoTCertificate::toJSON() const
{
    std::stringstream ans;

    ans << "{"
        << "\"pubkey\": \"" << pubkey << "\""
        << ",\"saddr\": \"" << saddr << "\""
        << ",\"sname\": \"" << sname << "\""
        << ",\"sgaddr\": \"" << sgaddr << "\""
        << ",\"sphone\": \"" << sphone << "\""
        << ",\"semail\": \"" << semail << "\""
        << ",\"shttp\": \"" << shttp << "\""
        << ",\"oname\": \"" << oname << "\""
        << ",\"ogaddr\": \"" << ogaddr << "\""
        << ",\"ophone\": \"" << ophone << "\""
        << ",\"oemail\": \"" << oemail << "\""
        << ",\"ohttp\": \"" << ohttp << "\""
        << ",\"expire\": \"" << expire << "\""
        << ",\"signature\": \"";

    auto i = signature.begin();
    auto e = signature.end();

    char out[3];
    out[2] = 0;

    while (i != e)
    {
        ans << toChar(*i, out);
        ++i;
    }

    ans << "\" }";

    return ans.str();
}

class Hasher
{
    CHash160 ctx;
public:
    Hasher & write(const char *pch, size_t size)
    {
        ctx.Write((const unsigned char*)pch, size);
        return (*this);
    }
    uint160 GetHash()
    {
        uint160 result;
        ctx.Finalize((unsigned char*)&result);
        return result;
    }

    template<typename T>
    Hasher & operator<<(const T& obj)
    {
        ::Serialize(*this, obj, SER_GETHASH, PROTOCOL_VERSION);
        return (*this);
    }
};

uint160	WoTCertificate::GetID() const
{
    Hasher h;
    h << *this;
    return h.GetHash();
}

namespace
{
std::string buildJSON(
    const std::string & pubkey,
    const std::string & name,
    const std::string & gaddr,
    const std::string & phone,
    const std::string & email,
    const std::string & http,
    uint64_t expire)
{
    std::stringstream ans;

    ans << "{";
    ans << "\"pubkey\":\"" << pubkey << "\"";
    ans << ",\"name\":\"" << name << "\"";
    ans << ",\"address\":\"" << gaddr << "\"";
    ans << ",\"phone\":\"" << phone << "\"";
    ans << ",\"email\":\"" << email << "\"";
    ans << ",\"http\":\"" << http << "\"";
    ans << ",\"expire\":\"" << expire << "\"";
    ans << "}";

    return ans.str();
}

void insertStr(
    std::vector<unsigned char>::iterator & it,
    const std::string & str)
{
    uint16_t len = static_cast<uint16_t>(str.size());

    *it++ = len >> 8;
    *it++ = len & 0xf;

    auto i = str.begin();
    auto e = str.end();
    while (i != e)
    {
        *it++ = *i;
        ++i;
    }
}

}

/******************************************************************************
requestwotcertificate

    An owner of a public key is requesting another user certify his pubkey.
    Note that this solicitation is not required to create WoT certificates.
    It is simply a means for the owner of the public key to notify the
    potential signer that he wants the signer to create the certificate. If
    this message is not sent, then the signer will have to get the
    identification information by some other means.

    Parameters:

    1) Pubkey of to be certified.
    2) Address of signer
    3) Name of owner of public key
    4) Physical address of owner of public key
    5) Phone number of owner of public key
    6) email address of owner of public key
    7) http address of owner of public key
    8) Expiration time of certificate in number of blocks from current block

    Return: none

    Side effects:

    - Sends request-wot-certificate message to address of signer
******************************************************************************/

UniValue requestwotcertificate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 7 || request.params.size() > 8)
        throw std::runtime_error(
            "requestwotcertificate \"pubkey\" \"signer-address\" \"name\" \"geo-address\" \"phone#\" \"email-addr\" \"http-addr\" ( expiration )\n"
            "\nAn owner of a public key is requesting another user certify his pubkey.\n"
            "Note that this solicitation is not required to create WoT certificates.\n"
            "It is simply a means for the owner of the public key to notify the\n"
            "potential signer that he wants the signer to create the certificate. If\n"
            "this message is not sent, then the signer will have to get the\n"
            "identification information by some other means\n"
            "\nArguments:\n"
            "1. \"pubkey\"          (string, required) The public key to be certified\n"
            "2. \"signer-address\"  (string, required) Address of the signer\n"
            "3. \"name\"            (string, required) Name of the owner of public key\n"
            "4. \"geo-address\"     (string, required) Geographic address of owner of public key\n"
            "5. \"phone#\"          (string, required) Phone number of owner of public key\n"
            "6. \"email-addr\"      (string, required) email address of owner of public key\n"
            "7. \"http-addr\"       (string, required) http address of owner of public key\n"
            "8. \"expiration\"      (number, optional) Expiration time of certificate, measured in number of blocks from current block\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("requestwotcertificate", "\"39sdfd34341q5q45qdfaert2gfgrD301\" \"dvj4entdva4tqkdaadfv\" \"ACME Corp.\" \"100 Avenue Road\" \"519 435-1932\" \"\" \"\"")
            + HelpExampleRpc("requestwotcertificate", "\"39sdfd34341q5q45qdfaert2gfgrD301\" \"dvj4entdva4tqkdaadfv\" \"ACME Corp.\" \"100 Avenue Road\" \"519 435-1932\" \"\" \"\"")
        );

    std::string pubkey = request.params[0].get_str();
    std::string saddr = request.params[1].get_str();
    std::string name = request.params[2].get_str();
    std::string gaddr = request.params[3].get_str();
    std::string phone = request.params[4].get_str();
    std::string email = request.params[5].get_str();
    std::string http = request.params[6].get_str();

    uint32_t expirBlocks = 0;
    if (request.params.size() == 8)
        expirBlocks = static_cast<uint32_t>(request.params[7].get_int());

    // Convert pubkey string to CPubkey
    CPubKey pk;
    if (IsHex(pubkey))
    {
        CPubKey vchPubKey(ParseHex(pubkey));
        if (!vchPubKey.IsFullyValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + pubkey);
        pk = vchPubKey;
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + pubkey);
    }

    // Convert signer address string to bitcoin address
    CBitcoinAddress	signerAddr(saddr);

    CKeyID signerID;
    if (!signerAddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid signer address");

    if (!signerAddr.GetKeyID(signerID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid signer address");

    // Build message content from pubkey, name, gaddr, phone, email, http
    std::string data = buildJSON(pubkey, name, gaddr, phone, email, http, expirBlocks);

    // Send message
    CPeerToPeer * msg = CPeerToPeer::create(CRequestWoTcertificate::tag, pk.GetID(), signerID, data);

    g_connman->RelayUserMessage(msg, true);

    UniValue result(msg->GetHash().ToString());
    return result;
}

/******************************************************************************
getwotcertificate

    Creates a new WOT certificate

    Parameters:

    1) Pubkey of to be certified
    2) Address of signer
    3) Name of owner of public key
    4) Geographic address of owner of public key
    5) Phone number of owner of public key
    6) email address of owner of public key
    7) http address of owner of public key
    8) Name of signer
    9) Geographic address of signer
    10) Phone number of signer
    11) email address of signer
    12) http address of signer
    13) Expiration time of certificate in number of blocks from current block

    Return: None

    Side effects:

    - Creates WOT certificate. Broadcasts wot-certificate message to network
      which contains the certificate.
    - Saves the WOT certificate to the wallet
******************************************************************************/

UniValue getwotcertificate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 12 || request.params.size() > 13)
        throw std::runtime_error(
            "getwotcertificate \"pubkey\" \"address\" \"oname\" \"ogeo-addr\" \"ophone\" \"oe-mail\" \"ohttp\" \"sname\" \"sgeo-addr\" \"sphone\" \"semail\" \"shttp\" ( expire )\n"
            "\nCreates a new WOT certificate.\n"
            "\nArguments:\n"
            "1. \"address\"        (string, required) Adddres of Pubkey of to be certified\n"
            "2. \"address\"        (string, required) Address of signer\n"
            "3. \"oname\"          (string, required) Name of owner of public key\n"
            "4. \"ogeo-addr\"      (string, required) Geographic address of owner of public key\n"
            "5. \"ophone\"         (string, required) Phone number of owner of public key\n"
            "6. \"oe-mail\"        (string, required) email address of owner of public key\n"
            "7. \"ohttp\"          (string, required) http address of owner of public key\n"
            "8. \"sname\"          (string, required) Name of signer\n"
            "9. \"sgeo-addr\"      (string, required) Geographic address of signer\n"
            "10.\"sphone\"         (string, required) Phone number of signer\n"
            "11.\"semail\"         (string, required) email address of signer\n"
            "12.\"shttp\"          (string, required) http address of signer\n"
            "13.\"expire\"         (number, optional) Expiration time of certificate in number of blocks from current block\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("getwotcertificate", "\"39sdfd34341q5q45qdfaert2gfgrD301\" \"dvj4entdva4tqkdaadfv\" \"ACME Corp.\" \"100 Avenue Road\" \"519 435-1932\" \"pr@acme.com\" \"www.acme.com\" \"Western Ratings\" \"1210 Main Street\" \"\" \"\" \"www.western-ratings.com\" 5000\n")
            + HelpExampleRpc("getwotcertificate", "\"39sdfd34341q5q45qdfaert2gfgrD301\" \"dvj4entdva4tqkdaadfv\" \"ACME Corp.\" \"100 Avenue Road\" \"519 435-1932\" \"pr@acme.com\" \"www.acme.com\" \"Western Ratings\" \"1210 Main Street\" \"\" \"\" \"www.western-ratings.com\" 5000\n")
        );

    std::string pkAddrs = request.params[0].get_str();
    std::string saddr = request.params[1].get_str();
    std::string oname = request.params[2].get_str();
    std::string ogaddr = request.params[3].get_str();
    std::string ophone = request.params[4].get_str();
    std::string oemail = request.params[5].get_str();
    std::string ohttp = request.params[6].get_str();
    std::string sname = request.params[7].get_str();
    std::string sgaddr = request.params[8].get_str();
    std::string sphone = request.params[9].get_str();
    std::string semail = request.params[10].get_str();
    std::string shttp = request.params[11].get_str();

    uint32_t expire = 0;
    if (request.params.size() == 13)
        expire = static_cast<uint32_t>(request.params[7].get_int());

    CBitcoinAddress   sender(saddr);
    CKeyID senderID;
    if (!sender.GetKeyID(senderID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    WoTCertificate	cert(
        pkAddrs,
        saddr,
        oname,
        ogaddr,
        ophone,
        oemail,
        ohttp,
        sname,
        sgaddr,
        sphone,
        semail,
        shttp,
        expire);

    CPubKey pubkey;	// public key to be certified
    CPubKey sPubkey;// public key corresponding to private key that signed the certificate

    cert.sign(pubkey, sPubkey);

    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->AddWoTCertificate(pubkey, sPubkey, cert, errStr);
    }

    if (!rc)
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);

    uint16_t pkLen = static_cast<uint16_t>(pubkey.size());
    uint16_t spkLen = static_cast<uint16_t>(sPubkey.size());

    uint16_t cLen = static_cast<uint16_t>(cert.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION));

    std::vector<unsigned char> data;
    data.resize(pkLen + spkLen + cLen + sizeof(uint16_t) * 3);

    *reinterpret_cast<uint16_t *>(data.data()) = pkLen;
    *reinterpret_cast<uint16_t *>(data.data() + sizeof(uint16_t)) = spkLen;
    *reinterpret_cast<uint16_t *>(data.data() + sizeof(uint16_t) * 2) = cLen;

    auto i = data.begin() + 3 * sizeof(uint16_t);

    auto pi = pubkey.begin();
    auto pe = pubkey.end();
    while (pi != pe)
    {
        *i = *pi;

        ++i;
        ++pi;
    }

    auto si = sPubkey.begin();
    auto se = sPubkey.end();
    while (si != se)
    {
        *i = *si;

        ++i;
        ++si;
    }

    CDataStream ss(
        reinterpret_cast<const char *>(data.data() + pkLen + spkLen + sizeof(uint16_t) * 3),
        reinterpret_cast<const char *>(data.data() + data.size()),
        SER_NETWORK, PROTOCOL_VERSION);
    ss << cert;

    // Broadcast certificate to the network
    CBroadcast * msg = CBroadcast::create(CCreateWoTcertificate::tag, senderID, data);

    g_connman->RelayUserMessage(msg, true);

    UniValue result(msg->GetHash().ToString());
    return result;
}

/******************************************************************************
revokewotcertificate

    Revokes a WOT certificate

    Parameters:

    1) Public key on certificate to be revoked
    2) Public key of signer
    3) Reason for revocation

    Return: True if successful

    Side Effects

    - Broadcasts wot-certificate-revoked message to the network
    - Saves certificate revoked record to the wallet
******************************************************************************/

UniValue revokewotcertificate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "revokewotcertificate \"address\" \"sign-address\" ( \"reason\" )\n"
            "\nRevokes a WOT certificate.\n"
            "\nArguments:\n"
            "1. \"address\"      (string, required) Address of public key to be revoked\n"
            "2. \"sign-address\" (string, required) Address of public key of signer\n"
            "3. \"reason\"       (string, optional) Reason for revocation\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("revokewotcertificate", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\"")
            + HelpExampleRpc("revokewotcertificate", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\"")
        );

    std::string addr = request.params[0].get_str();
    std::string saddr = request.params[1].get_str();

    std::string reason;
    if (request.params.size() == 3)
        reason = request.params[2].get_str();

    CPubKey	pubkey;
    addressToPubKey(addr, pubkey, theApp);

    CPubKey	spubkey;
    addressToPubKey(saddr, spubkey, theApp);

    CBitcoinAddress   sender(saddr);
    CKeyID senderID;
    if (!sender.GetKeyID(senderID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->RevokeWoTCertificate(pubkey, spubkey, reason, errStr);
    }

    if (!rc)
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);

    uint16_t pkLen = static_cast<uint16_t>(pubkey.size());
    uint16_t saLen = static_cast<uint16_t>(saddr.size());
    uint16_t rLen = static_cast<uint16_t>(reason.size());

    std::vector<unsigned char> data;
    data.resize(pkLen + saLen + rLen + sizeof(uint16_t) * 3);

    *reinterpret_cast<uint16_t *>(data.data()) = pkLen;
    *reinterpret_cast<uint16_t *>(data.data() + sizeof(uint16_t)) = saLen;
    *reinterpret_cast<uint16_t *>(data.data() + sizeof(uint16_t) * 2) = rLen;

    auto i = data.begin() + 3 * sizeof(uint16_t);

    auto pi = pubkey.begin();
    auto pe = pubkey.end();
    while (pi != pe)
    {
        *i = *pi;

        ++i;
        ++pi;
    }

    auto si = saddr.begin();
    auto se = saddr.end();
    while (si != se)
    {
        *i = *si;

        ++i;
        ++si;
    }

    auto ri = reason.begin();
    auto re = reason.end();
    while (ri != re)
    {
        *i = *ri;

        ++i;
        ++ri;
    }

    // Broadcast certificate revocation to the network
    CBroadcast * msg = CBroadcast::create(CRevokeWoTcertificate::tag, senderID, data);

    g_connman->RelayUserMessage(msg, true);

    UniValue result(msg->GetHash().ToString());
    return result;
}

/******************************************************************************
deletewotcertificate

    Deletes a WOT certificate

    Parameters:

    1) Public key on certificate to be deleted
    2) Public key of signer

    Return: True if successful

    Side Effects
    Removes certificate from DB
******************************************************************************/

UniValue deletewotcertificate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "deletewotcertificate \"address\" \"sign-address\"\n"
            "\nDeletes a WOT certificate.\n"
            "\nArguments:\n"
            "1. \"address\"      (string, required) Address of public key to be revoked\n"
            "2. \"sign-address\" (string, required) Address of public key of signer\n"
            "\nResult: true or false\n"
            "\nExamples:\n"
            + HelpExampleCli("deletewotcertificate", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\"")
            + HelpExampleRpc("deletewotcertificate", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\"")
        );

    std::string addr = request.params[0].get_str();
    std::string saddr = request.params[1].get_str();

    CPubKey	pubkey;
    addressToPubKey(addr, pubkey, theApp);

    CPubKey	spubkey;
    addressToPubKey(saddr, spubkey, theApp);

    bool rc;
    std::string errStr;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        rc = pwalletMain->DeleteWoTCertificate(pubkey, spubkey, errStr);
    }

    if (!rc)
        throw JSONRPCError(RPC_TYPE_ERROR, errStr);

    UniValue result(rc);
    return result;
}

/******************************************************************************
wotchainexists

    Determines if a trust chain exists between two entities (indentified by
    their public keys).

    Parameters:

    1) Public key at end of the chain
    2) Public key at the beginning of the chain
    3) Maximum length of the chain. If this value is specified, then only
       chains whose length is less than or equal to this value will be
       accepted.

    Returns:

    Let P1 be a public key beginning of the chain. A public key P2 is a link
    to P1 if a certificate that has not expired or been revoked exists
    containing P1 that was signed by the private key corresponding to P2.

    Let the second parameter be P1 and the first parameter, Pn. If there exists
    public keys P2, ..., Pn-1 such that P1 links to P2, P2 links to P3, ...,
    Pn-1 links to Pn, then there exists a chain of length n-1 between P1 and Pn.
    If the third parameter is not specified, or if it is greater than or equal
    to n-1, then true is returned.  Otherwise, false it returned.

    Note that there may be more then one chain between P1 and Pn. All that is
    required is that one of them be short enough.

    Side Effects: None.
******************************************************************************/

UniValue wotchainexists(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "wotchainexists \"eaddr\" \"baddr\" ( maxlen )\n"
            "\nDetermines if a trust chain exists between two entities (indentified by\n"
            "their public keys).\n"
            "\nArguments:\n"
            "1. \"eaddr\"      (string, required) Address of public key at the end of the chain\n"
            "2. \"baddr\"      (string, required) Address of public key at the beginning of the chain\n"
            "3. maxlen         (number, optional) Maximum length of the chain. Defaults to 2\n"
            "\nResult: true or false\n"
            "\nExamples:\n"
            + HelpExampleCli("wotchainexists", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\" 3")
            + HelpExampleRpc("wotchainexists", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\"")
        );

    std::string eaddr = request.params[0].get_str();
    std::string baddr = request.params[1].get_str();

    uint64_t maxlen = 2;
    if (request.params.size() == 3)
        maxlen = request.params[2].get_int();

    CPubKey	epubkey;
    addressToPubKey(eaddr, epubkey, theApp);

    CPubKey	bpubkey;
    addressToPubKey(baddr, bpubkey, theApp);

    bool rc = pwalletMain->WoTchainExists(epubkey, bpubkey, maxlen);

    UniValue result(rc);
    return result;
}

namespace
{

const CRPCCommand Commands[] =
{ //  category        name                        actor (function)           okSafeMode
  //  --------------- --------------------------- -----------------------    ----------
    { "equibit",      "requestwotcertificate", &requestwotcertificate, true },
    { "equibit",      "getwotcertificate",     &getwotcertificate,     true },
    { "equibit",      "deletewotcertificate",  &deletewotcertificate,  true },
    { "equibit",      "revokewotcertificate",  &revokewotcertificate,  true },
    { "equibit",      "wotchainexits",         &wotchainexists,        true },
};

}

void RegisterWoTRPCCommands(CRPCTable & tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(Commands); vcidx++)
        tableRPC.appendCommand(Commands[vcidx].name, &Commands[vcidx]);
}
