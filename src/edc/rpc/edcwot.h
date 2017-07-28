// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "serialize.h"

class WoTCertificate
{
    std::string pubkey;
    std::string saddr;
    std::string oname;
    std::string ogaddr;
    std::string ophone;
    std::string oemail;
    std::string ohttp;
    std::string sname;
    std::string sgaddr;
    std::string sphone;
    std::string semail;
    std::string shttp;
    uint32_t expire;
    std::vector<unsigned char>	signature;

public:
    WoTCertificate() :expire(0) {}

    WoTCertificate(
        const std::string & _pubkey,
        const std::string & _saddr,
        const std::string & _oname,
        const std::string & _ogaddr,
        const std::string & _ophone,
        const std::string & _oemail,
        const std::string & _ohttp,
        const std::string & _sname,
        const std::string & _sgaddr,
        const std::string & _sphone,
        const std::string & _semail,
        const std::string & _shttp,
        uint32_t _expire) :
        pubkey(_pubkey),
        saddr(_saddr),
        oname(_oname),
        ogaddr(_ogaddr),
        ophone(_ophone),
        oemail(_oemail),
        ohttp(_ohttp),
        sname(_sname),
        sgaddr(_sgaddr),
        sphone(_sphone),
        semail(_semail),
        shttp(_shttp),
        expire(_expire)
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(pubkey);
        READWRITE(saddr);
        READWRITE(oname);
        READWRITE(ogaddr);
        READWRITE(ophone);
        READWRITE(oemail);
        READWRITE(ohttp);
        READWRITE(sname);
        READWRITE(sgaddr);
        READWRITE(sphone);
        READWRITE(semail);
        READWRITE(shttp);
        READWRITE(expire);
        READWRITE(signature);
    }

    void sign(CPubKey &, CPubKey &);

    std::string toJSON() const;

    uint160	GetID() const;
};
