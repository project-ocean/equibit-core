// Copyright (c) 2016-2017 The Equibit Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pubkey.h"


class CIssuer
{

public:

    CPubKey pubKey_;
    std::string location_;
    std::string emailAddress_;
    std::string phoneNumber_;

    CIssuer(
        const std::string& loc,
        const std::string& ea,
        const std::string& pn) :
        location_(loc),
        emailAddress_(ea),
        phoneNumber_(pn)
    {
        SetNull();
    }

    CIssuer()
    {
        SetNull();
    }

    void SetNull()
    {
        pubKey_ = CPubKey();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(pubKey_);
        READWRITE(location_);
        READWRITE(emailAddress_);
        READWRITE(phoneNumber_);
    }
};
