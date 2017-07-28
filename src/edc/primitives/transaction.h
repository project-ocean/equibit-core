// Copyright (c) 2016-2017 The Equibit Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "uint256.h"
#include "serialize.h"
#include "univalue/include/univalue.h"


enum class Currency : uint32_t
{
    NONE = 0,
    BTC = 1,
};

/// @brief Equibit specific information added to an output of a transaction
class EquibitTxOut
{
public:

    Currency    m_payment_currency = Currency::NONE;
    uint256     m_payment_tx_id;
    std::string m_payload;

public:

    EquibitTxOut() = default;

public:

    UniValue to_json() const;

public:

    template <typename Stream, typename Operation> void SerializationOp(Stream& s, Operation ser_action)
    {
        uint32_t currency = static_cast<uint32_t>(m_payment_currency);

        READWRITE(currency);
        READWRITE(m_payment_tx_id);
        READWRITE(m_payload);

        m_payment_currency = static_cast<Currency>(currency);
    }

    friend bool operator == (const EquibitTxOut&, const EquibitTxOut&);
};
