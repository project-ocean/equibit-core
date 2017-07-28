// Copyright (c) 2016-2017 The Equibit Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transaction.h"
#include "utilstrencodings.h"


UniValue EquibitTxOut::to_json() const
{
    UniValue json(UniValue::VType::VOBJ);

    json.push_back(Pair("payment_currency", static_cast<uint64_t>(m_payment_currency)));
    json.push_back(Pair("payment_tx_id", HexStr(m_payment_tx_id)));
    json.push_back(Pair("payload", m_payload));

    return json;
}

bool operator == (const EquibitTxOut& a, const EquibitTxOut& b)
{
    return
        a.m_payment_currency == b.m_payment_currency &&
        a.m_payment_tx_id == b.m_payment_tx_id &&
        a.m_payload == b.m_payload;
}
