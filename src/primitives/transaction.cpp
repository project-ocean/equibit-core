// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "base58.h"

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

const char* ToString(Currency c)
{
    switch (c)
    {
        default:  return "ERROR:Unsupported currency";
        case BTC: return "BTC";
    }
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, wotMinLevel=%d, receiptTxID=%s, payCurr=%s, issuerPubKey=%s, issuerAddr=%s, scriptPubKey=%s ...)", nValue / COIN, nValue % COIN, wotMinLevel, receiptTxID.ToString().c_str(), ::ToString(payCurr), HexStr(issuerPubKey).c_str(), (issuerAddr.IsNull() ? "" : CBitcoinAddress(issuerAddr).ToString().c_str()), HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::GetWitnessHash() const
{
    if (!HasWitness()) {
        return GetHash();
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime), hash(ComputeHash()) {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nValueOut;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = (GetTransactionWeight(*this) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].scriptWitness.ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

int64_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR -1) + ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
}

CTxOut::CTxOut(
    const CAmount& nValueIn,
    unsigned wotMinLevelIn,
    const CPubKey& issuerPubKeyIn,
    const CKeyID& issuerAddrIn,
    CScript scriptPubKeyIn) :
    nValue(nValueIn),
    wotMinLevel(wotMinLevelIn),
    payCurr(BTC),
    issuerPubKey(issuerPubKeyIn),
    issuerAddr(issuerAddrIn),
    scriptPubKey(scriptPubKeyIn)
{
}

std::string CTxIn::toJSON(const char* margin) const
{
    std::stringstream ans;

    time_t t = prevout.n;
    time_t s = nSequence;

    ans << margin << "{\"prevout\":COutPoint(" << prevout.hash.ToString().substr(0, 10) << "..," << ctime(&t) << ")"
        << ",\"scriptSig\":" << HexStr(scriptSig)
        << ",\"sequence\":" << ctime(&s)
        << "}";

    return ans.str();
}

std::string CTxOut::toJSON(const char * margin) const
{
    std::stringstream ans;

    ans << margin << "{\n"
        << margin << "\"value\":" << nValue << ",\n"
        << margin << "\"wotMinLevel\":" << wotMinLevel << ",\n"
        << margin << "\"receiptTxID\":" << receiptTxID.ToString() << ",\n"
        << margin << "\"payCurr\":" << ::ToString(payCurr) << ",\n"
        << margin << "\"issuerPubKey\":" << HexStr(issuerPubKey) << ",\n"
        << margin << "\"issuerAddr\":"
        << (issuerAddr.IsNull() ? "" : CBitcoinAddress(issuerAddr).ToString()) << ",\n"
        << margin << "\"scriptPubKey\":" << HexStr(scriptPubKey) << ",\n"
        << margin << "}";

    return ans.str();
}

std::string CTransaction::toJSON(const char* margin) const
{
    std::stringstream ans;

    ans << margin << "{\n";

    std::string innerMargin = margin;
    innerMargin += " ";

    time_t t = nLockTime;

    ans << innerMargin << "\"lockTime\":" << ctime(&t) << ",\n";
    ans << innerMargin << "\"txIn\": [\n";

    auto ii = vin.begin();
    auto ie = vin.end();

    bool first = true;

    std::string inner2Margin = innerMargin + " ";

    while (ii != ie)
    {
        if (!first)
            ans << ", ";
        else
            first = false;

        ans << ii->toJSON(inner2Margin.c_str());
        ++ii;
    }

    ans << innerMargin << "],\n";

    ans << innerMargin << "\"txOut\": [\n";

    auto oi = vout.begin();
    auto oe = vout.end();

    first = true;

    while (oi != oe)
    {
        if (!first)
            ans << ", ";
        else
            first = false;

        ans << oi->toJSON(inner2Margin.c_str());

        ++oi;
    }

    ans << innerMargin << "]\n";

    ans << margin << "}\n";

    return ans.str();
}
