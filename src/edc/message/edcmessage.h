// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <time.h>
#include "pubkey.h"
#include "serialize.h"


class CDataStream;
class CWallet;


// User Messages are messages created by users for the purpose of communicating 
// with other users
//
// All user messages will have the format:
//
// USER_MSG:type:timestamp:sender-address:nonce:message-type-specific-data
//
class CUserMessage
{
public:
    CUserMessage();
    virtual ~CUserMessage() {}

    virtual std::string vtag() const = 0;
    virtual std::string desc() const = 0;

    // Hash of message
    virtual uint256 GetHash() const = 0;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        if (ser_action.ForRead())
        {
            time_t  sec;
            long    nsec;

            READWRITE(sec);
            READWRITE(nsec);

            timestamp_.tv_sec = sec;
            timestamp_.tv_nsec = nsec;
        }
        else
        {
            time_t  sec = timestamp_.tv_sec;
            long    nsec = timestamp_.tv_nsec;

            READWRITE(sec);
            READWRITE(nsec);
        }

        READWRITE(senderPK_);
        if (ser_action.ForRead())
        {
            senderAddr_ = senderPK_.GetID();
        }
        READWRITE(nonce_);
        READWRITE(data_);
        READWRITE(signature_);
    }

    void proofOfWork();

    /**
     * Verify that the signature is valid
     */
    virtual bool	verify() const = 0;

    virtual std::string	ToString() const;
    virtual std::string	ToJSON() const;

    virtual void process(CWallet &);

    std::string	senderAddr() const { return senderAddr_.ToString(); }
    time_t second() const { return timestamp_.tv_sec; }

    static CUserMessage	* create(const std::string & type, CDataStream &);

protected:
    struct timespec timestamp_;
    CKeyID senderAddr_;
    CPubKey senderPK_;
    uint64_t nonce_;
    std::vector<unsigned char> data_;
    std::vector<unsigned char> signature_;
};

//----------------------------------------------------------------------

// Message to a single recipient. Encrypted.
//
// Message specific data:
//
// encrypted-message-data
//
class CPeerToPeer : public CUserMessage
{
public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(*static_cast<CUserMessage *>(this));
        READWRITE(receiverAddr_);
    }

    std::string	receiverAddr() const { return receiverAddr_.ToString(); }

    virtual uint256 GetHash() const;

    static CPeerToPeer * create(const std::string & type,
                                const CKeyID & sender,
                                const CKeyID & receiver,
                                const std::string & data);

    static CPeerToPeer * create(const std::string & type,
                                const CKeyID & sender,
                                const CKeyID & receiver,
                                const std::vector<unsigned char> & data);

    virtual bool	verify() const;
    virtual std::string	ToString() const;
    virtual std::string	ToJSON() const;

protected:
    CKeyID	receiverAddr_;
};

class CPrivate : public CPeerToPeer
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CRequestWoTcertificate : public CPeerToPeer
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CVote : public CPeerToPeer
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    void extract(std::string & pollid, std::string & response, CKeyID & pAddr) const;

    static const std::string tag;
};

//----------------------------------------------------------------------

// Mesage to a specific collection of recipients
//
// Message specific data:
//
// security-id:encrypted-message-data
//
class CMulticast : public CUserMessage
{
public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(*static_cast<CUserMessage *>(this));
    }

    virtual uint256 GetHash() const;

    virtual bool	verify() const;
    virtual std::string	ToString() const;
    virtual std::string	ToJSON() const;

    static CMulticast * create(const std::string & type,
                               const CKeyID & issuer,
                               const std::string & data);
};

class CAssetPrivate : public CMulticast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CPoll : public CMulticast
{
public:
    CPoll() {}
    CPoll(const CKeyID & issuer, const std::string & data);

    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    static const std::string tag;
};

//--------------------------------------------------------------

// Message to all addresses
// Not encrypted.
//
// Message specific data:
//
// security-id:message-data
//
class CBroadcast : public CUserMessage
{
public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(*static_cast<CUserMessage *>(this));
    }

    virtual bool	verify() const;
    virtual std::string	ToString() const;
    virtual std::string	ToJSON() const;

    virtual uint256 GetHash() const;

    static CBroadcast * create(const std::string & type,
                               const CKeyID & sender,
                               const std::string & data);

    static CBroadcast * create(const std::string & type,
                               const CKeyID & sender,
                               const std::vector<unsigned char> & data);
};

class CAcquisition : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CAsk : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CAssimilation : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CBankruptcy : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CBid : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CBonusIssue : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CBonusRights : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CBuyBackProgram : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CCashDividend : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CCashStockOption : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CClassAction : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CConversionOfConvertibleBonds : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CCouponPayment : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CDelisting : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CDeMerger : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CDividendReinvestmentPlan : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CDutchAuction : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CEarlyRedemption : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CFinalRedemption : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CGeneralAnnouncement : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CInitialPublicOffering : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CLiquidation : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CLottery : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CMandatoryExchange : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CMerger : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CMergerWithElections : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CNameChange : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class COddLotTender : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class COptionalPut : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class COtherEvent : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CPartialRedemption : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CParValueChange : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CReturnOfCapital : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CReverseStockSplit : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CRightsAuction : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CRightsIssue : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CSchemeofArrangement : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CScripDividend : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CScripIssue : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CSpinoff : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CSpinOffWithElections : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CStockDividend : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CStockSplit : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CSubscriptionOffer : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CTakeover : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CTenderOffer : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CVoluntaryExchange : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CWarrantExercise : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CWarrantExpiry : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class CWarrantIssue : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;

    static const std::string tag;
};

class WoTCertificate;

class CCreateWoTcertificate : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    static const std::string tag;

    void extract(CPubKey &, CPubKey &, WoTCertificate &) const;
};

class CRevokeWoTcertificate : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    static const std::string tag;

    void extract(CPubKey &, CPubKey &, std::string &) const;
};

class CGeneralProxy : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    void extract(CKeyID &, CKeyID &) const;

    static const std::string tag;
};

class CRevokeGeneralProxy : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    void extract(CKeyID &, CKeyID &) const;

    static const std::string tag;
};

class CIssuerProxy : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    void extract(CKeyID &, CKeyID &, CKeyID &) const;

    static const std::string tag;
};

class CRevokeIssuerProxy : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    void extract(CKeyID &, CKeyID &, CKeyID &) const;

    static const std::string tag;
};

class CPollProxy : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    void extract(CKeyID &, CKeyID &, std::string &) const;

    static const std::string tag;
};

class CRevokePollProxy : public CBroadcast
{
public:
    virtual std::string vtag() const { return tag; }
    virtual std::string desc() const;
    virtual void process(CWallet &);

    void extract(CKeyID &, CKeyID &, std::string &) const;

    static const std::string tag;
};
