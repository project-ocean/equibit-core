// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "script/sign.h"
#include "edc/script/edcinterpreter.h"

class CKeyID;
class CKeyStore;
class CScript;
class CEDCTransaction;

struct CEDCMutableTransaction;

/** A signature creator for transactions. */
class EDCTransactionSignatureCreator : public BaseSignatureCreator 
{
    const CEDCTransaction* txTo;
    unsigned int nIn;
    int nHashType;
	CAmount amount;
    const EDCTransactionSignatureChecker checker;

public:
    EDCTransactionSignatureCreator(	const CKeyStore * keyStoreIn,
							  const CEDCTransaction * txToIn, 
										 unsigned int nInIn, 
									  const CAmount & amountIn,
												  int nHashTypeIn=SIGHASH_ALL);

    const BaseSignatureChecker& Checker() const { return checker; }

    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const;
};

class EDCMutableTransactionSignatureCreator : public EDCTransactionSignatureCreator 
{
    CEDCTransaction tx;

public:
    EDCMutableTransactionSignatureCreator(
					 const CKeyStore * keystoreIn, 
		const CEDCMutableTransaction * txToIn, 
						  unsigned int nInIn, 
					   const CAmount & amount, 
								   int nHashTypeIn) : 
			EDCTransactionSignatureCreator(
				keystoreIn, &tx, nInIn, amount, nHashTypeIn), tx(*txToIn) {}
};

/** Produce a script signature using a generic signature creator. */
bool edcProduceSignature(const BaseSignatureCreator& creator, const CScript& scriptPubKey, SignatureData & sigdata);

/** Produce a script signature for a transaction. */
bool SignSignature(const CKeyStore& keystore, const CScript& fromPubKey, CEDCMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int nHashType=SIGHASH_ALL);
bool SignSignature(const CKeyStore& keystore, const CEDCTransaction& txFrom, CEDCMutableTransaction& txTo, unsigned int nIn, int nHashType);

SignatureData edcCombineSignatures( const CScript & scriptPubKey, const BaseSignatureChecker & checker, const SignatureData & scriptSig1, const SignatureData & scriptSig2);

/** Extract signature data from a transaction, and insert it. */
SignatureData edcDataFromTransaction(const CEDCMutableTransaction& tx, unsigned int nIn);
void edcUpdateTransaction(CEDCMutableTransaction& tx, unsigned int nIn, const SignatureData& data);


