// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/script/edcsign.h"

#include "key.h"
#include "edc/wallet/edcwallet.h"
#include "edc/policy/edcpolicy.h"
#include "edc/primitives/edctransaction.h"
#include "script/standard.h"
#include "uint256.h"
#ifdef USE_HSM
#include "edc/edcapp.h"
#include "edc/edcparams.h"
#include "Thales/interface.h"
#include <secp256k1.h>

namespace
{
secp256k1_context	* secp256k1_context_verify;

struct Verifier
{
	Verifier()
	{
		secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	}
	~Verifier()
	{
		secp256k1_context_destroy(secp256k1_context_verify);
	}
};

Verifier	verifier;

}

#endif

#include <boost/foreach.hpp>

using namespace std;

typedef std::vector<unsigned char> valtype;

EDCTransactionSignatureCreator::EDCTransactionSignatureCreator(
		  const CKeyStore * keystoreIn, 
	const CEDCTransaction * txToIn, 
			   unsigned int nInIn, 
			const CAmount & amountIn, 
						int nHashTypeIn) : 
	BaseSignatureCreator(keystoreIn), 
	txTo(txToIn), 
	nIn(nInIn), 
	nHashType(nHashTypeIn), 
	amount(amountIn), 
	checker(txTo, nIn, amountIn) 
{}

bool EDCTransactionSignatureCreator::CreateSig(
	std::vector<unsigned char> & vchSig, 
				  const CKeyID & address, 
				 const CScript & scriptCode, 
					  SigVersion sigversion) const
{
    CKey key;
    if (!keystore->GetKey(address, key))
	{
#ifdef USE_HSM
		EDCparams & params = EDCparams::singleton();

		if( params.usehsm )
		{
			const CEDCWallet * wallet = dynamic_cast<const CEDCWallet *>(keystore);

			if( wallet )
			{
				std::string hsmID;
				if( wallet && wallet->GetHSMKey(address, hsmID))
				{
					EDCapp & theApp = EDCapp::singleton();
	
   			 		uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, SIGVERSION_BASE);
   			 		if (!NFast::sign( *theApp.nfHardServer(), *theApp.nfModule(), 
					hsmID, hash.begin(), 256, vchSig))
   	     				return false;
	
					secp256k1_ecdsa_signature sig;
					memcpy( sig.data, vchSig.data(), sizeof(sig.data));

					secp256k1_ecdsa_signature_normalize( secp256k1_context_verify, &sig, &sig );
	
					vchSig.resize(72);
   			 		size_t nSigLen = 72;
	
			    	secp256k1_ecdsa_signature_serialize_der( secp256k1_context_verify, 
						(unsigned char*)&vchSig[0], &nSigLen, &sig);
				    vchSig.resize(nSigLen);
   		 			vchSig.push_back((unsigned char)nHashType);
	
					return true;
				}
			}
		}
#endif
        return false;
	}

    uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    return true;
}

namespace
{

bool edcSign1(
			  const CKeyID & address, 
const BaseSignatureCreator & creator, 
			 const CScript & scriptCode, 
	  std::vector<valtype> & ret, 
				  SigVersion sigversion)
{
    vector<unsigned char> vchSig;
    if (!creator.CreateSig(vchSig, address, scriptCode, sigversion))
        return false;
    ret.push_back(vchSig);
    return true;
}

bool edcSignN(
	 const vector<valtype> & multisigdata, 
const BaseSignatureCreator & creator, 
			 const CScript & scriptCode, 
	  std::vector<valtype> & ret, 
				  SigVersion sigversion )
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
    {
        const valtype& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (edcSign1(keyID, creator, scriptCode, ret, sigversion))
            ++nSigned;
    }
    return nSigned==nRequired;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
bool edcSignStep(
	const BaseSignatureCreator & creator, 
				 const CScript & scriptPubKey,
		  std::vector<valtype> & ret, 
					txnouttype & whichTypeRet, 
					  SigVersion sigversion)
{
    CScript scriptRet;
    uint160 h160;
    ret.clear();

    vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    CKeyID keyID;
    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return false;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        return edcSign1(keyID, creator, scriptPubKey, ret, sigversion);
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!edcSign1(keyID, creator, scriptPubKey, ret, sigversion))
            return false;
        else
        {
            CPubKey vch;
#ifndef USE_HSM
            creator.KeyStore().GetPubKey(keyID, vch);
#else
			if(!creator.KeyStore().GetPubKey(keyID, vch))
			{
				const CEDCWallet * wallet = dynamic_cast<const CEDCWallet *>(&creator.KeyStore());
				if( wallet )
				{
					wallet->GetHSMPubKey(keyID, vch);
				}
			}
#endif
            ret.push_back(ToByteVector(vch));
        }
        return true;
    case TX_SCRIPTHASH:
        if (creator.KeyStore().GetCScript(uint160(vSolutions[0]), scriptRet)) 
		{
            ret.push_back(std::vector<unsigned char>(scriptRet.begin(), scriptRet.end()));
            return true;
        }
		return false;

    case TX_MULTISIG:
        ret.push_back(valtype()); // workaround CHECKMULTISIG bug
        return (edcSignN(vSolutions, creator, scriptPubKey, ret, sigversion));

    case TX_WITNESS_V0_KEYHASH:
        ret.push_back(vSolutions[0]);
        return true;

    case TX_WITNESS_V0_SCRIPTHASH:
        CRIPEMD160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160.begin());
        if (creator.KeyStore().GetCScript(h160, scriptRet)) 	
		{
            ret.push_back(std::vector<unsigned char>(scriptRet.begin(), scriptRet.end()));
            return true;
        }
        return false;

    default:
        return false;
    }
    return false;
}

CScript PushAll(const vector<valtype>& values)
{
    CScript result;
    BOOST_FOREACH(const valtype& v, values) 
	{
        if (v.size() == 0) 
		{
            result << OP_0;
        } 
		else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) 
		{
            result << CScript::EncodeOP_N(v[0]);
        } 
		else 
		{
            result << v;
        }
    }
    return result;
}

}

bool edcProduceSignature(
	const BaseSignatureCreator & creator, 
				 const CScript & fromPubKey, 
				 SignatureData & sigdata)
{
    CScript script = fromPubKey;
    bool solved = true;
    std::vector<valtype> result;
    txnouttype whichType;

    solved = edcSignStep(creator, script, result, whichType, SIGVERSION_BASE);
    bool P2SH = false;
    CScript subscript;
    sigdata.scriptWitness.stack.clear();

    if (solved && whichType == TX_SCRIPTHASH)
    {
        // Solver returns the subscript that needs to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        script = subscript = CScript(result[0].begin(), result[0].end());
        solved = solved && edcSignStep(creator, script, result, whichType, SIGVERSION_BASE) && whichType != TX_SCRIPTHASH;
        P2SH = true;
    }
 
    if (solved && whichType == TX_WITNESS_V0_KEYHASH)
    {
        CScript witnessscript;
        witnessscript << OP_DUP << OP_HASH160 << ToByteVector(result[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
        txnouttype subType;

        solved = solved && edcSignStep(creator, witnessscript, result, subType, SIGVERSION_WITNESS_V0);
        sigdata.scriptWitness.stack = result;
        result.clear();
    }
    else if (solved && whichType == TX_WITNESS_V0_SCRIPTHASH)
    {
        CScript witnessscript(result[0].begin(), result[0].end());
        txnouttype subType;
        solved = solved && edcSignStep(creator, witnessscript, result, subType, 
			SIGVERSION_WITNESS_V0) && 
			subType != TX_SCRIPTHASH && 
			subType != TX_WITNESS_V0_SCRIPTHASH && 
			subType != TX_WITNESS_V0_KEYHASH;
        result.push_back(std::vector<unsigned char>(witnessscript.begin(), witnessscript.end()));
        sigdata.scriptWitness.stack = result;
        result.clear();
     }
 
    if (P2SH) 
	{
        result.push_back(std::vector<unsigned char>(subscript.begin(), subscript.end()));
    }
    sigdata.scriptSig = PushAll(result);

    // Test solution
	return solved && edcVerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
}

SignatureData edcDataFromTransaction(const CEDCMutableTransaction& tx, unsigned int nIn)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;

    if (tx.wit.vtxinwit.size() > nIn) 
	{
        data.scriptWitness = tx.wit.vtxinwit[nIn].scriptWitness;
    }
    return data;
}

void edcUpdateTransaction(CEDCMutableTransaction& tx, unsigned int nIn, const SignatureData& data)
{
    assert(tx.vin.size() > nIn);
    tx.vin[nIn].scriptSig = data.scriptSig;

    if (!data.scriptWitness.IsNull() || tx.wit.vtxinwit.size() > nIn) 
	{
        tx.wit.vtxinwit.resize(tx.vin.size());
        tx.wit.vtxinwit[nIn].scriptWitness = data.scriptWitness;
    }
}

bool SignSignature(
		   const CKeyStore & keystore, 
	  		 const CScript & fromPubKey, 
	CEDCMutableTransaction & txTo, 
				unsigned int nIn, 
			 const CAmount & amount,
						 int nHashType)
{
    assert(nIn < txTo.vin.size());

    CEDCTransaction txToConst(txTo);
    EDCTransactionSignatureCreator creator(&keystore, &txToConst, nIn, amount, nHashType);

    SignatureData sigdata;
    bool ret = edcProduceSignature(creator, fromPubKey, sigdata);
    edcUpdateTransaction(txTo, nIn, sigdata);

    return ret;
}

bool SignSignature(
		   const CKeyStore & keystore, 
	 const CEDCTransaction & txFrom, 
	CEDCMutableTransaction & txTo, 
				unsigned int nIn, 
						 int nHashType)
{
    assert(nIn < txTo.vin.size());
    CEDCTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CEDCTxOut& txout = txFrom.vout[txin.prevout.n];

	return SignSignature(keystore, txout.scriptPubKey, txTo, nIn, txout.nValue, nHashType);
}

static vector<valtype> CombineMultisig(
					 const CScript & scriptPubKey, 
		const BaseSignatureChecker & checker,
         	 const vector<valtype> & vSolutions,
         	 const vector<valtype> & sigs1, 
		 	 const vector<valtype> & sigs2, 
						  SigVersion sigversion)
{
    // Combine all the signatures we've got:
    set<valtype> allsigs;
    BOOST_FOREACH(const valtype& v, sigs1)
    {
        if (!v.empty())
            allsigs.insert(v);
    }
    BOOST_FOREACH(const valtype& v, sigs2)
    {
        if (!v.empty())
            allsigs.insert(v);
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys:
    assert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = vSolutions.size()-2;
    map<valtype, valtype> sigs;
    BOOST_FOREACH(const valtype& sig, allsigs)
    {
        for (unsigned int i = 0; i < nPubKeys; i++)
        {
            const valtype& pubkey = vSolutions[i+1];
            if (sigs.count(pubkey))
                continue; // Already got a sig for this pubkey

            if (checker.CheckSig(sig, pubkey, scriptPubKey, sigversion))
            {
                sigs[pubkey] = sig;
                break;
            }
        }
    }
    // Now build a merged CScript:
    unsigned int nSigsHave = 0;
	std::vector<valtype> result; result.push_back(valtype()); // pop-one-too-many workaround
    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
    {
        if (sigs.count(vSolutions[i+1]))
        {
			result.push_back(sigs[vSolutions[i+1]]);
            ++nSigsHave;
        }
    }
    // Fill any missing with OP_0:
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
		result.push_back(valtype());

    return result;
}

namespace
{

struct Stacks
{
    std::vector<valtype> script;
    std::vector<valtype> witness;

    Stacks() {}
    explicit Stacks(const std::vector<valtype>& scriptSigStack_) : 
		script(scriptSigStack_), witness() {}
    explicit Stacks(const SignatureData& data) : witness(data.scriptWitness.stack) 
	{
        EvalScript(script, data.scriptSig, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), 
			SIGVERSION_BASE);
    }

    SignatureData Output() const 
	{
        SignatureData result;
        result.scriptSig = PushAll(script);
        result.scriptWitness.stack = witness;
        return result;
    }
};

}


static Stacks edcCombineSignatures(
				 const CScript & scriptPubKey, 
	const BaseSignatureChecker & checker,
    			const txnouttype txType, 
		 const vector<valtype> & vSolutions,
						  Stacks sigs1, 
						  Stacks sigs2, 
					  SigVersion sigversion)
{
    switch (txType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.script.size() >= sigs2.script.size())
            return sigs1;
        return sigs2;
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.script.empty() || sigs1.script[0].empty())
            return sigs2;
        return sigs1;
    case TX_WITNESS_V0_KEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.witness.empty() || sigs1.witness[0].empty())
            return sigs2;
        return sigs1;
    case TX_SCRIPTHASH:
        if (sigs1.script.empty() || sigs1.script.back().empty())
            return sigs2;
        else if (sigs2.script.empty() || sigs2.script.back().empty())
            return sigs1;
        else
        {
            // Recur to combine:
			valtype spk = sigs1.script.back();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            vector<vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            
			sigs1.script.pop_back();
			sigs2.script.pop_back();
            Stacks result = edcCombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, 
				sigs2, sigversion);
            result.script.push_back(spk);
            return result;
        }
    case TX_MULTISIG:
        return Stacks(CombineMultisig(scriptPubKey, checker, vSolutions, sigs1.script, sigs2.script, sigversion));
    case TX_WITNESS_V0_SCRIPTHASH:
        if (sigs1.witness.empty() || sigs1.witness.back().empty())
            return sigs2;
        else if (sigs2.witness.empty() || sigs2.witness.back().empty())
            return sigs1;
        else
        {
            // Recur to combine:
            CScript pubKey2(sigs1.witness.back().begin(), sigs1.witness.back().end());
            txnouttype txType2;
            vector<valtype> vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.witness.pop_back();
            sigs1.script = sigs1.witness;
            sigs1.witness.clear();
            sigs2.witness.pop_back();
            sigs2.script = sigs2.witness;
            sigs2.witness.clear();
            Stacks result = edcCombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2, SIGVERSION_WITNESS_V0);
            result.witness = result.script;
            result.script.clear();
            result.witness.push_back(valtype(pubKey2.begin(), pubKey2.end()));
            return result;
        }
    default:
        return Stacks();
    }
}

SignatureData edcCombineSignatures(
				 const CScript & scriptPubKey, 
	const BaseSignatureChecker & checker,
           const SignatureData & scriptSig1, 
		   const SignatureData & scriptSig2)
{
    txnouttype txType;
    vector<vector<unsigned char> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);

	return edcCombineSignatures(scriptPubKey, checker, txType, vSolutions, Stacks(scriptSig1), 
		Stacks(scriptSig2), SIGVERSION_BASE).Output();
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker : public BaseSignatureChecker
{
public:
    DummySignatureChecker() {}

    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
    {
        return true;
    }
};
const DummySignatureChecker dummyChecker;
}
