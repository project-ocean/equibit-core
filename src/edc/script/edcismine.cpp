// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcismine.h"

#include "key.h"
#include "keystore.h"
#include "script/script.h"
#include "script/standard.h"
#include "edc/script/edcsign.h"
#ifdef USE_HSM
#include "edc/wallet/edcwallet.h"
#endif


#include <boost/foreach.hpp>

using namespace std;

typedef vector<unsigned char> valtype;

namespace
{

bool edcHaveKey(const CKeyStore & keystore, const CKeyID & keyID)
{
	if (keystore.HaveKey(keyID))
		return true;
#ifdef USE_HSM
	const CEDCWallet * wallet = dynamic_cast<const CEDCWallet *>(&keystore);
	if( wallet )
	{
		std::string hsmID;
		if( wallet->GetHSMKey( keyID, hsmID ) )
			return true;
	}
#endif
	return false;
}

unsigned int edcHaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH(const valtype& pubkey, pubkeys)
    {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (edcHaveKey(keystore, keyID))
            ++nResult;
    }
    return nResult;
}

}

isminetype edcIsMine(const CKeyStore &keystore, const CTxDestination& dest)
{
    CScript script = GetScriptForDestination(dest);
    return edcIsMine(keystore, script);
}

isminetype edcIsMine(const CKeyStore &keystore, const CScript& scriptPubKey)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions)) 
	{
        if (keystore.HaveWatchOnly(scriptPubKey))
            return ISMINE_WATCH_UNSOLVABLE;
        return ISMINE_NO;
    }

    CKeyID keyID;
    switch (whichType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        break;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (edcHaveKey( keystore, keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_PUBKEYHASH:
	case TX_WITNESS_V0_KEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (edcHaveKey( keystore, keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_SCRIPTHASH:
    {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) 
		{
            isminetype ret = edcIsMine(keystore, subscript);
            if (ret == ISMINE_SPENDABLE)
                return ret;
        }
        break;
    }
    case TX_WITNESS_V0_SCRIPTHASH:
    {
        uint160 hash;
        CRIPEMD160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(hash.begin());
        CScriptID scriptID = CScriptID(hash);
        CScript subscript;

        if (keystore.GetCScript(scriptID, subscript)) 
		{
            isminetype ret = edcIsMine(keystore, subscript);
            if (ret == ISMINE_SPENDABLE)
                return ret;
        }
        break;
    }
    case TX_MULTISIG:
    {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (edcHaveKeys(keys, keystore) == keys.size())
            return ISMINE_SPENDABLE;
        break;
    }
    }

    if (keystore.HaveWatchOnly(scriptPubKey)) 
	{
        // TODO: This could be optimized some by doing some work after the above solver
		SignatureData sigs;
        return edcProduceSignature(DummySignatureCreator(&keystore), scriptPubKey, sigs) ? ISMINE_WATCH_SOLVABLE : ISMINE_WATCH_UNSOLVABLE;
    }
    return ISMINE_NO;
}
