from ecc import PrivateKey
from helper import decode_base58, p2pkh_script, SIGHASH_ALL
from script import Script
from tx import TxIn, TxOut, Tx

secret1 = 16479294351**6
priv1 = PrivateKey(secret=secret1)

secret2 = 16479294351**2
priv2 = PrivateKey(secret=secret2)
target_address = priv2.point.address(testnet=True)

prev_tx = bytes.fromhex('5c81b6fbbe7f3ae01541da7dafc670dbaa72536eb8fb2adbc4d0626745f46b63')
prev_index = 1
#target_address = 'miKegze5FQNCnGw6PKyqUbYUeBa4x2hFeM'
target_amount = 0.024
#change_address = 'mgdAMFSq18B5HwwyiUtseCMF7VHnZ8cKcC'
change_address = priv1.point.address(testnet=True)
change_amount = 0.0

print("from", change_address)
print("to", target_address)

# initialize inputs
tx_ins = []
# create a new tx input with prev_tx, prev_index, blank script_sig and max sequence
tx_ins.append(TxIn(
            prev_tx=prev_tx,
            prev_index=prev_index,
            script_sig=b'',
            sequence=0xffffffff,
        ))

# initialize outputs
tx_outs = []
# decode the hash160 from the target address
h160 = decode_base58(target_address)
# convert hash160 to p2pkh script
script_pubkey = p2pkh_script(h160)
# convert target amount to satoshis (multiply by 100 million)
target_satoshis = int(target_amount*100000000)
# create a new tx output for target with amount and script_pubkey
tx_outs.append(TxOut(
    amount=target_satoshis,
    script_pubkey=script_pubkey,
))
# decode the hash160 from the change address
h160 = decode_base58(change_address)
# convert hash160 to p2pkh script
script_pubkey = p2pkh_script(h160)
# convert change amount to satoshis (multiply by 100 million)
change_satoshis = int(change_amount*100000000)
# create a new tx output for target with amount and script_pubkey
tx_outs.append(TxOut(
    amount=change_satoshis,
    script_pubkey=script_pubkey,
))

# create the transaction
tx_obj = Tx(version=1, tx_ins=tx_ins, tx_outs=tx_outs, locktime=0, testnet=True)

# now sign the 0th input with the private key using SIGHASH_ALL using sign_input
tx_obj.sign_input(0, priv1, SIGHASH_ALL)

# SANITY CHECK: change address corresponds to private key
if priv1.point.address(testnet=True) != change_address:
    raise RuntimeError('Private Key does not correspond to Change Address, check priv_key and change_address')

# SANITY CHECK: output's script_pubkey is the same one as your address
if tx_ins[0].script_pubkey(testnet=True).elements[2] != decode_base58(change_address):
    raise RuntimeError('Output is not something you can spend with this private key. Check that the prev_tx and prev_index are correct')

# SANITY CHECK: fee is reasonable
if tx_obj.fee(testnet=True) > 0.05*100000000 or tx_obj.fee(testnet=True) <= 0:
    raise RuntimeError('Check that the change amount is reasonable. Fee is {}'.format(tx_obj.fee()))

# serialize and hex()
print(tx_obj.serialize().hex())
