from ecc import PrivateKey
from helper import decode_base58, p2pkh_script, SIGHASH_ALL, hash160, double_sha256, encode_base58
from script import Script
from tx import TxIn, TxOut, Tx


secret2 = 16479294351**3
priv2 = PrivateKey(secret=secret2)
target_address = priv2.point.address(testnet=True)
print("to", target_address)

def KeyToAddr(privkey, prefix):
    '''Returns the address string'''
    # get the sec
    sec = privkey.point.sec(compressed=True)
    # hash160 the sec
    h160 = hash160(sec)

    raw = prefix + h160
    # checksum is first 4 bytes of double_sha256 of raw
    checksum = double_sha256(raw)[:4]
    # encode_base58 the raw + checksum
    address = encode_base58(raw+checksum)
    # return as a string, you can use .decode('ascii') to do this.

    return address.decode('ascii')
    
print('testnet ', KeyToAddr(priv2, b'\x6f'))
print('mainnet ', KeyToAddr(priv2, b'\x00'))
print('p2script', KeyToAddr(priv2, b'\x05'))
print('bip-38  ', KeyToAddr(priv2, b'\x01\x42'))
print('bip-32  ', KeyToAddr(priv2, b'\x04\x88\xB2\x1E'))
print('EQ      ', KeyToAddr(priv2, (1931).to_bytes(2, 'big')))
print('EQ      ', KeyToAddr(priv2, b'\x07\x8b'))

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')
    
def search():
    for i in range(0xffffff):
        pre = i.to_bytes(3, 'big')
        addr = KeyToAddr(priv2, pre)
        prefix = addr[:3].lower()
        if prefix == 'eqb':
            print(i, pre, addr)


for i in range(100):
    pk = PrivateKey(secret=10101+i)
    print('EQ      ', KeyToAddr(pk, b'\x01\xb5\x98'))