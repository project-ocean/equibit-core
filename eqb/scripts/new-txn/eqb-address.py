from ecc import PrivateKey
from helper import decode_base58, p2pkh_script, SIGHASH_ALL, hash160, double_sha256, encode_base58
from script import Script
from tx import TxIn, TxOut, Tx


secret2 = 16479294351**3
priv2 = PrivateKey(secret=secret2)

target_address = priv2.point.address(testnet=True)
# print("to", target_address)

# modify the code to not use ripmd160, instead
def KeyToSecret(privkey, prefix):
    '''Returns the address string'''
    # get the sec
    sec = privkey.point.sec(compressed=True)

    # addprefix to the secret , add 01 for compression flag
    raw = prefix + sec + bytes.fromhex('01')

    print("raw so far: {}".format(raw))

    # checksum is first 4 bytes of double_sha256 of raw
    checksum = double_sha256(raw)[:4]

    # encode_base58 the raw + checksum
    secret = encode_base58(raw+checksum)
    # return as a string, you can use .decode('ascii') to do this.

    return secret.decode('ascii')

def KeyToAddr(privkey, prefix):
    '''Returns the address string'''
    # get the sec
    sec = privkey.point.sec(compressed=True)
    # hash160 the sec
    h160 = hash160(sec)
    print(h160)
    raw = prefix + h160
    # checksum is first 4 bytes of double_sha256 of raw
    checksum = double_sha256(raw)[:4]
    # encode_base58 the raw + checksum
    address = encode_base58(raw+checksum)
    # return as a string, you can use .decode('ascii') to do this.

    return address.decode('ascii')
    
#print('testnet ', KeyToAddr(priv2, b'\x6f'))
#print('mainnet ', KeyToAddr(priv2, b'\x00'))
#print('p2script', KeyToAddr(priv2, b'\x05'))
#print('bip-38  ', KeyToAddr(priv2, b'\x01\x42'))
#print('bip-32  ', KeyToAddr(priv2, b'\x04\x88\xB2\x1E'))
#print('EQ      ', KeyToAddr(priv2, (1931).to_bytes(2, 'big')))
#print('EQ      ', KeyToAddr(priv2, b'\x07\x8b'))

print('EQ Main Pubkey Address:     ', KeyToAddr(priv2, b'\x01\xb5\xd1')) # EQa: wallet: \x01\xb5\xd1,  python: \x01\xb5\xd1, \x01\xb5\xd2
print('EQ Main Script Address:     ', KeyToAddr(priv2, b'\x01\xb5\xfc')) # EQs: wallet:\x01\xb5\xfc,   python:  \x01\xb5\xfb \x01\xb5\xfc \x01\xb5\xfd

#TODO: Once the method is updated.. update the following secret values
print('EQ Main Secret Key:     ', KeyToAddr(priv2, b'\x01\xb5\xea'))  #EQk:  wallet: 01 b5 ea.  python: \x01\xb5\xeb or  \x01\xb5\xea
print('EQ Main Secret Key comp.:     ', KeyToAddr(priv2, b'\x04\xb5\xd6'))  # #EQc:  wallet: x04\xb5\xd6,  python: x04\xb5\xd6, x04\xb5\xd7

print('EQ Test Pubkey Address:     ', KeyToAddr(priv2, b'\x03\x5e\x5d'))  # TQa: wallet: \x03\x5e\x5d, python: \x03\x5e\x5d, \x03\x5e\x5e,
print('EQ Test Script Address:     ', KeyToAddr(priv2, b'\x03\x5e\x87'))  #TQs: wallet: \x03\x5e\x87, python: \x03\x5e\x87, \x03\x5e\x88

#TODO: Once the method is updated.. update the following secret values
print('EQ Test Secret Key:     ', KeyToAddr(priv2, b'\x03\x5e\x75'))
print('EQ Test Secret Key comp.:     ', KeyToAddr(priv2, b'\x03\x5e\x63'))


# https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses#How_to_create_Bitcoin_Address
# https://en.bitcoin.it/wiki/Wallet_import_format
# https://en.bitcoin.it/wiki/List_of_address_prefixes

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')
    
def search(target, type):
    print("Searching for {}".format(target))
    for i in range(0xffffff):
        pre = i.to_bytes(3, 'big')
        if type == "key":
            addr = KeyToAddr(priv2, pre)
        if type == "secret":
            addr = KeyToSecret(priv2, pre)
        prefix = addr[:3]
        if prefix == target:
            print(i, pre, addr)
            test(pre, 20)
        if i % 100000 == 0:
            print(i)

def test(pre, n):
    for i in range(n):
        pk = PrivateKey(secret=10101+i)
        print('EQ      ', KeyToAddr(pk, pre))
        
#search('EQa', "key")