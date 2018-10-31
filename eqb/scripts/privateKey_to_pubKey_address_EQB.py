#!/usr/bin/env python3

'''
Converts PrivateKey -> PublicKey -> PubKeyHash -> Address (legacy)
Input: Base58-encoded private key (string)

Example EQB:

λ python privateKey_to_scriptPubKey_EQB.py cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA
Base58 decoded Private Key: b'ef00000000000000000000000000000000000000000000000000000000000000010184e38d1f'
Network prefix:   b'ef'
Private Key:      b'0000000000000000000000000000000000000000000000000000000000000001'
Compression flag: b'01'
Check sum:        b'84e38d1f'
Public Key raw:   b'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
Public Key:       b'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
Public Key Hash (ripemd160 <- sha3_256): b'bd73d439ac57c49a438f609342df72f35934e912'
Addres mainnet:   b'00bd73d439ac57c49a438f609342df72f35934e912b832b64f'    B58: b'1JGjUCPP65653XPHqZ6Qdkr5H81tZ9FYVk'
Addres testnet:   b'6fbd73d439ac57c49a438f609342df72f35934e912a05ce03c'    B58: b'mxngmFUMu6XKpdruZ84nTg4Q97cbTXfUFu'
'''

import sys
import hashlib
import base58check
import codecs
import ecdsa

def public_compressed(pk):
	x = pk[0:64]
	y = int.from_bytes(codecs.decode(pk[64:128], 'hex'), byteorder='big', signed='false')
	prefix = b'02' if y % 2 == 0 else b'03'
	return prefix + x

def checkSum(pk):
	return codecs.encode(hashlib.new('sha3_256', (hashlib.new('sha3_256', codecs.decode(pk, 'hex')).digest())).digest(), 'hex')[0:8]

def encode58(int_byteString):
	return base58check.b58encode(codecs.decode(int_byteString, 'hex'))

privateKey_base58_str = sys.argv[1]
privateKey_hex_str = codecs.encode((base58check.b58decode(privateKey_base58_str)), 'hex')
print("Base58 decoded Private Key: {}".format(privateKey_hex_str))
privKey_networkPrefix = privateKey_hex_str[0:2]
privKey_crc = privateKey_hex_str[-8:]
privKey_clean = privateKey_hex_str[2:66]
privKey_compressionFlag = privateKey_hex_str[66:68] if len(privateKey_hex_str) == 76 else None
print("Network prefix:   {}".format(privKey_networkPrefix))
print("Private Key:      {}".format(privKey_clean))
print("Compression flag: {}".format(privKey_compressionFlag))
print("Check sum:        {}".format(privKey_crc))

pubKey_raw = codecs.encode(ecdsa.SigningKey.from_string(codecs.decode(privKey_clean, 'hex'), curve=ecdsa.SECP256k1).verifying_key.to_string(), 'hex')
print("Public Key raw:   {}".format(pubKey_raw))
pubKeyFull = b'04' + pubKey_raw if privKey_compressionFlag is None else public_compressed(pubKey_raw)
print("Public Key:       {}".format(pubKeyFull))
pubKey_s3_256 = codecs.encode(hashlib.new('sha3_256', codecs.decode(pubKeyFull, 'hex')).digest(), 'hex')
publicKeyHash = codecs.encode(hashlib.new('ripemd160', codecs.decode(pubKey_s3_256, 'hex')).digest(), 'hex')
print("Public Key Hash (ripemd160 <- sha3_256): {}".format(publicKeyHash))

pubKeyHash_mainnet = b'00' + publicKeyHash
pubKeyHash_testnet = b'6f' + publicKeyHash
address_main = pubKeyHash_mainnet + checkSum(pubKeyHash_mainnet)
address_test = pubKeyHash_testnet + checkSum(pubKeyHash_testnet)
print("Addres mainnet:   {}    B58: {}".format(address_main, encode58(address_main)))
print("Addres testnet:   {}    B58: {}".format(address_test, encode58(address_test)))
