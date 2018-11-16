#!/usr/bin/env python3

'''
for Bitcoin TestNet/MainNet, compressed/uncompressed. 
Input: 64-symbol string representing Hex integer, or it will generate a random number.

Examples:

λ python make_privateKey_from_number_BTC.py 0000000000000000000000000000000000000000000000000000000000000001
Private Key Compressed   TestNet:     b'ef00000000000000000000000000000000000000000000000000000000000000010184e38d1f'
Private Key Compressed   TestNet B58: b'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA'
Private Key Compressed   MainNet:     b'800000000000000000000000000000000000000000000000000000000000000001014671fc3f'
Private Key Compressed   MainNet B58: b'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
Private Key Uncompressed TestNet:     b'ef000000000000000000000000000000000000000000000000000000000000000140df3cbd'
Private Key Uncompressed TestNet B58: b'91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx'
Private Key Uncompressed MainNet:     b'800000000000000000000000000000000000000000000000000000000000000001a85aa87e'
Private Key Uncompressed MainNet B58: b'5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf'

λ python make_privateKey_from_number_BTC.py
Private Key Compressed   TestNet:     b'ef3d66cd078c8533fddcbb6d5c210c0278b65ae9a7c0a3d7cf43e50567153e7e8d016d6aaaa6'
Private Key Compressed   TestNet B58: b'cPe4LF6jQCjour7Jwra2subCvbD6i1nLyNPiNyMeUDWhzvXcURZX'
Private Key Compressed   MainNet:     b'803d66cd078c8533fddcbb6d5c210c0278b65ae9a7c0a3d7cf43e50567153e7e8d01a426d1ce'
Private Key Compressed   MainNet B58: b'KyH4sL6sy93YkQe3ZSkuWb69JMuh3ZgeuLFFGYu8y6rhkBUNdg7f'
Private Key Uncompressed TestNet:     b'ef3d66cd078c8533fddcbb6d5c210c0278b65ae9a7c0a3d7cf43e50567153e7e8da63310bb'
Private Key Uncompressed TestNet B58: b'923xap9YowmbC4spZpUsitnp7FYjysUVYMFfNk8PzNQx4EAhhz2'
Private Key Uncompressed MainNet:     b'803d66cd078c8533fddcbb6d5c210c0278b65ae9a7c0a3d7cf43e50567153e7e8dd1f632d3'
Private Key Uncompressed MainNet B58: b'5JHL15L1DihTE1NXwUaxrJErTbC2phwJCQPiJ7mtedfuHDgYgVx'
'''

import sys
import hashlib
import base58check
import codecs
import ecdsa
import secrets

def checkSum(x_bytearray):
	return codecs.encode(hashlib.new('sha256', (hashlib.new('sha256', codecs.decode(x_bytearray, 'hex')).digest())).digest(), 'hex')[0:8]

def encode58(int_byteString):
	return base58check.b58encode(codecs.decode(int_byteString, 'hex'))

def generateRandomKey():
	bits = secrets.randbits(256)
	return hex(bits)[2:]

privateKey_value = sys.argv[1] if len(sys.argv) > 1 else generateRandomKey()
for (keyType, cmpByte) in [("Compressed", b'01'), ("Uncompressed", b'')]:
	privateKeyTn_hex = b'ef' + privateKey_value.encode('utf-8') + cmpByte + checkSum(b'ef' + privateKey_value.encode('utf-8') + cmpByte)
	privateKeyMn_hex = b'80' + privateKey_value.encode('utf-8') + cmpByte + checkSum(b'80' + privateKey_value.encode('utf-8') + cmpByte)
	print("Private Key {:12} TestNet:     {}".format(keyType, privateKeyTn_hex))
	print("Private Key {:12} TestNet B58: {}".format(keyType, encode58(privateKeyTn_hex)))
	print("Private Key {:12} MainNet:     {}".format(keyType, privateKeyMn_hex))
	print("Private Key {:12} MainNet B58: {}".format(keyType, encode58(privateKeyMn_hex)))
