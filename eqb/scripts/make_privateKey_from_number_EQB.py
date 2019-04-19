#!/usr/bin/env python3

'''
for OCEAN TestNet/MainNet, compressed/uncompressed. 
Input: 64-symbol string representing Hex integer, or it will generate a random number.

Examples:

λ python make_privateKey_from_number_OCN.py 0000000000000000000000000000000000000000000000000000000000000001
Private Key Compressed   TestNet:     b'ef000000000000000000000000000000000000000000000000000000000000000101fcab5f16'
Private Key Compressed   TestNet B58: b'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87Jceaw6xD'
Private Key Compressed   MainNet:     b'8000000000000000000000000000000000000000000000000000000000000000010156d8a6ad'
Private Key Compressed   MainNet B58: b'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVi767W'
Private Key Uncompressed TestNet:     b'ef0000000000000000000000000000000000000000000000000000000000000001b3fbe242'
Private Key Uncompressed TestNet B58: b'91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwpWyxMF'
Private Key Uncompressed MainNet:     b'8000000000000000000000000000000000000000000000000000000000000000011dfb883d'
Private Key Uncompressed MainNet B58: b'5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAj5Zf8G'

λ python make_privateKey_from_number_OCN.py
Private Key Compressed   TestNet:     b'ef229435dcdf98abea2a3684c6c7b9a7fc045caf2e8a980e3eb75870acd9af2b27010a67b29b'
Private Key Compressed   TestNet B58: b'cNjvEQUr3E6CfeMH6DuMadeoBgVJUfUWtqHtVfpuRtDYJEpfGALr'
Private Key Compressed   MainNet:     b'80229435dcdf98abea2a3684c6c7b9a7fc045caf2e8a980e3eb75870acd9af2b27016445ae95'
Private Key Compressed   MainNet B58: b'KxNvmVUzcAPwWCt1hp6EDK9jZTBtpDNppo9RPFNPvmZY3VnKWLr8'
Private Key Uncompressed TestNet:     b'ef229435dcdf98abea2a3684c6c7b9a7fc045caf2e8a980e3eb75870acd9af2b272f1aee39'
Private Key Uncompressed TestNet B58: b'91r9SEvtSRiWNtxoEsW5fS52rYbxcio7KYLEUnxG3vHtVrAmEDW'
Private Key Uncompressed MainNet:     b'80229435dcdf98abea2a3684c6c7b9a7fc045caf2e8a980e3eb75870acd9af2b2706d8623d'
Private Key Uncompressed MainNet B58: b'5J5WrW7LrCeNQqTWcXcAnqX5CtFFTZFuybUHQAbkiBYqioY3LQU'

'''

import sys
import hashlib
import base58check
import codecs
import ecdsa
import secrets

def checkSum(x_bytearray):
	return codecs.encode(hashlib.new('sha3_256', (hashlib.new('sha3_256', codecs.decode(x_bytearray, 'hex')).digest())).digest(), 'hex')[0:8]

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
