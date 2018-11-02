#! python2
#
# For serialize_tests.cpp

import hashlib, struct, binascii
from sha3 import sha3_256

def reversed_hex(x):
    return binascii.hexlify(''.join(reversed(x)))
    
def dsha256(x):
    return hashlib.sha256(hashlib.sha256(x).digest()).digest()

def dsha3(x):
    return sha3_256(sha3_256(x).digest()).digest()

fhash = reversed_hex(dsha256(''.join(struct.pack('<f', x) for x in range(0,1000))))
print(fhash)
assert fhash == '8e8b4cf3e4df8b332057e3e23af42ebc663b61e0495d5e7e32d85099d7f3fe0c'

dhash = reversed_hex(dsha256(''.join(struct.pack('<d', x) for x in range(0,1000))))
print(dhash)
assert dhash == '43d0c82591953c4eafe114590d392676a01585d25b25d433557f0d7878b23f96'

fhash3 = reversed_hex(dsha3(''.join(struct.pack('<f', x) for x in range(0,1000))))
print(fhash3)
assert fhash3 == '61b079bcff9fec9de324534c4e7edd17d77013d7845165943dc91494cd1582c3'

dhash3 = reversed_hex(dsha3(''.join(struct.pack('<d', x) for x in range(0,1000))))
print(dhash3)
assert dhash3 == '9b195dc1e3fbcbc2abf9b0a25dd625b14b4a34eab8ca13b5a56b3f25852fa3f4'
