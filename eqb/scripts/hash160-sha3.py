import hashlib
import sha3


# This is a handy script to generate a Equibit HASH160 which is RIPEMD160(SHA3(input)))

#step 1: sha256
input = ""
k = hashlib.new('sha3_256')
k.update(input.encode('utf-8'))
s1 = k.digest();

#step 2: ripemd160 
h = hashlib.new('ripemd160')
h.update(s1)
s2 = h.hexdigest()

#print output     
print (s2)

#empty input should be 0xb0a2c9108b9cff7f0f686fef1d2ecbd5f1999972