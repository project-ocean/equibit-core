import hashlib
import sha3


# This is a handy script to generate a Equibit HASH160 which is RIPEMD160(SHA3(input)))

#step 1: sha256
input = ""
k = sha3.keccak_256()
k.update(input.encode('utf-8'))
s1 = k.digest();

#step 2: ripemd160 
h = hashlib.new('ripemd160')
h.update(s1)
s2 = h.hexdigest()

#print output     
print (s2)

#empty input should be 0xb472a266d0bd89c13706a4132ccfb16f7c3b9fcb