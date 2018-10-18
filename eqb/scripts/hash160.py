import hashlib
# This is a handy script to generate a Bitcoin HASH160 which is RIPEMD160(SHA256(input)))

#step 1: sha256
input = ""
h = hashlib.sha256(input.encode('utf-8'))
s1 = h.digest()

#step 2: ripemd160 
h = hashlib.new('ripemd160')
h.update(s1)
s2 = h.hexdigest()

#print output     
print (s2)

#empty input should be 0xb472a266d0bd89c13706a4132ccfb16f7c3b9fcb