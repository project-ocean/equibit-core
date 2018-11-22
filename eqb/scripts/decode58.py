import base58check
    

# This script converts a Bitcoin address into its HASH160 format. 
# It first remove the first number and then base58 decode the address
	
bitcoinaddress = "1E7SGgAZFCHDnVZLuRViX3gUmxpMfdvd2o"

address = address[1:]

print("Base58 decoding {}".format(address))  
plain =  base58check.b58decode(address)

print ("The HASH160 address is: {}".format(plain.hex()))




