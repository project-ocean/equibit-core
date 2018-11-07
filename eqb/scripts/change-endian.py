# This is a handy reverses the endianess of a given binary string in HEX
import sys

input  = "020000000001017c037e163f8dfee4632a8cf6c87187d3cb61224e6dae8f4b0ed0fae3a38008570000000017160014c5729e3aaacb6a160fa79949a8d7f1e5cd1fbc51feffffff0288102c040000000017a914ed649576ad657747835d116611981c90113c074387005a62020000000017a914e62a29e7d756eb30c453ae022f315619fe8ddfbb8702483045022100b40db3a574a7254d60f8e64335d9bab60ff986ad7fe1c0ad06dcfc4ba896e16002201bbf15e25b0334817baa34fd02ebe90c94af2d65226c9302a60a96e8357c0da50121034f889691dacb4b7152f42f566095a8c2cec6482d2fc0a16f87f59691e7e37824df000000"

def test():
	assert reverse("") == ""
	assert reverse("F") == "F"
	assert reverse("FF") == "FF"
	assert reverse("00FF") == "FF00"
	assert reverse("AA00FF") == "FF00AA"
	assert reverse("AB01EF") == "EF01AB"
	assert reverse("b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f1963") == "63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5"

def reverse(input):
	res = "".join(reversed([input[i:i+2] for i in range(0, len(input), 2)]))
	return res
	
if __name__ == "__main__":
	test()
	if len(sys.argv) > 1:
	  	input = sys.argv[1]
	print(reverse(input))
	
	
	