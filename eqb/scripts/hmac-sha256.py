#!/usr/bin/env python
# Generate test data for crypto_tests/hmac_sha3_testvectors


import hashlib
import hmac

def TestHMACSHA256(key, message, expected):
    m = hmac.new(bytearray.fromhex(key), bytearray.fromhex(message), hashlib.sha256)
    result = m.hexdigest()
    print(key, message)
    print(expected)
    print(result, result == expected)
    print()

TestHMACSHA256("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
               "4869205468657265",
               "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
TestHMACSHA256("4a656665",
               "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
               "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
TestHMACSHA256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
               "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
               "dddddddddddddddddddddddddddddddddddd",
               "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
TestHMACSHA256("0102030405060708090a0b0c0d0e0f10111213141516171819",
               "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
               "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
               "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
TestHMACSHA256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaa",
               "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
               "65204b6579202d2048617368204b6579204669727374",
               "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
TestHMACSHA256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaa",
               "5468697320697320612074657374207573696e672061206c6172676572207468"
               "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
               "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
               "647320746f20626520686173686564206265666f7265206265696e6720757365"
               "642062792074686520484d414320616c676f726974686d2e",
               "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")
#// Test case with key length 63 bytes.
TestHMACSHA256("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
               "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566",
               "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
               "9de4b546756c83516720a4ad7fe7bdbeac4298c6fdd82b15f895a6d10b0769a6")
#// Test case with key length 64 bytes.
TestHMACSHA256("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
               "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665",
               "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
               "528c609a4c9254c274585334946b7c2661bad8f1fc406b20f6892478d19163dd")
#// Test case with key length 65 bytes.
TestHMACSHA256("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
               "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
               "4a",
               "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
               "d06af337f359a2330deffb8e3cbe4b5b7aa8ca1f208528cdbd245d5dc63c4483")