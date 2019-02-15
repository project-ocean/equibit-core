#!/usr/bin/env python
# Generate test data for crypto_tests/hmac_sha3_testvectors
# consistent with http://www.wolfgang-ehrhardt.de/hmac-sha3-testvectors.html

import hashlib
import base64
import hmac

def TestHMACSHA3(key, message, expected):
    m = hmac.new(bytearray.fromhex(key), bytearray.fromhex(message), 'sha3_256')
    result = m.hexdigest()
    print(key, message)
    print(expected)
    print(result, result == expected)
    print()

TestHMACSHA3("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "4869205468657265",
    "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb")
TestHMACSHA3("4a656665",
    "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
    "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5")
TestHMACSHA3("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    "dddddddddddddddddddddddddddddddddddd",
    "84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207")
TestHMACSHA3("0102030405060708090a0b0c0d0e0f10111213141516171819",
    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    "57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7")
TestHMACSHA3("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaa",
    "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
    "65204b6579202d2048617368204b6579204669727374",
    "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b")
TestHMACSHA3("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaa",
    "5468697320697320612074657374207573696e672061206c6172676572207468"
    "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
    "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
    "647320746f20626520686173686564206265666f7265206265696e6720757365"
    "642062792074686520484d414320616c676f726974686d2e",
    "65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123")
# Test case with key length 63 bytes.
TestHMACSHA3("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
    "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566",
    "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
    "d9c45751ac95f179061fff0e8d6b76cff253c29a63165aa9f88e3aba331edac9")
# Test case with key length 64 bytes.
TestHMACSHA3("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
    "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665",
    "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
    "6c78117febd95bcf520b5cea826fdfba5d3a9ae6bda15feee9ed82fc773f0433")
# Test case with key length 65 bytes.
TestHMACSHA3("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
    "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
    "4a",
    "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
    "d032a9a31ae88c298277f44ae41394bbd0a73255a9ef585fe40795f55009b33c")
