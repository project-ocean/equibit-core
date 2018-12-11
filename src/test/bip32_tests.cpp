// Copyright (c) 2013-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <base58.h>
#include <key.h>
#include <uint256.h>
#include <util.h>
#include <utilstrencodings.h>
#include <test/test_bitcoin.h>

#include <string>
#include <vector>

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    explicit TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.push_back(TestDerivation());
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

#ifdef BUILD_BTC

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
     "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
     0x80000000)
    ("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
     "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
     1)
    ("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
     "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
     0x80000002)
    ("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
     "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
     2)
    ("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
     "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
     1000000000)
    ("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
     "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
     "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
     0)
    ("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
     "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
     0xFFFFFFFF)
    ("xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
     "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
     1)
    ("xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
     "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
     0xFFFFFFFE)
    ("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
     "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
     2)
    ("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
     "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
     0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    ("xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
     "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
      0x80000000)
    ("xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
     "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
      0);

#else  // BUILD_EQB

// EQB_TODO Generate the test data independently

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("xpub661MyMwAqRbcGX6igyVeB748CxUT3KkFLFeLACZpVMCkCgVAPSC113nC7BcPB9XYSusEchKUhun7tLE1uSvNMiQxTHXotyBzXMzsiu2fMaU",
     "xprv9s21ZrQH143K432Fawxdoy7Pevdxds2Py2ijMpACw1fmKtA1qtskTFTiFw4CcCuxKWUujfGsWYvFr1GDKqbERErAiY37GrSRS7xoB2k1b2z",
     0x80000000)
    ("xpub68UBKmzZiq6Neaj7bhkV4o4JVTNWxAL9ueHDJYF2QTakeedvY6tGmztiTUADpwa5x1USj3S3SBkX7Kj7GjqrPQ1c2tSuULrMPBS2W8az74e",
     "xprv9uUpvGTftTY5S6eeVgDUhf7ZwRY2YhcJYRMcW9qQr83mmrJmzZa2ECaEcC6tnw9JUBi3i3H2NGKXkaNZtXjynR35BK5rJFn2qE3Smpa8i2P",
     1)
    ("xpub6BJKZV1xdbbSwYvPBUKeb6aM48BWVFyaHK6pZgEC9RwuaXMP9yNw2Vn5dQFyHo1TBAusoDs5dPLpNcWTLpMgSv89D7LG5Mn4qiw233Faghf",
     "xprv9xJy9yV4oE39j4qv5SneDxdcW6M25oFiv6BDmHpab6Qvhj2EcS4gUhTbn77nVfWpWBbtEVdk15UcidJmKiTZjtTrnN6LCvas85G5Fx6NrH7",
     0x80000002)
    ("xpub6BfXRwG5dgJv113zbpSZKMcWMJTNapmgrzSw1t7akpdvngBbRZjRGYL3vi5EE8Lk8k6VvyaxrEHDqCiZdqfyxQosF4zz9xSKz3TiURD35Ki",
     "xprv9xgB2RjBoJkcnWyXVnuYxDfmoGctBN3qVmXLDVhyCV6wusrSt2RAik1a5R2864CbPo8NFTCp9hb9QxyPXc2ntxx5dQsKLqodHLbSPrL7P1c",
     2)
    ("xpub6Dh2UAm5FWQV1BtnRWQakKh1cM62ZLG4Udpe6Gx8PDhT7XrvSBunLCFHknrQPE1qKEnUKTzNeSQuFLzQKisTXE99Ub1vDxVjGsbFyXjnG2t",
     "xprv9zhg4fEBR8rBnhpKKUsaPBkH4KFY9sYD7Qu3HtYWptAUEjXmtebXnPvouZ9484qH2kYKfNXo7BJusZSEkQEUP3CLfN3JDB5ShHyJvbE2dXi",
     1000000000)
    ("xpub6G7N3xCh9wrbff8MbdupFh9X4Q6qRHHJnFLLRYgcQMouMsGbEVS8VLXRuGNCETygc25xHC7nHKS4Ph8jGfGzaKKLUZBHPiJ7gktuXGDVkfH",
     "xprvA381eSfoKaJJTB3tVcNotZCnWNGM1pZTR2QjdAGzr2GvV4wSgx7swYCx3y7ZLvg6x4BH9ZbhNRwG462TpKbJ1HyitUrQPBJg459boK2ey9G",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("xpub661MyMwAqRbcFicanfPjizCD5AHzEX5zXPtoxwYSGx3P5vRoS4dQsyVMkn9x68JUyYxkEtxzZc1uVettMrgxz1QAPD3kYcdPAwduiiEbxv6",
     "xprv9s21ZrQH143K3EY7gdrjMrFUX8TVq4N9AAyDAZ8picWQD86etXKALBAsuUNBcmej1baPDTwXraQ51tVfL74wd8S5xJoCCTSqvas3YdXrKNZ",
     0)
    ("xpub68oaZV5XjxMXCHL1QnFPJZ1MG22RsRdrjwEckFiYyLZW67vQHWtvjY7xEEui5dbTbUX3vWcjaKFpSQNXRkgXN2Kg5HScGdy4TPsiu3HWwjM",
     "xprv9upE9yYduaoDyoFYJkiNwR4chzBwTxv1NiK1wsJwR12XDKbFjyagBjoUNyrXXTs1j4X6kzoyBmR9y8vQfZh1hhtu1MBsqyx7qxSdZMCgF7g",
     0xFFFFFFFF)
    ("xpub6ARYwz46ofHCCvu3eLogFyxEM4hTucbziNm36RRrfnrLP1JQeLNoiVCrfN27Mjw3YvxRX7biPBWubwfGsqbvaVemVugfmpbTXmEz8ec93wr",
     "xprv9wSCYUXCyHitzSpaYKGftr1Vo2ryW9t9M9qSJ32F7TKMWCyG6o4ZAgtNp6aPHkK632ceV1dFyiBm5m6Ndyhj7eSLyDyAQbFgbB11iapzVrp",
     1)
    ("xpub6CXXBVoFDkMoVahf3uTFfLXy59j7PWiYHt9w2EKZzQZs9bFtSgmh7DUTnNXKEWtsa9TdEhtfaXYfv2pqW7oPCgEXLQTmzVHdV8stw8Fc9M5",
     "xprv9yYAmzGMPNoWH6dBwsvFJCbEX7tcz3zgvfELDquxS52tGnvju9TSZR9yw7jMwMaRvFiLAMZ1K2nLumX7HwrePHkgZzBVNamFKqPDrAxCd7J",
     0xFFFFFFFE)
    ("xpub6FQuE1qLv2g4ngZwhMLiNRJ7XH4Yca2dzJqxjtQqFYRa82Ngmcm6j2Ett6DnXVXNNWtoS5EkqHVNmiqAESjyWXfiRWs1eNyUWi47aVThKfc",
     "xprvA2RYpWJT5f7maCVUbKoi1HMNyFE4D7Jnd5vMwW1DhCtbFE3YE5SrBDvR2pvPjhUQgM9eW2hovLR42jGvtrGkA8FTLRoDmaKNBvabAeaRHyb",
     2)
    ("xpub6GrWpFeJybS3t3rxxegHXPNPpnRDxJtZKEkpzTvUVGLkn75Vef2j8bKXQZRe4aq4hVgVhSr9rtdvXXkayPnRAVuf4zFeEutcWwv8pUMQYHb",
     "xprvA3sAQk7R9DskfZnVrd9HAFRfGkajYrAhx1qEC5WrvvomuJkM77iUao13ZGZg7cBSHuF91AxuEdzmejEFn4KdvCAzh6W3tnHgeEU471LTK3D",
     0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    ("xpub661MyMwAqRbcH67oyNT8SMJBZp8sovtbjs8k555MCy9r5ihLQSCJBJstFiqTzN5Ek6EAgJNDLWaMXbwiVU7aGfyykF6qYqnxJpvP5EUZ2io",
     "xprv9s21ZrQH143K4c3LsLv85DMT1nJPQUAkNeD9GgfjedcsCvNBrtt3dWZQQTokDHLQv1NKeid3yoJCdk2hCATJjvhrM5DjyK332pU12zYU32M",
    0x80000000)
    ("xpub69aqk6TAsLPaR9QG9k31njketbWD6RZVHQ7FRNJwFLAqyUN6EUZvByGnnx6CKUq5P7oaUPmCETDkh7zheWgm6wWjxmtNtdeN7czfLsTDGYQ",
     "xprv9vbVLavH2xqHCfKo3iW1RbovLZfigxqdvBBecyuKgzds6g2wgwFfeAxJwfGJoA41HW2A14JZfv7vboP74HjrBMDFwqLJaJ2wz5ADM13YGYA",
     0);

#endif // END_BUILD

void RunTest(const TestVector &test) {
    std::vector<unsigned char> seed = ParseHex(test.strHexMaster);
    CExtKey key;
    CExtPubKey pubkey;
    key.SetMaster(seed.data(), seed.size());
    pubkey = key.Neuter();
    for (const TestDerivation &derive : test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        CBitcoinExtKey b58key; b58key.SetKey(key);
        BOOST_CHECK(b58key.ToString() == derive.prv);

        CBitcoinExtKey b58keyDecodeCheck(derive.prv);
        CExtKey checkKey = b58keyDecodeCheck.GetKey();
#ifdef BUILD_BTC
        assert(checkKey == key); //ensure a base58 decoded key also matches
#else  // BUILD_EQB
        BOOST_CHECK(checkKey == key); //ensure a base58 decoded key also matches
#endif // END_BUILD

        // Test public key
        CBitcoinExtPubKey b58pubkey; b58pubkey.SetKey(pubkey);
        BOOST_CHECK(b58pubkey.ToString() == derive.pub);

        CBitcoinExtPubKey b58PubkeyDecodeCheck(derive.pub);
        CExtPubKey checkPubKey = b58PubkeyDecodeCheck.GetKey();
#ifdef BUILD_BTC
        assert(checkPubKey == pubkey); //ensure a base58 decoded pubkey also matches
#else  // BUILD_EQB
        BOOST_CHECK(checkPubKey == pubkey); //ensure a base58 decoded pubkey also matches
#endif // END_BUILD

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;

        CDataStream ssPub(SER_DISK, CLIENT_VERSION);
        ssPub << pubkeyNew;
        BOOST_CHECK(ssPub.size() == 75);

        CDataStream ssPriv(SER_DISK, CLIENT_VERSION);
        ssPriv << keyNew;
        BOOST_CHECK(ssPriv.size() == 75);

        CExtPubKey pubCheck;
        CExtKey privCheck;
        ssPub >> pubCheck;
        ssPriv >> privCheck;

        BOOST_CHECK(pubCheck == pubkeyNew);
        BOOST_CHECK(privCheck == keyNew);
    }
}

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
#ifdef EQB_BREAK_TEST
    BOOST_ERROR("TEST DISABLED!");
#endif
    // EQB_TODO generate new test data
    // RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
#ifdef EQB_BREAK_TEST
    BOOST_ERROR("TEST DISABLED!");
#endif
    // EQB_TODO generate new test data
    // RunTest(test2);
}

BOOST_AUTO_TEST_CASE(bip32_test3) {
#ifdef EQB_BREAK_TEST
    BOOST_ERROR("TEST DISABLED!");
#endif
    // EQB_TODO generate new test data
    // RunTest(test3);
}

BOOST_AUTO_TEST_SUITE_END()
