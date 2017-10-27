# -----------------------------------------------------
# Configuration file (src)
# -----------------------------------------------------

set (TARGET_NAME src)

set (source_files
    .clang-format
    Makefile.am
    Makefile.bench.include
    Makefile.leveldb.include
    Makefile.qt.include
    Makefile.qttest.include
    Makefile.test.include
    )

include_directories(
    "${CMAKE_CURRENT_LIST_DIR}"
    "${Boost_INCLUDE_DIRS}"
    "${GMP_INCLUDE_DIR}"
    "${LIBEVENT_INCLUDE_DIR}"
    "${OPENSSL_INCLUDE_DIR}"
    "${BERKLEY_DB_INCLUDE_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/univalue/include"
    "${CMAKE_CURRENT_LIST_DIR}/secp256k1/include"
    "${CMAKE_CURRENT_LIST_DIR}/secp256k1"
    "${CMAKE_CURRENT_LIST_DIR}/leveldb/helpers/memenv"
    "${CMAKE_CURRENT_LIST_DIR}/leveldb/include"
    "${CMAKE_CURRENT_LIST_DIR}/leveldb"
    )

add_custom_target(${TARGET_NAME} SOURCES ${source_files})

tuneup_target(${TARGET_NAME})

add_subdirectory(univalue)
add_subdirectory(leveldb)
add_subdirectory(secp256k1)

#
# The targets below were constructed from src/Makefile.am
#

set (BITCOIN_CORE_H
    addrdb.h
    addrman.h
    base58.h
    bloom.h
    blockencodings.h
    chain.h
    chainparams.h
    chainparamsbase.h
    chainparamsseeds.h
    checkpoints.h
    checkqueue.h
    clientversion.h
    coins.h
    compat.h
    compat/byteswap.h
    compat/endian.h
    compat/sanity.h
    compressor.h
    consensus/consensus.h
    core_io.h
    core_memusage.h
    cuckoocache.h
    httprpc.h
    httpserver.h
    indirectmap.h
    init.h
    key.h
    keystore.h
    dbwrapper.h
    limitedmap.h
    memusage.h
    merkleblock.h
    miner.h
    net.h
    net_processing.h
    netaddress.h
    netbase.h
    netmessagemaker.h
    noui.h
    policy/fees.h
    policy/policy.h
    policy/rbf.h
    pow.h
    protocol.h
    random.h
    reverselock.h
    rpc/client.h
    rpc/protocol.h
    rpc/server.h
    rpc/register.h
    scheduler.h
    script/sigcache.h
    script/sign.h
    script/standard.h
    script/ismine.h
    streams.h
    support/allocators/secure.h
    support/allocators/zeroafterfree.h
    support/cleanse.h
    support/events.h
    support/lockedpool.h
    sync.h
    threadsafety.h
    threadinterrupt.h
    timedata.h
    torcontrol.h
    txdb.h
    txmempool.h
    ui_interface.h
    undo.h
    util.h
    utilmoneystr.h
    utiltime.h
    validation.h
    validationinterface.h
    versionbits.h
    wallet/coincontrol.h
    wallet/crypter.h
    wallet/db.h
    wallet/rpcwallet.h
    wallet/wallet.h
    wallet/walletdb.h
    warnings.h
    zmq/zmqabstractnotifier.h
    zmq/zmqconfig.h
    zmq/zmqnotificationinterface.h
    zmq/zmqpublishnotifier.h
    )

set (libbitcoin_server_a_SOURCES
    addrman.cpp
    addrdb.cpp
    bloom.cpp
    blockencodings.cpp
    chain.cpp
    checkpoints.cpp
    httprpc.cpp
    httpserver.cpp
    init.cpp
    dbwrapper.cpp
    merkleblock.cpp
    miner.cpp
    net.cpp
    net_processing.cpp
    noui.cpp
    policy/fees.cpp
    policy/policy.cpp
    pow.cpp
    rest.cpp
    rpc/blockchain.cpp
    rpc/mining.cpp
    rpc/misc.cpp
    rpc/net.cpp
    rpc/rawtransaction.cpp
    rpc/server.cpp
    script/sigcache.cpp
    script/ismine.cpp
    timedata.cpp
    torcontrol.cpp
    txdb.cpp
    txmempool.cpp
    ui_interface.cpp
    validation.cpp
    validationinterface.cpp
    versionbits.cpp
    )

set (libbitcoin_zmq_a_SOURCES
    zmq/zmqabstractnotifier.cpp
    zmq/zmqnotificationinterface.cpp
    zmq/zmqpublishnotifier.cpp
    )

set (libbitcoin_wallet_a_SOURCES
    wallet/crypter.cpp
    wallet/db.cpp
    wallet/rpcdump.cpp
    wallet/rpcwallet.cpp
    wallet/wallet.cpp
    wallet/walletdb.cpp
    policy/rbf.cpp
)

set (crypto_libbitcoin_crypto_a_SOURCES
    crypto/aes.cpp
    crypto/aes.h
    crypto/common.h
    crypto/hmac_sha256.cpp
    crypto/hmac_sha256.h
    crypto/hmac_sha512.cpp
    crypto/hmac_sha512.h
    crypto/ripemd160.cpp
    crypto/ripemd160.h
    crypto/sha1.cpp
    crypto/sha1.h
    crypto/sha256.cpp
    crypto/sha256.h
    crypto/sha512.cpp
    crypto/sha512.h
    edc/sha3/align.h
    edc/sha3/brg_endian.h
    edc/sha3/KeccakHash.cpp
    edc/sha3/KeccakHash.h
    edc/sha3/KeccakP-1600-64.macros
    edc/sha3/KeccakP-1600-opt64.cpp
    edc/sha3/KeccakP-1600-opt64-config.h
    edc/sha3/KeccakP-1600-SnP.h
    edc/sha3/KeccakP-1600-unrolling.macros
    edc/sha3/KeccakSponge.inc
    edc/sha3/KeccakSponge-common.h
    edc/sha3/KeccakSpongeWidth1600.cpp
    edc/sha3/KeccakSpongeWidth1600.h
    edc/sha3/SimpleFIPS202.cpp
    edc/sha3/SimpleFIPS202.h
    edc/sha3/SnP-Relaned.h
    )

set (libbitcoin_consensus_a_SOURCES
    amount.h
    arith_uint256.cpp
    arith_uint256.h
    consensus/merkle.cpp
    consensus/merkle.h
    consensus/params.h
    consensus/validation.h
    hash.cpp
    hash.h
    prevector.h
    primitives/block.cpp
    primitives/block.h
    primitives/transaction.cpp
    primitives/transaction.h
    pubkey.cpp
    pubkey.h
    script/bitcoinconsensus.cpp
    script/interpreter.cpp
    script/interpreter.h
    script/script.cpp
    script/script.h
    script/script_error.cpp
    script/script_error.h
    serialize.h
    tinyformat.h
    uint256.cpp
    uint256.h
    utilstrencodings.cpp
    utilstrencodings.h
    version.h
    )

set (libbitcoin_common_a_SOURCES
    amount.cpp
    base58.cpp
    chainparams.cpp
    coins.cpp
    compressor.cpp
    core_read.cpp
    core_write.cpp
    key.cpp
    keystore.cpp
    netaddress.cpp
    netbase.cpp
    protocol.cpp
    scheduler.cpp
    script/sign.cpp
    script/standard.cpp
    warnings.cpp
    )

set (libbitcoin_util_a_SOURCES
    support/lockedpool.cpp
    chainparamsbase.cpp
    clientversion.cpp
    compat/glibc_sanity.cpp
    compat/glibcxx_sanity.cpp
    compat/strnlen.cpp
    random.cpp
    rpc/protocol.cpp
    support/cleanse.cpp
    sync.cpp
    threadinterrupt.cpp
    util.cpp
    utilmoneystr.cpp
    utilstrencodings.cpp
    utiltime.cpp
    )

set (libbitcoin_cli_a_SOURCES
    rpc/client.cpp
    )

set (equibitd_SOURCES
    bitcoind.cpp
    )

set (bitcoin_cli_SOURCES
    bitcoin-cli.cpp
    )

set (TARGET_NAME libbitcoin_headers)
add_custom_target(${TARGET_NAME} SOURCES ${BITCOIN_CORE_H})
tuneup_target(${TARGET_NAME})

set (TARGET_NAME libbitcoin_server)
add_library (${TARGET_NAME} STATIC ${libbitcoin_server_a_SOURCES})
install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)
tuneup_target(${TARGET_NAME})

if(0)
set (TARGET_NAME libbitcoin_zmq)
add_library (${TARGET_NAME} STATIC ${libbitcoin_zmq_a_SOURCES})
install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)
tuneup_target(${TARGET_NAME})
endif()

set (TARGET_NAME libbitcoin_wallet)
add_library (${TARGET_NAME} STATIC ${libbitcoin_wallet_a_SOURCES})
install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)
tuneup_target(${TARGET_NAME})

set (TARGET_NAME libbitcoin_crypto)
add_library (${TARGET_NAME} STATIC ${crypto_libbitcoin_crypto_a_SOURCES})
install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)
tuneup_target(${TARGET_NAME})

set (TARGET_NAME libbitcoin_consensus)
add_library (${TARGET_NAME} STATIC ${libbitcoin_consensus_a_SOURCES})
install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)
tuneup_target(${TARGET_NAME})

set (TARGET_NAME libbitcoin_common)
add_library (${TARGET_NAME} STATIC ${libbitcoin_common_a_SOURCES})
install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)
tuneup_target(${TARGET_NAME})

set (TARGET_NAME libbitcoin_util)
add_library (${TARGET_NAME} STATIC ${libbitcoin_util_a_SOURCES})
install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)
tuneup_target(${TARGET_NAME})

set (TARGET_NAME libbitcoin_cli)
add_library (${TARGET_NAME} STATIC ${libbitcoin_cli_a_SOURCES})
install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)
tuneup_target(${TARGET_NAME})

set (TARGET_NAME equibit_server)
add_executable(${TARGET_NAME} ${equibitd_SOURCES})
install (TARGETS ${TARGET_NAME} RUNTIME DESTINATION bin)
tuneup_target(${TARGET_NAME})

target_link_libraries (${TARGET_NAME}
    ${Boost_LIBRARIES}
    ${BERKLEY_DB_LIBRARIES}
    ${LIBEVENT_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    "ws2_32.lib"
    "Shlwapi.lib"
    "Crypt32.lib"
    libbitcoin_server
    libbitcoin_common
    libunivalue
    libbitcoin_util
    libbitcoin_wallet
    libbitcoin_consensus
    libbitcoin_crypto
    libleveldb
    libsecp256k1
    )

set (TARGET_NAME equibit_client)
add_executable(${TARGET_NAME} ${bitcoin_cli_SOURCES})
install (TARGETS ${TARGET_NAME} RUNTIME DESTINATION bin)
tuneup_target(${TARGET_NAME})

target_link_libraries (${TARGET_NAME}
    ${Boost_LIBRARIES}
    ${LIBEVENT_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    "ws2_32.lib"
    "Crypt32.lib"
    libbitcoin_cli
    libunivalue
    libbitcoin_util
    libbitcoin_crypto
    )
