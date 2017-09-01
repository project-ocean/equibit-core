# -----------------------------------------------------
# Configuration file (secp256k1)
# -----------------------------------------------------

set (TARGET_NAME libsecp256k1)

# the target was constructed from src/secp256k1/Makefile.am
set (libsecp256k1_la_SOURCES
    src/secp256k1.c
    src/modules/recovery/main_impl.h
    )

add_library (${TARGET_NAME} STATIC ${libsecp256k1_la_SOURCES})

install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)

tuneup_target(${TARGET_NAME})
