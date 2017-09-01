# -----------------------------------------------------
# Configuration file (univalue)
# -----------------------------------------------------

set (TARGET_NAME libunivalue)

# the target was constructed from src/uinivalue/Makefile.am
set (libunivalue_la_SOURCES
    lib/univalue.cpp
    lib/univalue_read.cpp
    lib/univalue_write.cpp
    )

add_library (${TARGET_NAME} STATIC ${libunivalue_la_SOURCES})

install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)

tuneup_target(${TARGET_NAME})
