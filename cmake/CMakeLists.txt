# -------------------------------------------------------------
# A fake target with CMake modules to access them easily in IDE
# -------------------------------------------------------------

set (TARGET_NAME CMake)

set (source_files
    berkley.cmake
    boost.cmake
    globals.cmake
    gmp.cmake
    libevent.cmake
    macros.cmake
    openssl.cmake
    )

add_custom_target(${TARGET_NAME} SOURCES ${source_files})

tuneup_target(${TARGET_NAME})
