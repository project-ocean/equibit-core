# -----------------------------------------------------------------
# Configuration file with thridparty Berkley libraries
# -----------------------------------------------------------------

set (BERKLEY_DB_ROOT "${THIRDPARTY_DIRECTORY}/berkleydb/db.source")

if (MSVC)

    set (BERKLEY_DB_INCLUDE_DIR "${BERKLEY_DB_ROOT}/build_windows")

    set (BERKLEY_DB_LIBRARIES
        debug "${BERKLEY_DB_ROOT}/build_windows/x64/Debug_static/libdb48sd.lib"
        optimized "${BERKLEY_DB_ROOT}/build_windows/x64/Release_static/libdb48s.lib"
        )

endif()
