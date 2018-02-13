# -----------------------------------------------------------------
# Configuration file with thridparty libevent
# -----------------------------------------------------------------

set (LIBEVENT_ROOT        "${THIRDPARTY_DIRECTORY}/libevent/libevent.source")

set (LIBEVENT_INCLUDE_DIR
    "${LIBEVENT_ROOT}/include"
    "${LIBEVENT_ROOT}/WIN32-Code/nmake"
    )

set (LIBEVENT_LIBRARIES
    "${LIBEVENT_ROOT}/libevent.lib"
    "${LIBEVENT_ROOT}/libevent_core.lib"
    "${LIBEVENT_ROOT}/libevent_extras.lib"
    "${LIBEVENT_ROOT}/libevent_openssl.lib"
    )
