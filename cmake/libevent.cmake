# -----------------------------------------------------------------
# Configuration file with thridparty libevent
# -----------------------------------------------------------------

#set (LIBEVENT_ROOT        "${THIRDPARTY_DIRECTORY}/c/libevent.source")
set (LIBEVENT_ROOT        "${THIRDPARTY_DIRECTORY}/libevent")

set (LIBEVENT_INCLUDE_DIR
    "${LIBEVENT_ROOT}/include"
    "${LIBEVENT_ROOT}/WIN32-Code/nmake"
    )

set (LIBEVENT_LIBRARIES
    "${LIBEVENT_ROOT}/lib/event.lib"
    "${LIBEVENT_ROOT}/lib/event_core.lib"
    "${LIBEVENT_ROOT}/lib/event_extra.lib"
    "${LIBEVENT_ROOT}/lib/event_openssl.lib"
    )
