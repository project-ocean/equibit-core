# -----------------------------------------------------------------
# Configuration file with project global variables
# -----------------------------------------------------------------

# turn on folders usage in IDEs
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/build")
set (CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}/install")
set (THIRDPARTY_DIRECTORY "${PROJECT_SOURCE_DIR}/../thirdparty")

if (MSVC)

    set (CMAKE_DEBUG_POSTFIX "")

    set (disabled_warnings
        "/wd4456"   # warning C4456: declaration of 'xxxx' hides previous local declaration
        "/wd4244"   # warning C4244: conversion from '__int64' to 'unsigned int', possible loss of data
        "/wd4267"   # warning C4244: conversion from 'size_t'  to 'uint16_t',     possible loss of data
        "/wd4800"   # warning C4800: 'unsigned int': forcing value to bool 'true' or 'false' (performance warning)
        "/wd4804"   # warning C4804: '>>': unsafe use of type 'bool' in operation
        "/wd4273"   # warning C4273: inconsistent dll linkage
        "/wd4018"   # warning C4018: '<=': signed/unsigned mismatch
        "/wd4996"   # warning C4996: The POSIX name for this item is deprecated. Instead, use the ISO C and C++ conformant name: _strdup. See online help for details.
        "/wd4312"   # warning C4312: 'reinterpret_cast': conversion from 'int' to 'void *' of greater size
        "/wd4101"   # warning C4101: unreferenced local variable
        "/wd4146"   # warning C4146: unary minus operator applied to unsigned type, result still unsigned
        "/wd4700"   # warning C4700: uninitialized local variable used
        "/wd4005"   # warning C4005: macro redefinition
        "/wd4305"   # warning C4305: truncation from 'int' to 'bool'
        )

    string (REPLACE ";" " " disabled_warnings "${disabled_warnings}")

    if (STRICT_COMPILER)

        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /WX /W4")

    endif()

    add_definitions(-DJSON_TEST_SRC="C:/test")
    add_definitions(-DPACKAGE_NAME="PACKAGE_NAME")
    add_definitions(-DCOPYRIGHT_HOLDERS="COPYRIGHT_HOLDERS")
    add_definitions(-DCOPYRIGHT_HOLDERS_FINAL="COPYRIGHT_HOLDERS_FINAL")
    add_definitions(-DCOPYRIGHT_HOLDERS_SUBSTITUTION="COPYRIGHT_HOLDERS_SUBSTITUTION")
    add_definitions(-DHAVE_WORKING_BOOST_SLEEP_FOR)
    add_definitions(-DENABLE_WALLET=1)
    add_definitions(-DLEVELDB_PLATFORM_WINDOWS)
    add_definitions(-DENABLE_MODULE_RECOVERY)

    if(0)
    add_definitions(-DUSE_NUM_GMP -DUSE_FIELD_5X52  -DUSE_FIELD_INV_NUM     -DUSE_SCALAR_4X64 -DUSE_SCALAR_INV_NUM)
    else()
    add_definitions(-DUSE_NUM_GMP -DUSE_FIELD_10X26 -DUSE_FIELD_INV_BUILTIN -DUSE_SCALAR_8X32 -DUSE_SCALAR_INV_BUILTIN)
    endif()

    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS /MP ${disabled_warnings}")
    set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Ob2 /Oi /Ot /Oy /GL /Z7")
    set (CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /NODEFAULTLIB:libcmt.lib")
    set (CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /DEBUG /NODEFAULTLIB:libcmt.lib")
    set (CMAKE_STATIC_LINKER_FLAGS_RELEASE "${CMAKE_STATIC_LINKER_FLAGS_RELEASE} /LTCG")

else()

    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -Wconversion -Werror")
    set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")

endif()
