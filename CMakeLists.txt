# -----------------------------------------------------
# A main CMake configuration file for the whole project
# -----------------------------------------------------

cmake_minimum_required (VERSION 3.3)

set (CMAKE_CONFIGURATION_TYPES Debug Release CACHE STRING "Configurations" FORCE)
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")

project (equibit)

include (cmake/globals)
include (cmake/gmp)
include (cmake/macros)
include (cmake/berkley)
include (cmake/boost)
include (cmake/libevent)
include (cmake/openssl)

set (Boost_USE_STATIC_LIBS ON)
find_package(Boost COMPONENTS chrono date_time filesystem program_options thread REQUIRED)

find_package(Openssl REQUIRED)

add_subdirectory (cmake)
add_subdirectory (src)

set (TARGET_NAME root)

set (source_files
    .gitattributes
    .gitignore
    .travis.yml
    autogen.sh
    configure.ac
    CONTRIBUTING.md
    COPYING
    INSTALL.md
    libbitcoinconsensus.pc.in
    Makefile.am
    README.md
    )

add_custom_target(${TARGET_NAME} SOURCES ${source_files})

tuneup_target(${TARGET_NAME})
