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
    scripts/cmake.create.solution.linux.sh
    scripts/cmake.create.solution.VisualStudio.bat
    scripts/project.build.VisualStudio.bat
    scripts/project.set.variables.bat
    scripts/VisualStudio.set.variables.bat
    )

add_custom_target(${TARGET_NAME} SOURCES ${source_files})

tuneup_target(${TARGET_NAME})
