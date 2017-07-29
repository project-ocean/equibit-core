@ECHO OFF
ECHO -----------------------------------------------------
ECHO This batch file builds a solution by MS Visual Studio
ECHO -----------------------------------------------------
ECHO.


REM Project variable
SET  VISUAL_STUDIO_VERSION=2015
call VisualStudio.set.variables.bat
call project.set.variables.bat


REM Delete previous solution directory
IF exist "%PROJECT_SOLUTION_BUILD%" (
ECHO Remove an old solution build folder
rmdir /Q /S "%PROJECT_SOLUTION_BUILD%"
ECHO.
)


REM Set some MS Visual Studio variables
ECHO Initialize Visual Studio environment
ECHO.
call "%VISUAL_STUDIO%\VC\vcvarsall.bat" amd64


REM Create a solution by CMake
ECHO Build the solution with Visual Studio && ECHO.
ECHO   VISUAL_STUDIO_PLATFORM = %VISUAL_STUDIO_PLATFORM%      && ECHO.
ECHO   VISUAL_STUDIO_CMAKE    = %VISUAL_STUDIO_CMAKE%         && ECHO.
ECHO   PROJECT_SOLUTION       = %PROJECT_SOLUTION%            && ECHO.
ECHO.


REM Build the solution
%PROJECT_DRIVE%
cd "%PROJECT_SOLUTION%"
msbuild /p:Configuration=Release install.vcxproj

pause
