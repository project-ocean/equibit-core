@ECHO OFF
ECHO ---------------------------------------------------------------
ECHO This batch file create a Visual Studio solution for the project
ECHO ---------------------------------------------------------------
ECHO.


SET  PLATFORM=x64
SET  VISUAL_STUDIO_VERSION=2015

call VisualStudio.set.variables.bat
call project.set.variables.bat



IF not exist "%PROJECT_SOURCE%" ECHO The source "%PROJECT_SOURCE%" does not exist && pause && exit

IF exist "%PROJECT_SOLUTION%" (
ECHO Remove an old solution folder 
rmdir /Q /S "%PROJECT_SOLUTION%" 
IF exist "%PROJECT_SOLUTION%" pause && exit
ECHO.
)

IF not exist "%PROJECT_SOLUTION%" (
ECHO Create a new solution folder
mkdir "%PROJECT_SOLUTION%"
IF not exist "%PROJECT_SOLUTION%" pause && exit
ECHO.
)

ECHO Initialize Visual Studio environment
call "%VISUAL_STUDIO%\VC\vcvarsall.bat" %VISUAL_STUDIO_PLATFORM%
ECHO.

%PROJECT_DRIVE% && cd "%PROJECT_SOLUTION%"

ECHO Initialize solution with CMake && ECHO.
ECHO   VISUAL_STUDIO_PLATFORM = %VISUAL_STUDIO_PLATFORM%      && ECHO.
ECHO   VISUAL_STUDIO_CMAKE    = %VISUAL_STUDIO_CMAKE%         && ECHO.

cmake  ^
    -G "%VISUAL_STUDIO_CMAKE%" ^
    "%PROJECT_SOURCE%"
    
pause
explorer "%PROJECT_SOLUTION%"
exit /b
