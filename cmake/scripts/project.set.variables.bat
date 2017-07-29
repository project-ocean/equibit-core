REM Project paths
SET PROJECT_DRIVE=%CD:~0,2%
SET PROJECT_SOURCE=%CD%\..\..
SET PROJECT_SOLUTION=%PROJECT_SOURCE%\..\equibit-core.solution

call :ABSOLUTE_PATH    PROJECT_SOURCE       %PROJECT_SOURCE%
call :ABSOLUTE_PATH    PROJECT_SOLUTION     %PROJECT_SOLUTION%

exit /b

REM Get an absolute path from a relative one
:ABSOLUTE_PATH
SET %1=%~f2
exit /b
