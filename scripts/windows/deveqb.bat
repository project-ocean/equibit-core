@echo off

call eqbr.bat

devenv %PROJECT_BUILD%/%PROJECT_SOLUTION%.sln
