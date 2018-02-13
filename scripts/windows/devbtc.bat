@echo off

call btcr.bat

devenv %PROJECT_BUILD%/%PROJECT_SOLUTION%.sln
