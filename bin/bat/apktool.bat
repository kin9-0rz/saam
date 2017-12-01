@echo off
set BAT_PATH=%~dp0
set APKTOOL_PATH=%BAT_PATH:~0,-9%\tools\apktool\

java -jar %APKTOOL_PATH%apktool.jar %*