@echo off
REM better invocation scripts for windows from lanchon, release in public domain. thanks!
REM https://code.google.com/p/dex2jar/issues/detail?id=192

setlocal enabledelayedexpansion

set LIB=%~dp0lib

set CP=
for %%X in ("%LIB%"\*.jar) do (
    set CP=!CP!%%X;
)

"C:/Program Files/Java/jdk1.8.0_77/bin/java" -Xms512m -Xmx1024m -cp "%CP%" %*
