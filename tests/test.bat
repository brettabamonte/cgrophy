@echo off

goto Run
:Usage
echo.Run Cgrophy test executables from the command line. Requires the appropriate version of Microsoft Visual Studio to be installed.
echo.
echo. Available flags:
echo.  -h Display this help message
echo.  -d Compile tests in debug mode
echo.  -t Target
exit /b 127

:Run
setlocal
set target=bin
set debug=false

:CheckOpts
if "%~1"=="-h" goto Usage
if "%~1"=="-d" (set debug=true) & shift & goto CheckOpts
if "%~1"=="-t" (set target=%2) & shift & shift & goto CheckOpts
goto Tests

:Tests

if "%clean%"=="true" (
    pushd %target%
    del "*.o"  "*.lib"  "*.exe"  "*.dll"  "*.pdb" "*.ilk" "*.obj" "*.exp"
    popd
)

goto Build

:Build
set "arguments=-c -z"

if "%debug%"=="true" (
    set "arguments=%arguments% -d"
)

rem build executables
echo Compiling tests
pushd ..
call "%~dp0..\build.bat" %arguments% > nul 2>&1
popd
echo Tests finished compiling

rem run tests
pushd "%~dp0..\%target%"
sha1.exe

echo.
echo.

sha256.exe

echo.
echo.

hmac.exe
