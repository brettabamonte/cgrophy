@echo off
goto Run
:Usage
echo.Build Cgrophy from the command line. Requires the appropriate version of Microsoft Visual Studio to be installed.
echo.
echo. Available flags:
echo.  -h Display this help message
echo.  -d Set the configuration to Debug
echo.  -z Compile tests
echo.  -t Target 
echo.  -c Clean previous build artifacts 
exit /b 127

:Run
setlocal
set conf=release
set target=bin
set tests=false
set clean=false

:CheckOpts
if "%~1"=="-h" goto Usage
if "%~1"=="-d" (set conf=debug) & shift & goto CheckOpts
if "%~1"=="-c" (set clean=true) & shift & goto CheckOpts
if "%~1"=="-t" (set target=%2) & shift & shift & goto CheckOpts
if "%~1"=="-z" (set tests=true) & shift & goto CheckOpts
goto Clean

:Clean
if "%clean%"=="true" (
    pushd %target%
    del "*.o"  "*.lib"  "*.exe"  "*.dll"  "*.pdb" "*.ilk" "*.obj" "*.exp"
    popd
)

goto Build

:Build
rem c4711 - function expanded inline by compiler. don't care.
set "arguments=/Wall /wd4711 /Fo:%target%\ /Fe:%target%\ /Fd:%target%\"

if "%tests%"=="true" (
    set "arguments=%arguments% /DSHA1_TEST"
)
echo %arguments%

if "%conf%"=="release" (
    set "arguments=%arguments% /O2"
) else if "%conf%"=="debug" (
    set "arguments=%arguments% /Zi"
)

rem Finally build library
cl %arguments% /c src\sha1.c
lib /OUT:%target%\sha1.lib %target%\sha1.obj

rem Build executable with entry-point that can run tests
if "%tests%"=="true" (
    cl %arguments% src\sha1.c
)
