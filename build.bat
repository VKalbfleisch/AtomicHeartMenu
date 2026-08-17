@echo off
REM One-click build. Produces bin\AtomicHeartMenu.dll
setlocal
cd /d "%~dp0"

REM Build Tools ships CMake but puts nothing on PATH, so plain "cmake" fails on an
REM otherwise complete toolchain. Fall back to the copy inside the VS install.
set "CMAKE=cmake"
where cmake >nul 2>&1 && goto :have_cmake

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :no_cmake
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH goto :no_cmake
set "CMAKE=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not exist "%CMAKE%" goto :no_cmake
echo Using CMake from Visual Studio: %CMAKE%

:have_cmake
echo === Configuring (VS 2022, x64) ===
"%CMAKE%" -S . -B build -G "Visual Studio 17 2022" -A x64
if errorlevel 1 goto :err

echo === Building (Release) ===
"%CMAKE%" --build build --config Release
if errorlevel 1 goto :err

echo.
echo === DONE ===
echo Output: %~dp0bin\AtomicHeartMenu.dll
goto :eof

:no_cmake
echo.
echo CMake not found, and no Visual Studio 2022 install provided one.
echo Install Visual Studio 2022 (Community or Build Tools) with the
echo "Desktop development with C++" workload, which includes CMake.
exit /b 1

:err
echo.
echo BUILD FAILED - see messages above.
exit /b 1
