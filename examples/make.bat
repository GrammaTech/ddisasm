@ECHO OFF
REM NMake wrapper that initializes the required x86 or x64 VS build environment.
REM Usage:  SET TARGET_ARCH=x86
REM         ..\makes.bat
REM         ..\makes.bat clean

IF NOT DEFINED TARGET_ARCH (
    SET TARGET_ARCH=x64
)

IF "%VSCMD_ARG_TGT_ARCH%" NEQ "%TARGET_ARCH%" (
    @CALL "%VCINSTALLDIR%\Auxiliary\Build\vcvarsall.bat" %TARGET_ARCH%
)

nmake %*
