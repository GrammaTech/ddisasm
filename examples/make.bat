@echo off
@call "%VCINSTALLDIR%\Auxiliary\Build\vcvarsall.bat" %ARCH%

nmake %*
