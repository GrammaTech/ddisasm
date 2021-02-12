set ARCH
set VCINSTALLDIR

@call "%VCINSTALLDIR%\Auxiliary\Build\vcvarsall.bat" %ARCH%

nmake %*
