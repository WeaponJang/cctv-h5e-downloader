@echo off && cd /d "%~dp0"
chcp 65001
cls
windres -i version.rc -O coff -o version_res.o
if errorlevel 1 (echo 资源编译失败 && pause & exit /b 1)
g++ -std=c++20 -O2 -municode -flto -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -fmerge-all-constants -s -Wl,--gc-sections -march=native -static -o dec.exe cctv_h5e_decrypt.cpp version_res.o
if errorlevel 1 (echo 编译失败 && pause & exit /b 1)
del version_res.o>nul
echo. 编译完成
dir /n/b *.exe
call dec
pause>nul