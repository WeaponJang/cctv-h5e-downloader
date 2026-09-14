@echo off && cd /d "%~dp0"
chcp 936
cls
g++ -std=c++17 -Os -flto -s -Wl,--gc-sections -march=native -static -o dec.exe dec_cpp17.cpp
echo. ±àÒëÍê³É
dir /n/b *.exe
call dec
pause>nul