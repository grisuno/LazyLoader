#!/bin/bash
sudo apt install mingw-w64
x86_64-w64-mingw32-gcc -o loader.exe main.c -lwinhttp -lcrypt32 -lpsapi
