#pragma once
#include <windows.h>
#include <iostream>

bool InjShellcodeViaCRT(int PID, BYTE* ShCode, SIZE_T size);
