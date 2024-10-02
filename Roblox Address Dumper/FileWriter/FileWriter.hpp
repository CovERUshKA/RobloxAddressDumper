#pragma once

#include <Windows.h>

namespace FileWriter
{
	BOOL Open(const char* chName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes);
	BOOL Close();

	BOOL Write(const char* chData);
	BOOL Write(LPCVOID lpBuffer, DWORD dwlength);
}