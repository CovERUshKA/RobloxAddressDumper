#include "FileWriter.hpp"

namespace FileWriter {
	HANDLE hFile;

	BOOL Write(LPCVOID lpBuffer, DWORD dwLength)
	{
		BOOL bRet;
		DWORD dwBytesWritten;

		bRet = FALSE;

		if (!WriteFile(hFile, lpBuffer, dwLength, &dwBytesWritten, 0))
			goto end;

		if (dwLength != dwBytesWritten)
			goto end;

		bRet = TRUE;
	end:

		return bRet;
	}

	BOOL Write(const char* chData)
	{
		return Write(chData, strlen(chData));
	}

	BOOL Close()
	{
		return CloseHandle(hFile);
	}

	BOOL Open(const char* chName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes)
	{
		BOOL bRet;

		bRet = FALSE;

		hFile = CreateFileA(chName, dwDesiredAccess, dwShareMode, 0, dwCreationDisposition, dwFlagsAndAttributes, 0);
		if (hFile == INVALID_HANDLE_VALUE)
			goto end;

		bRet = TRUE;
	end:

		return bRet;
	}
}