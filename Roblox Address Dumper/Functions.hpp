#pragma once

#include <windows.h>
#include <stdio.h>

void GetFileVersion(LPCWSTR wchFileName)
{
	DWORD dwSize;
	DWORD dwFileVersionInfoSize;
    UINT  uiLenFileInfo = 0;

	BYTE* pbVersionInfo = NULL;
    VS_FIXEDFILEINFO* pFileInfo = NULL;

	dwSize = GetFileVersionInfoSizeW(wchFileName, &dwFileVersionInfoSize);
	if (!dwSize)
		goto end;

	pbVersionInfo = new BYTE[dwSize];

	if (!GetFileVersionInfoW(wchFileName, 0, dwSize, pbVersionInfo))
	{
		printf("Error in GetFileVersionInfo: %d\n", GetLastError());
		goto end;
	}

    if (!VerQueryValueW(pbVersionInfo, TEXT("\\"), (LPVOID*)&pFileInfo, &uiLenFileInfo))
    {
        printf("Error in VerQueryValue: %d\n", GetLastError());
        goto end;
    }

    // pFileInfo->dwFileVersionMS is usually zero. However, you should check
    // this if your version numbers seem to be wrong

    printf("File Version: %d.%d.%d.%d\n",
        HIWORD(pFileInfo->dwFileVersionMS),
        LOWORD(pFileInfo->dwFileVersionMS),
        HIWORD(pFileInfo->dwFileVersionLS),
        LOWORD(pFileInfo->dwFileVersionLS)
    );

    // pFileInfo->dwProductVersionMS is usually zero. However, you should check
    // this if your version numbers seem to be wrong.

    printf("Product Version: %d.%d.%d.%d\n",
        HIWORD(pFileInfo->dwProductVersionMS),
        LOWORD(pFileInfo->dwProductVersionMS),
        HIWORD(pFileInfo->dwProductVersionLS),
        LOWORD(pFileInfo->dwProductVersionLS)
    );

end:
    if (pbVersionInfo)
        delete[] pbVersionInfo;

	return;
}