#include "Dumper.hpp"

BOOL GetProcessNameById(DWORD ID, wchar_t* buf, DWORD cbBuf)
{
    PROCESSENTRY32 peProcessEntry = { NULL };
    HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    peProcessEntry.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnapshot, &peProcessEntry);
    do
    {
        if (ID == peProcessEntry.th32ProcessID)
        {
            memcpy_s(buf, MAX_PATH * 2, peProcessEntry.szExeFile, MAX_PATH * 2);
            return TRUE;
        }
    } while (Process32Next(hSnapshot, &peProcessEntry));

    CloseHandle(hSnapshot);
    return FALSE;
}

HMODULE GetModuleHandleByName(DWORD pID, const wchar_t* name)
{
    MODULEENTRY32 peModuleEntry = { NULL };
    HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE, pID);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        cout << "Unable to create shapshot" << endl;
        return FALSE;
    }

    peModuleEntry.dwSize = sizeof(MODULEENTRY32);
    Module32First(hSnapshot, &peModuleEntry);
    do
    {
        if (wcscmp(name, peModuleEntry.szModule) == NULL)
        {
            return peModuleEntry.hModule;
        }
    } while (Module32Next(hSnapshot, &peModuleEntry));

    CloseHandle(hSnapshot);
    return FALSE;
}

BOOL Compare(DWORD dwAddress, BYTE* pattern, UINT pLength, BYTE* mask)
{
    BYTE byte;

    BOOL matched = TRUE;

    for (UINT i = 0; i < pLength; i++)
    {
        if (!Dumper::ReadByte(dwAddress + i, &byte))
            return FALSE;

        if (byte != pattern[i] && (mask == NULL || mask[i] == 'x'))
        {
            matched = FALSE;
            break;
        }
        else if (byte != pattern[i] && (mask == NULL || mask[i] != '?'))
        {
            matched = FALSE;
            break;
        }
    }

    return matched;
}

BOOL strfind(char* chString, const char* chCompare)
{
	BOOL bRet = FALSE;
	DWORD dwCompareLength = strlen(chCompare);
	DWORD dwStringLength = strlen(chString);

	if (dwStringLength < dwCompareLength)
		return bRet;

	for (DWORD i = 0; i < dwStringLength - dwCompareLength + 1; i++)
		if (memcmp(chString + i, chCompare, dwCompareLength) == NULL)
			bRet = TRUE;

	return bRet;
}

namespace Dumper
{
    HANDLE hProcess;
    DWORD base;
    DWORD begin;
    DWORD end;

	DWORD dwDosHeaderAddress;
	DWORD dwNtHeaderAddress;

	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeader;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptHeader;

	ZydisDecoder decoder;
	ZydisFormatter formatter;

	BOOL Disassemble(DWORD dwAddress, Instruction* lpInstruction)
    {
		BOOL bRet;
		DWORD dwBufferLength;

		BYTE data[16];
		ZeroMemory(&data, 16);

		char* buffer;
		char* next;

		if (!dwAddress
			|| !IsValidAddress(dwAddress)
			|| !lpInstruction)
			goto end;

		ZeroMemory(lpInstruction, sizeof(Instruction));

		if (!ReadByte(dwAddress, &data, 16))
			goto end;

		if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, 16,
			lpInstruction)))
			goto end;
		
		// Format the binary instruction structure to human readable format
		char chData[256];
		ZeroMemory(chData, 256);
		ZydisFormatterFormatInstruction(&formatter, lpInstruction, chData, sizeof(chData),
			dwAddress);

		memcpy_s(lpInstruction->chData, 256, chData, 256);

		buffer = strtok_s(chData, " ", &next);

		dwBufferLength = strlen(buffer);

		if (dwBufferLength != 0
			|| dwBufferLength >= 256)
			memcpy_s(lpInstruction->chOpcode, dwBufferLength, buffer, dwBufferLength);

		//cout << lpInstruction->data << " Size - " << (int)lpInstruction->len << endl;

		bRet = TRUE;
	end:

		return bRet;
    }

    DWORD FindPattern(DWORD dwBeginAddress, DWORD dwEndAddress, const char* chPattern, DWORD cbLength, const char* chMask, int offset)
    {
        for (DWORD c = dwBeginAddress; c < (dwEndAddress - cbLength); c++)
        {
            if (Compare(c, (BYTE*)chPattern, cbLength, (BYTE*)chMask))
            {
                return (DWORD)(c + offset);
            }
        }

        return NULL;
    }

	DWORD FindPattern(const char* chPattern, DWORD cbPattern, const char* chMask, const char* chSectionName, int offset)
	{
		SectionData sectionData;

		if (!GetSectionData(chSectionName, &sectionData))
		{
			cout << "Unable to GetSectionData of " << chSectionName << endl;
			Log("Unable to GetSectionData");
			return FALSE;
		}

		return FindPattern(sectionData.dwPhysicalAddress, sectionData.dwPhysicalAddress + sectionData.dwRegionSize, chPattern, cbPattern, chMask, offset);
	}

    DWORD FindPattern(string pattern, const char* chMask, const char* chSectionName, int offset)
    {
        return FindPattern(pattern.c_str(), pattern.length(), chMask, chSectionName, offset);
    }

	BOOL FindEqualPatterns(DWORD dwBeginAddress, DWORD dwEndAddress, RESULTS* lpResults)
	{
		BOOL bRet;
		DWORD cbSize;

		BYTE* lpBuf;

		bRet = FALSE;

		if (!lpResults
			|| !dwBeginAddress
			|| !dwEndAddress
			|| dwBeginAddress >= dwEndAddress)
			goto end;

		lpResults->clear();

		cbSize = dwEndAddress - dwBeginAddress;

		lpBuf = new BYTE[cbSize];

		if (!ReadByte(dwBeginAddress, lpBuf, cbSize))
			goto end;

		for (DWORD c = begin; c != (end - cbSize); c++)
			if (Compare(c, lpBuf, cbSize, NULL))
				lpResults->push_back(c);

		bRet = TRUE;
	end:

		return bRet;
	}

    BOOL ScanPointers(DWORD dwAddress, RESULTS* lpResults)
    {
		BYTE cmd;
		DWORD dwBuf;
		BOOL bRet, bTextSection;

		SectionData sectionData;

        if (!lpResults)
            goto end;

		bRet = FALSE;

        lpResults->clear();

		if (!GetSectionData(dwAddress, &sectionData))
			goto end;

		if (memcmp(sectionData.chName, ".text", 5) == NULL)
			bTextSection = TRUE;
		else
			bTextSection = FALSE;

        for (DWORD c = begin; c != (end - 5); c++)
        {
            if (!ReadByte(c, &cmd))
                goto end;

            if (bTextSection
				&& cmd == 0xE8)
            {
                if (!ReadByte(c + 1, &dwBuf, 4))
                    goto end;

                if (c + 5 + dwBuf == dwAddress)
                    lpResults->push_back(c);
            }
			else if (cmd == 0x68)
			{
				if (!ReadByte(c + 1, &dwBuf, 4))
					goto end;

				if (dwBuf == dwAddress)
					lpResults->push_back(c);
			}
        }

        bRet = TRUE;

    end:

        return bRet;
    }

    CallConvention GetCallConvention(DWORD dwAddress)
    {
		BOOL ecx = FALSE;

		DWORD dwNextAddress;
		DWORD dwEpilogueAddress;

		Instruction instruction;

		CallConvention ccRet = CC_None;

        USHORT usRet = 0;

        if (!hProcess)
            goto end;

		dwEpilogueAddress = GetEpilogue(dwAddress);
        if (!dwEpilogueAddress)
            goto end;

		if (!GetFunctionReturn(dwAddress, &usRet))
			goto end;

        if (!usRet)
            ccRet = CC_cdecl;
        else if (usRet)
            ccRet = CC_stdcall;

		dwNextAddress = dwAddress;

		while (dwNextAddress < dwEpilogueAddress) {
			if (!Disassemble(dwNextAddress, &instruction))
				return CC_None;
		
			if (strfind(instruction.chData, ", ecx")
				|| strfind(instruction.chData, ", [ecx")
				|| strfind(instruction.chData, ", edx")
				|| strfind(instruction.chData, ", [edx")
				|| (((memcmp(instruction.chData, "cmp", 3) == NULL) && (strfind(instruction.chData, "ecx") || strfind(instruction.chData, "edx")))))
				if (!ecx)
				{
					ccRet = CC_fastcall;
					break;
				}

			if ((strfind(instruction.chData, "ecx") && memcmp(instruction.chData, "push", 4) != NULL)
				|| strfind(instruction.chData, "edx"))
				ecx = TRUE;

			dwNextAddress += instruction.length;
		}

    end:

        return ccRet;
    }

    BOOL IsPrologue(DWORD dwAddress)
    {
		BOOL bRet;

        BYTE prologue[3];
        ZeroMemory(prologue, 3);

		bRet = FALSE;

        if (!hProcess
			|| !IsValidAddress(dwAddress))
            goto end;

        if (!ReadByte(dwAddress, &prologue, 3))
            goto end;

		// push ebp
		// mov ebp, esp
		if ((memcmp(prologue, "\x55\x8B\xEC", 3) == NULL))
			bRet = TRUE;

    end:

        return bRet;
    }

    BOOL IsEpilogue(DWORD dwAddress)
    {
		BOOL bRet;

        BYTE epilogue[2];
        ZeroMemory(epilogue, 2);

		bRet = FALSE;

        if (!hProcess)
            goto end;

        if (!ReadByte(dwAddress, &epilogue, 2))
            goto end;

		if ((epilogue[0] == 0x5D || epilogue[0] == 0x5E) && // pop ebp, or pop esi,
			(epilogue[1] == 0xC2 || epilogue[1] == 0xC3)) // with a retn or ret XX
			bRet = TRUE;
    end:

        return bRet;
    }

	BOOL FindOperand(DWORD dwFunctionAddress, const char* chOperand, Instruction* lpInstruction)
	{
		BOOL bRet;
		DWORD dwOperandLen;
		DWORD dwFuncSize;
		DWORD dwNextAddress;

		Instruction instruction;

		bRet = FALSE;

		if (!hProcess
			|| !chOperand
			|| !IsPrologue(dwFunctionAddress))
			goto end;

		dwOperandLen = strlen(chOperand);

		dwNextAddress = dwFunctionAddress;

		if (!GetFunctionSize(dwFunctionAddress, &dwFuncSize))
			goto end;

		if (!Disassemble(dwNextAddress, &instruction))
			goto end;

		while (dwNextAddress < dwFunctionAddress + dwFuncSize)
		{
			dwNextAddress += instruction.length;

			if (!Disassemble(dwNextAddress, &instruction))
				goto end;

			if (strlen(instruction.chOpcode) != dwOperandLen)
				continue;

			if (memcmp(chOperand, instruction.chOpcode, dwOperandLen) == NULL)
			{
				bRet = TRUE;
				break;
			}
		}

	end:

		return bRet;
	}

	BOOL FindOperands(DWORD dwFunctionAddress, vector<const char*> chOperands)
	{
		BOOL bRet;
		Instruction instruction;

		bRet = FALSE;

		if (!hProcess
			|| !chOperands.size()
			|| !IsPrologue(dwFunctionAddress))
			goto end;

		for (size_t i = 0; i < chOperands.size(); i++)
			if (!FindOperand(dwFunctionAddress, chOperands[i], &instruction))
				goto end;

		bRet = TRUE;

	end:

		return bRet;
	}

	DWORD GetNextOP(DWORD dwAddress, BYTE bOPCode)
	{
		DWORD dwNextAddress;

		Instruction instruction;

		if (!hProcess
			|| !dwAddress
			|| !IsValidAddress(dwAddress))
			goto end;

		dwNextAddress = dwAddress;

		if (!Disassemble(dwNextAddress, &instruction))
			goto end;

		dwNextAddress += instruction.length;

		while (true)
		{
			if (!Disassemble(dwNextAddress, &instruction))
				goto end;

			if (instruction.opcode == bOPCode)
				break;

			dwNextAddress += instruction.length;
		}

	end:

		return dwNextAddress;
	}

    DWORD GetNextPrologue(DWORD dwAddress, Direction dir)
    {
        if (!hProcess)
            goto end;

        do
        {
            if (dir == Forward) dwAddress++;
            else if (dir == Behind) dwAddress--;
        } while (!IsPrologue(dwAddress));

    end:

        return dwAddress;
    }

	BOOL GetFunctionReturn(DWORD dwFunctionAddress, USHORT* lpBuffer)
	{
		BOOL bRet = FALSE;
		DWORD dwFunctionEpilogue = NULL;
		USHORT usRet;
		BYTE epilogue[2];

		if (!hProcess)
			goto end;

		*lpBuffer = 0;

		dwFunctionEpilogue = GetEpilogue(dwFunctionAddress);
		if (!dwFunctionEpilogue)
		{
			cout << "Unable to GetEpilogue of " << dwFunctionAddress << " function" << endl;
			Log("Unable to GetEpilogue");
			goto end;
		}

		if (!ReadByte(dwFunctionEpilogue, epilogue, 2))
			goto end;

		switch (epilogue[1])
		{
		case 0xC2:
		{
			if (!ReadByte(dwFunctionEpilogue + 2, &usRet, 2))
				goto end;

			*lpBuffer = usRet;
		}
			break;
		case 0xC3:
			break;
		default:
			goto end;;
		}

		bRet = TRUE;
	end:

		return bRet;
	}

	DWORD GetNextFunction(DWORD dwAddress, Direction dir)
	{
		if (!hProcess)
			goto end;

		do
		{
			if (dir == Forward) dwAddress += 16;
			else if (dir == Behind) dwAddress -= 16;
		} while (!IsPrologue(dwAddress));

	end:

		return dwAddress;
	}

	DWORD GetNextFunction(DWORD dwAddress, Direction dir, DWORD dwNumber)
	{
		DWORD dwRet = FALSE;

		if (!hProcess)
			goto end;

		dwRet = dwAddress;

		for (DWORD i = 0; i < dwNumber; i++)
			dwRet = GetNextFunction(dwRet, dir);

	end:

		return dwRet;
	}

    DWORD GetPrologue(DWORD dwAddress)
    {
        return GetNextPrologue(dwAddress, Behind);
    }

    DWORD GetNextEpilogue(DWORD dwAddress, Direction dir)
    {
        if (!hProcess)
            goto end;

        do
        {
            if (dir == Forward) dwAddress++;
            else if (dir == Behind) dwAddress--;
        } while (!IsEpilogue(dwAddress));

    end:

        return dwAddress;
    }

    DWORD GetEpilogue(DWORD dwAddress)
    {
        return GetNextEpilogue(dwAddress, Forward);
    }

    DWORD GetNextCall(DWORD dwAddress, Direction dir)
    {
        BYTE cmd;
        DWORD address;

        DWORD dwRet = FALSE;

        if (!hProcess)
            goto end;

        while (dwAddress - 1 > begin && dwAddress + 1 < end)
        {
            if (dir == Forward) dwAddress++;
            else if (dir == Behind) dwAddress--;

            if (!ReadByte(dwAddress, &cmd))
                goto end;

            if (cmd == 0xE8)
            {
                if (!ReadByte(dwAddress + 1, &address, 4))
                    goto end;

                if (dwAddress + 5 + address < end && dwAddress + 5 + address > begin)
                    break;
            }
        }

        dwRet = dwAddress;

    end:

        return dwRet;
    }

    DWORD GetNextCall(DWORD dwAddress, Direction dir, DWORD dwNumber)
    {
        DWORD dwRet = FALSE;

        if (!hProcess)
            goto end;

        dwRet = dwAddress;

        for (DWORD i = 0; i < dwNumber; i++)
            dwRet = GetNextCall(dwRet, dir);

    end:

        return dwRet;
    }

	BOOL GetFunctionSize(DWORD dwAddress, DWORD* lpBuf)
	{
		BOOL bRet;

		bRet = FALSE;

		if (!IsValidAddress(dwAddress)
			|| !lpBuf
			|| !IsPrologue(dwAddress))
			goto end;

		*lpBuf = 0;

		do
		{
			*lpBuf += 0x10;
		} while (!IsPrologue(dwAddress + *lpBuf));

		bRet = TRUE;

	end:

		return bRet;
	}

	BOOL IsValidAddress(DWORD dwAddress)
	{
		BOOL bRet;
		MEMORY_BASIC_INFORMATION memInfo;

		bRet = FALSE;

		if (!VirtualQueryEx(hProcess, (LPCVOID)dwAddress, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			cout << "Unable to VirtualQueryEx" << endl;
			goto end;
		}

		if (!(memInfo.Protect & PAGE_READONLY || memInfo.Protect & PAGE_READWRITE || memInfo.Protect & PAGE_EXECUTE_READ || memInfo.Protect & PAGE_EXECUTE_READWRITE)
			|| memInfo.Protect & PAGE_GUARD)
		{
			goto end;
		}

		bRet = TRUE;

	end:

		return bRet;
	}

	BOOL GetSectionData(DWORD dwAddress, SectionData* lpBuffer)
	{
		BOOL bRet = FALSE;

		DWORD dwSectionHeaderAddress;

		MEMORY_BASIC_INFORMATION memInfo;
		IMAGE_SECTION_HEADER SectionHeader;

		for (WORD i = 0; i < FileHeader.NumberOfSections; i++)
		{
			dwSectionHeaderAddress = dwNtHeaderAddress + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER);

			if (!ReadByte(dwSectionHeaderAddress, &SectionHeader, sizeof(IMAGE_SECTION_HEADER)))
			{
				Log("Unable to read dwSectionHeaderAddress");

				goto end;
			}

			if (!VirtualQueryEx(hProcess, (LPCVOID)(base + SectionHeader.VirtualAddress), &memInfo, sizeof(memInfo)))
			{
				Log("Unable to VirtualQueryEx (LPCVOID)(base + SectionHeader.VirtualAddress)");

				goto end;
			}

			if (base + SectionHeader.VirtualAddress <= dwAddress
				&& dwAddress < base + SectionHeader.VirtualAddress + memInfo.RegionSize)
			{
				lpBuffer->dwPhysicalAddress = base + SectionHeader.VirtualAddress;
				lpBuffer->dwRegionSize = memInfo.RegionSize;

				memcpy_s(lpBuffer->chName, 8, SectionHeader.Name, 8);

				break;
			}

			//cout << SectionHeader.Name << endl;
			//cout << base + SectionHeader.VirtualAddress << endl;

			//cout << memInfo.RegionSize << endl;
		}

		bRet = TRUE;
	end:

		return bRet;
	}

	BOOL GetSectionData(const char* chSectionName, SectionData* lpBuffer)
	{
		BOOL bRet = FALSE;

		DWORD dwSectionHeaderAddress;

		MEMORY_BASIC_INFORMATION memInfo;
		IMAGE_SECTION_HEADER SectionHeader;

		for (WORD i = 0; i < FileHeader.NumberOfSections; i++)
		{
			dwSectionHeaderAddress = dwNtHeaderAddress + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER);

			if (!ReadByte(dwSectionHeaderAddress, &SectionHeader, sizeof(IMAGE_SECTION_HEADER)))
			{
				Log("Unable to read dwSectionHeaderAddress");

				goto end;
			}

			if (memcmp(SectionHeader.Name, chSectionName, strlen(chSectionName)) == NULL)
			{
				if (!VirtualQueryEx(hProcess, (LPCVOID)(base + SectionHeader.VirtualAddress), &memInfo, sizeof(memInfo)))
				{
					Log("Unable to VirtualQueryEx (LPCVOID)(base + SectionHeader.VirtualAddress)");

					goto end;
				}

				lpBuffer->dwPhysicalAddress = base + SectionHeader.VirtualAddress;
				lpBuffer->dwRegionSize = memInfo.RegionSize;

				memcpy_s(lpBuffer->chName, 8, SectionHeader.Name, 8);

				break;
			}

			//cout << SectionHeader.Name << endl;
			//cout << base + SectionHeader.VirtualAddress << endl;

			//cout << memInfo.RegionSize << endl;
		}

		bRet = TRUE;
	end:

		return bRet;
	}

    DWORD GetBaseAddress()
    {
        return base;
    }

    DWORD GetBeginAddress()
    {
        return begin;
    }

    DWORD GetEndAddress()
    {
        return end;
    }

    BOOL ReadByte(DWORD dwAddress, LPVOID lpBuffer)
    {
        BOOL bRet = FALSE;

        if (!ReadProcessMemory(hProcess, (LPCVOID)dwAddress, lpBuffer, 1, 0))
        {
            Log("Unable to ReadProcessMemory");
            goto end;
        }

        bRet = TRUE;
    end:

        return bRet;
    }

    BOOL ReadByte(DWORD dwAddress, LPVOID lpBuffer, DWORD cbCount)
    {
        BOOL bRet = FALSE;
        DWORD cbReaded = 0;

        if (!ReadProcessMemory(hProcess, (LPCVOID)dwAddress, lpBuffer, cbCount, &cbReaded))
        {
            Log("Unable to ReadProcessMemory");
            goto end;
        }

        bRet = TRUE;
    end:

        return bRet;
    }

	HANDLE GetHandle()
	{
		return hProcess;
	}

    BOOL Init(HANDLE hProcess)
    {
        BOOL bRet = FALSE;

        MODULEINFO moduleInfo;
        DWORD dwProcessID;
        HMODULE hModule;

        MEMORY_BASIC_INFORMATION memInfo;

        wchar_t buf[MAX_PATH];
        ZeroMemory(buf, sizeof(buf));

        if (!hProcess)
            goto end;

        Dumper::hProcess = hProcess;

        if (!K32GetModuleFileNameExW(hProcess, NULL, buf, MAX_PATH))
        {
            cout << "Unable to get process full path" << endl;

            goto end;
        }

        wchar_t bufe[MAX_PATH];
        ZeroMemory(bufe, sizeof(bufe));

        dwProcessID = GetProcessId(hProcess);
        if (!dwProcessID)
        {
            cout << "Unable to get process id" << endl;

            goto end;
        }

        GetProcessNameById(dwProcessID, bufe, MAX_PATH);

        hModule = GetModuleHandleByName(dwProcessID, bufe);
        if (!hModule)
        {
            cout << "Unable to get hModule" << endl;

            goto end;
        }

        if (!K32GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo)))
        {
            cout << "Unable to K32GetModuleInformation" << endl;

            goto end;
        }

        base = (DWORD)moduleInfo.lpBaseOfDll;

		dwDosHeaderAddress = (DWORD)moduleInfo.lpBaseOfDll;

        // *reinterpret_cast<IMAGE_DOS_HEADER*>(moduleInfo.lpBaseOfDll);
        if (!ReadByte(dwDosHeaderAddress, &DosHeader, sizeof(IMAGE_DOS_HEADER)))
        {
            Log("Unable to read moduleInfo.lpBaseOfDll");

            goto end;
        }

		dwNtHeaderAddress = dwDosHeaderAddress + DosHeader.e_lfanew;

        // *reinterpret_cast<IMAGE_NT_HEADERS*>((DWORD)moduleInfo.lpBaseOfDll + DosHeader.e_lfanew);
        if (!ReadByte(dwNtHeaderAddress, &NtHeader, sizeof(IMAGE_NT_HEADERS)))
        {
            Log("Unable to read moduleInfo.lpBaseOfDll + DosHeader.e_lfanew");

            goto end;
        }

		FileHeader = NtHeader.FileHeader;

        OptHeader = NtHeader.OptionalHeader;

        begin = (DWORD)moduleInfo.lpBaseOfDll + OptHeader.BaseOfCode;

		if (!VirtualQueryEx(hProcess, (LPCVOID)begin, &memInfo, sizeof(memInfo)))
		{
			Log("Unable to VirtualQueryEx begin");

			goto end;
		}

        end = (DWORD)begin + memInfo.RegionSize;

		// Initialize decoder context
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);

		// Initialize formatter. Only required when you actually plan to do instruction
		// formatting ("disassembling"), like we do here
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

        bRet = TRUE;

    end:

        return bRet;
    }
}