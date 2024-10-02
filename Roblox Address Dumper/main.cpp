#include "Header.hpp"

#define NonASLR(x) (x + 0x400000 - Dumper::GetBaseAddress())

struct RobloxFunction
{
	DWORD dwAddress;
	CallConvention eCallConvention;

	char chLuaName[32];
	char chVarName[32];
};

struct RobloxLuaType
{
	int iID;

	char chName[32];
};

struct RobloxLuaOffset
{
	DWORD dwOffset;

	char chName[32];
};

struct RobloxPseudoIndice
{
	int iPseudoIndice;

	char chName[32];
};

static std::vector<RobloxLuaType> rLuaTypes;
static std::vector<RobloxFunction> rFunctions;
static std::vector<RobloxLuaOffset> rLuaOffsets;
static std::vector<RobloxPseudoIndice> rPseudoIndices;

// Function Addresses

DWORD dwSetTopAddress;
DWORD dwGetTopAddress;
DWORD dwGetFieldAddress;
DWORD dwRawGetAddress;
DWORD dwRawGetIAddress;
DWORD dwRawSetAddress;
DWORD dwRawSetIAddress;
DWORD dwSetFieldAddress;
DWORD dwCreateTableAddress;
DWORD dwNewThreadAddress;
DWORD dwNewUserDataAddress;
DWORD dwNextAddressFunc;
DWORD dwGetTableAddress;
DWORD dwSetTableAddress;
DWORD dwPushNilAddress;
DWORD dwPushBooleanAddress;
DWORD dwPushValueAddress;
DWORD dwPushIntegerAddress;
DWORD dwPushNumberAddress;
DWORD dwCallAddress;
DWORD dwPCallAddress;
DWORD dwToStringAddress;
DWORD dwPushStringAddress;
DWORD dwPushLStringAddress;
DWORD dwPushLightUserDataAddress;
DWORD dwPushCClosureAddress;
DWORD dwPushThreadAddress;
DWORD dwRemoveAddress;
DWORD dwIndex2AdrAddress;
DWORD dwNewLStrAddress;
DWORD dwVGetTableAddress;
DWORD dwVSetTableAddress;
DWORD dwDCallAddress;
DWORD dwDPreCallAddress;
DWORD dwVExecuteAddress;
DWORD dwHSetAddress;
DWORD dwHGetAddress;

// Pseudo indices

DWORD dwGlobalsIndex;
DWORD dwEnvironIndex;
DWORD dwRegistryIndex;

// Lua offsets

UCHAR uchLuaTop;
UCHAR uchLuaBase;

// Lua Types

INT iNilID;
INT iBooleanID;
INT iNumberID;
INT iStringID;
INT iLightUserDataID;
INT iTableID;
INT iUserDataID;
INT iFunctionID;
INT iThreadID;
INT iProtoID;
INT iUpValueID;

void PrintAddress(DWORD dwAddress)
{
	cout << "0x" << hex << uppercase << dwAddress;
}

BOOL GetLuaType(DWORD dwAddress, int* lpBuf)
{
	BOOL bRet;
	DWORD dwNextAddress;
	DWORD dwFunctionSize;

	Instruction instruction;

	bRet = FALSE;

	if (!dwAddress
		|| !Dumper::IsValidAddress(dwAddress))
		goto end;

	dwNextAddress = dwAddress;

	if (!Dumper::GetFunctionSize(dwAddress, &dwFunctionSize))
		goto end;

	while (dwNextAddress < dwNextAddress + dwFunctionSize)
	{
		if (!Dumper::Disassemble(dwNextAddress, &instruction))
			goto end;

		if (memcmp(instruction.chOpcode, "mov", 3) == NULL
			&& instruction.operand_count == 2
			&& instruction.operands[0].encoding == ZYDIS_OPERAND_ENCODING_MODRM_RM
			&& instruction.operands[1].encoding == ZYDIS_OPERAND_ENCODING_SIMM16_32_32)
		{
			*lpBuf = instruction.operands[1].imm.value.u;
			break;
		}

		dwNextAddress += instruction.length;
	}

	bRet = TRUE;
end:

	return bRet;
}

BOOL HasReturnCheck(DWORD dwAddress)
{
	BOOL bRet;
	DWORD cbFunctionSize;

	bRet = FALSE;

	if (!Dumper::IsValidAddress(dwAddress)
		|| !Dumper::IsPrologue(dwAddress))
		goto end;

	if (!Dumper::GetFunctionSize(dwAddress, &cbFunctionSize))
	{
		cout << "Unable to get function size" << endl;
		goto end;
	}

	if (!Dumper::FindPattern(dwAddress, dwAddress + cbFunctionSize, "\x72?\xA1????\x8B", 8, "x?x????x", 0))
		goto end;

	bRet = TRUE;
end:

	return bRet;
}

void PrintFunctionInfo(RobloxFunction rFunction)
{
	cout << rFunction.chLuaName << ":";

	cout << hex << uppercase;

	cout << " Address: " << rFunction.dwAddress;

	cout << " | Aslr: ";

	PrintAddress(NonASLR(rFunction.dwAddress));

	cout << " | Ret Check: ";

	if (HasReturnCheck(rFunction.dwAddress))
		cout << "True";
	else
		cout << "False";

	cout << " | Call Convention: ";

	switch (rFunction.eCallConvention)
	{
	case CC_cdecl:
		cout << "__cdecl";
		break;
	case CC_stdcall:
		cout << "__stdcall";
		break;
	case CC_fastcall:
		cout << "__fastcall";
		break;
	default:
		cout << "unknown";
		break;
	}

	cout << endl;
}

DWORD GetFunctionAddress(DWORD dwCallAddress)
{
	DWORD dwAddressDelta;

	Dumper::ReadByte(dwCallAddress + 1, &dwAddressDelta, 4);

	return dwCallAddress + 5 + dwAddressDelta;
}

DWORD GetLower(vector<RobloxFunction> vRobloxFunctions, DWORD dwBegin, DWORD dwEnd)
{
	DWORD number = 0;
	DWORD dwBufAddress = 0xFFFFFFFF;

	for (size_t i = dwBegin; i < dwEnd; i++)
	{
		if (vRobloxFunctions[i].dwAddress < dwBufAddress)
		{
			number = i;
			dwBufAddress = vRobloxFunctions[i].dwAddress;
		}
	}

	return number;
}

void SortRobloxFunctions(vector<RobloxFunction>* vRobloxFunctions)
{
	DWORD dwLowerFunction = 0;
	DWORD dwSortedCount = 0;
	DWORD dwCountFunctions = vRobloxFunctions->size();

	RobloxFunction bufRobloxFunction;

	while (dwCountFunctions != dwSortedCount)
	{
		ZeroMemory(&bufRobloxFunction, sizeof(RobloxFunction));

		dwLowerFunction = GetLower(*vRobloxFunctions, 0, dwCountFunctions - dwSortedCount);

		bufRobloxFunction = (*vRobloxFunctions)[dwLowerFunction];

		vRobloxFunctions->erase(vRobloxFunctions->begin() + dwLowerFunction);

		vRobloxFunctions->push_back(bufRobloxFunction);

		dwSortedCount += 1;
	}

	return;
}

void PrintFunctions()
{
	for (size_t i = 0; i < rFunctions.size(); i++)
		PrintFunctionInfo(rFunctions[i]);

	return;
}

void AddFunction(DWORD dwAddress, const char* chFunctionName, const char* chVariableName)
{
	DWORD dwFunctionLength;
	DWORD dwVariableLength;

	RobloxFunction rFunction;
	ZeroMemory(&rFunction, sizeof(RobloxFunction));

	dwFunctionLength = strlen(chFunctionName);
	dwVariableLength = strlen(chVariableName);

	if (dwFunctionLength > 31
		|| dwVariableLength > 31)
		return;

	rFunction.dwAddress = dwAddress;

	rFunction.eCallConvention = Dumper::GetCallConvention(dwAddress);

	memcpy_s(rFunction.chLuaName, dwFunctionLength, chFunctionName, dwFunctionLength);

	memcpy_s(rFunction.chVarName, dwVariableLength, chVariableName, dwVariableLength);

	rFunctions.push_back(rFunction);

	return;
}

void AddLuaType(int iID, const char* chTypeName)
{
	DWORD dwTypeLength;

	RobloxLuaType rLuaType;
	ZeroMemory(&rLuaType, sizeof(RobloxLuaType));

	dwTypeLength = strlen(chTypeName);

	if (dwTypeLength > 31)
		return;

	rLuaType.iID = iID;

	memcpy_s(rLuaType.chName, dwTypeLength, chTypeName, dwTypeLength);

	rLuaTypes.push_back(rLuaType);

	return;
}

void AddPseudoIndice(int iPseudoIndice, const char* chPseudoIndiceName)
{
	DWORD dwPseudoIndiceLength;

	RobloxPseudoIndice rPseudoIndice;
	ZeroMemory(&rPseudoIndice, sizeof(RobloxLuaType));

	dwPseudoIndiceLength = strlen(chPseudoIndiceName);

	if (dwPseudoIndiceLength > 31)
		return;

	rPseudoIndice.iPseudoIndice = iPseudoIndice;

	memcpy_s(rPseudoIndice.chName, dwPseudoIndiceLength, chPseudoIndiceName, dwPseudoIndiceLength);

	rPseudoIndices.push_back(rPseudoIndice);

	return;
}

void AddLuaOffset(DWORD dwOffset, const char* chOffsetName)
{
	DWORD dwOffsetLength;

	RobloxLuaOffset rLuaOffset;
	ZeroMemory(&rLuaOffset, sizeof(RobloxLuaOffset));

	dwOffsetLength = strlen(chOffsetName);

	if (dwOffsetLength > 31)
		return;

	rLuaOffset.dwOffset = dwOffset;

	memcpy_s(rLuaOffset.chName, dwOffsetLength, chOffsetName, dwOffsetLength);

	rLuaOffsets.push_back(rLuaOffset);

	return;
}

void GetPseudoIndices()
{
	DWORD dwBuf;

	Instruction instruction;

	if (!dwIndex2AdrAddress)
		goto end;

	dwBuf = Dumper::GetNextOP(dwIndex2AdrAddress, 0x81);

	if (!Dumper::Disassemble(dwBuf, &instruction))
		goto end;

	dwGlobalsIndex = instruction.operands[1].imm.value.u;

	AddPseudoIndice(dwGlobalsIndex, "RLUA_GLOBALSINDEX");

	dwBuf = Dumper::GetNextOP(dwBuf, 0x81);

	if (!Dumper::Disassemble(dwBuf, &instruction))
		goto end;

	dwEnvironIndex = instruction.operands[1].imm.value.u;

	AddPseudoIndice(dwEnvironIndex, "RLUA_ENVIRONINDEX");

	dwBuf = Dumper::GetNextOP(dwBuf, 0x81);

	if (!Dumper::Disassemble(dwBuf, &instruction))
		goto end;

	dwRegistryIndex = instruction.operands[1].imm.value.u;

	AddPseudoIndice(dwRegistryIndex, "RLUA_REGISTRYINDEX");

end:

	return;
}

BOOL ParseGetTop()
{
	BOOL bRet;
	DWORD dwNextAddress;

	Instruction instruction;

	bRet = FALSE;

	if (!dwGetTopAddress)
		goto end;

	dwNextAddress = dwGetTopAddress;

	while (true)
	{
		if (!Dumper::Disassemble(dwNextAddress, &instruction))
			goto end;

		if (memcmp(instruction.chData, "mov eax", 7) == NULL) // Top
		{
			uchLuaTop = instruction.operands[1].mem.disp.value;
			AddLuaOffset(uchLuaTop, "Top");
		}
		else if (memcmp(instruction.chData, "sub eax", 7) == NULL) // Base
		{
			uchLuaBase = instruction.operands[1].mem.disp.value;
			AddLuaOffset(uchLuaBase, "Base");
			break;
		}

		dwNextAddress += instruction.length;
	}

	bRet = TRUE;
end:

	return bRet;
}

void GetRobloxLuaTypes()
{
	cout << "Roblox Lua Types: " << endl << endl;

	if (GetLuaType(dwPushNilAddress, &iNilID))
	{
		AddLuaType(iNilID, "RLUA_TNIL");
		cout << "Nil: " << iNilID << endl;
	}

	if (GetLuaType(dwPushBooleanAddress, &iBooleanID))
	{
		AddLuaType(iBooleanID, "RLUA_TBOOLEAN");
		cout << "Boolean: " << iBooleanID << endl;
	}

	if (GetLuaType(dwPushNumberAddress, &iNumberID))
	{
		AddLuaType(iNumberID, "RLUA_TNUMBER");
		cout << "Number: " << iNumberID << endl;
	}

	if (GetLuaType(dwPushLStringAddress, &iStringID))
	{
		AddLuaType(iStringID, "RLUA_TSTRING");
		cout << "String: " << iStringID << endl;
	}

	if (GetLuaType(dwCreateTableAddress, &iTableID))
	{
		AddLuaType(iTableID, "RLUA_TTABLE");
		cout << "Table: " << iTableID << endl;
	}

	if (GetLuaType(dwPushLightUserDataAddress, &iLightUserDataID))
	{
		AddLuaType(iLightUserDataID, "RLUA_TLIGHTUSERDATA");
		cout << "LightUserData: " << iLightUserDataID << endl;
	}

	if (GetLuaType(dwNewUserDataAddress, &iUserDataID))
	{
		AddLuaType(iUserDataID, "RLUA_TUSERDATA");
		cout << "UserData: " << iUserDataID << endl;
	}

	if (GetLuaType(dwPushCClosureAddress, &iFunctionID))
	{
		AddLuaType(iFunctionID, "RLUA_TFUNCTION");
		cout << "Function: " << iFunctionID << endl;
	}

	if (GetLuaType(dwPushThreadAddress, &iThreadID))
	{
		AddLuaType(iThreadID, "RLUA_TTHREAD");
		cout << "Thread: " << iThreadID << endl;
	}

	return;
}

char my_tolower(char ch)
{
	return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
}

void PrintFiles()
{
	char buf[16];
	ZeroMemory(buf, 16);

	if (!FileWriter::Open("Addresses.hpp", GENERIC_WRITE, FILE_SHARE_READ, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL))
		if (!FileWriter::Open("Addresses.hpp", GENERIC_WRITE, FILE_SHARE_READ, CREATE_NEW, FILE_ATTRIBUTE_NORMAL))
		{
			Log("Unable to open file");
			return;
		}
	
	FileWriter::Write("#pragma once");

	FileWriter::Write("\n");

	for (size_t i = 0; i < rLuaTypes.size(); i++)
	{
		sprintf_s(buf, "%u", rLuaTypes[i].iID);

		FileWriter::Write("\n");

		FileWriter::Write("#define ");
		FileWriter::Write(rLuaTypes[i].chName);
		FileWriter::Write(" ");
		FileWriter::Write(buf);
	}

	FileWriter::Write("\n");

	for (size_t i = 0; i < rPseudoIndices.size(); i++)
	{
		sprintf_s(buf, "%08X", rPseudoIndices[i].iPseudoIndice);

		FileWriter::Write("\n");

		FileWriter::Write("#define ");
		FileWriter::Write(rPseudoIndices[i].chName);
		FileWriter::Write(" 0x");
		FileWriter::Write(buf);
	}

	FileWriter::Write("\n");

	for (size_t i = 0; i < rLuaOffsets.size(); i++)
	{
		sprintf_s(buf, "%02X", rLuaOffsets[i].dwOffset);

		FileWriter::Write("\n");

		FileWriter::Write("#define RLUA_");

		for (size_t j = 0; j < strlen(rLuaOffsets[i].chName); j++)
		{
			char chUpper = toupper(rLuaOffsets[i].chName[j]);

			FileWriter::Write((char*)&chUpper, 1);
		}

		FileWriter::Write(" 0x");
		FileWriter::Write(buf);
	}

	for (size_t i = 0; i < rFunctions.size(); i++)
	{
		FileWriter::Write("\n\n");

		FileWriter::Write("#define ");

		for (size_t j = 0; j < strlen(rFunctions[i].chVarName) - 9; j++)
		{
			char chLower = tolower(rFunctions[i].chVarName[j + 2]);

			FileWriter::Write((char*)&chLower, 1);
		}

		FileWriter::Write("cc ");

		switch (rFunctions[i].eCallConvention)
		{
		case CC_cdecl:
			FileWriter::Write("__cdecl");
			break;
		case CC_stdcall:
			FileWriter::Write("__stdcall");
			break;
		case CC_fastcall:
			FileWriter::Write("__fastcall");
			break;
		default:
			FileWriter::Write("unknown");
			break;
		}
		
		FileWriter::Write("\n");

		sprintf_s(buf, "%08X", NonASLR(rFunctions[i].dwAddress));

		FileWriter::Write("static DWORD ");
		FileWriter::Write(rFunctions[i].chVarName);
		FileWriter::Write(" = ");
		FileWriter::Write("0x");
		FileWriter::Write(buf);
		FileWriter::Write(";");
	}

	FileWriter::Close();
}

int main()
{
	DWORD dwProcessID = 0;
	HANDLE hProcess = 0;

	DWORD dwPrintAddress = 0;
	DWORD dwPrologueAddress = 0;
	DWORD dwSignatureAddress = 0, dwSignatureAddress1 = 0;
	DWORD dwBufAddress = 0;
	DWORD dwBufSize = 0;

	RESULTS results;
	Instruction instruction;

	cout << "Finding RobloxPlayaerBeta.exe process..." << endl;

	while (!dwProcessID)
	{
		dwProcessID = GetProcessIDByName(L"RobloxPlayerBeta.exe");

		Sleep(15);
	}

	cout << "Process RobloxPlayerBeta.exe founded" << endl;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwProcessID);
	if (!hProcess)
	{
		cout << "Unable to open process" << endl;

		goto end;
	}

	if (!Dumper::Init(hProcess))
	{
		cout << "Unable to init dumper" << endl;

		goto end;
	}

	wchar_t buf[MAX_PATH];
	ZeroMemory(buf, sizeof(buf));

	GetModuleFileNameExW(Dumper::GetHandle(), 0, buf, MAX_PATH);

	wcout << "Roblox path: " << buf << endl;
	
	GetFileVersion(buf);

	cout << "Base: " << Dumper::GetBaseAddress() << endl;

	cout << "Execute code:" << endl;

	cout << "Begin - ";
	PrintAddress(Dumper::GetBeginAddress());
	cout << endl;

	cout << "End - ";
	PrintAddress(Dumper::GetEndAddress());
	cout << endl;

	dwPrintAddress = Dumper::FindPattern(sigrprint, strlen(sigrprint), sigrprintmask, ".text", 0);
	if (!dwPrintAddress)
	{
		cout << "Unable to find print function pattern" << endl;

		goto end;
	}

	cout << "Print Address: ";
	PrintAddress(dwPrintAddress);
	cout << endl;

	if (!Dumper::ScanPointers(GetFunctionAddress(Dumper::GetNextCall(dwPrintAddress, Forward, 2)), &results))
	{
		cout << "Unable to scan pointers for luaS_newlstr" << endl;

		goto end;
	}

	cout << "What i need: ";
	PrintAddress(results[3]);
	cout << endl;

	dwPrologueAddress = Dumper::GetPrologue(results[3]);

	cout << "What i need prologue: ";
	PrintAddress(dwPrologueAddress);
	cout << endl;

	dwSetTopAddress = GetFunctionAddress(Dumper::GetNextCall(results[3], Behind, 3));

	AddFunction(dwSetTopAddress, "lua_settop", "dwSetTopAddress");

	dwGetTopAddress = GetFunctionAddress(Dumper::GetNextCall(dwPrologueAddress, Forward, 2));

	AddFunction(dwGetTopAddress, "lua_gettop", "dwGetTopAddress");

	dwGetFieldAddress = GetFunctionAddress(Dumper::GetNextCall(dwPrologueAddress, Forward, 3));

	AddFunction(dwGetFieldAddress, "lua_getfield", "dwGetFieldAddress");

	dwIndex2AdrAddress = GetFunctionAddress(Dumper::GetNextCall(dwGetFieldAddress, Forward, 1));

	AddFunction(dwIndex2AdrAddress, "index2adr", "dwIndex2AdrAddress");

	dwNewLStrAddress = GetFunctionAddress(Dumper::GetNextCall(dwGetFieldAddress, Forward, 2));

	AddFunction(dwNewLStrAddress, "luaS_newlstr", "dwSNewLStrAddress");

	dwVGetTableAddress = GetFunctionAddress(Dumper::GetNextCall(dwGetFieldAddress, Forward, 3));

	AddFunction(dwVGetTableAddress, "luaV_gettable", "dwVGetTableAddress");

	dwBufAddress = Dumper::FindPattern(sigrmetatablestring, strlen(sigrmetatablestring), sigrmetatablestringmask, ".rdata", 0);
	if (dwBufAddress)
	{
		if (!Dumper::ScanPointers(dwBufAddress, &results))
		{
			cout << "Unable to scan pointers for luaS_newlstr" << endl;

			goto end;
		}

		if (results.size() > 2)
		{
			dwPushStringAddress = GetFunctionAddress(Dumper::GetNextCall(results[1], Forward, 1));

			AddFunction(dwPushStringAddress, "lua_pushstring", "dwPushStringAddress");

			dwPushThreadAddress = Dumper::GetNextFunction(dwPushStringAddress, Forward, 1);

			AddFunction(dwPushThreadAddress, "lua_pushthread", "dwPushThreadAddress");

			dwSetFieldAddress = GetFunctionAddress(Dumper::GetNextCall(results[1], Forward, 2));

			AddFunction(dwSetFieldAddress, "lua_setfield", "dwSetFieldAddress");

			dwVSetTableAddress = GetFunctionAddress(Dumper::GetNextCall(dwSetFieldAddress, Forward, 3));

			AddFunction(dwVSetTableAddress, "luaV_settable", "dwVSetTableAddress");

			if (Dumper::GetFunctionSize(dwVSetTableAddress, &dwBufSize))
			{
				dwHSetAddress = GetFunctionAddress(Dumper::GetNextCall(dwVSetTableAddress, Forward, 1));

				if (dwBufSize < 0x40)
					dwHSetAddress = GetFunctionAddress(Dumper::GetNextCall(dwHSetAddress, Forward, 1));

				AddFunction(dwHSetAddress, "luaH_set", "dwHSetAddress");

				if (Dumper::ScanPointers(dwHSetAddress, &results))
				{
					if (results.size() != 5)
					{
						if (results.size() < 5)
							cout << "too small of pointers to luaH_set" << endl;
						else
							cout << "too much of pointers to luaH_set" << endl;
					}
					else
					{
						dwRawSetAddress = Dumper::GetPrologue(results[0]);

						AddFunction(dwRawSetAddress, "lua_rawset", "dwRawSetAddress");

						dwBufAddress = GetFunctionAddress(Dumper::GetNextCall(dwRawSetAddress, Forward, 3));

						if (Dumper::ScanPointers(dwBufAddress, &results))
						{
							dwRawSetIAddress = Dumper::GetPrologue(results[1]);

							AddFunction(dwRawSetIAddress, "lua_rawseti", "dwRawSetIAddress");
						}
					}
				}
				else
				{
					cout << "Unable to scan pointers for luaH_set" << endl;
				}
			}

			dwSetTableAddress = GetFunctionAddress(Dumper::GetNextCall(results[1], Forward, 5));

			AddFunction(dwSetTableAddress, "lua_settable", "dwSetTableAddress");

			dwBufAddress = Dumper::GetPrologue(results[0]);

			if (dwBufAddress)
			{
				if (!Dumper::ScanPointers(dwBufAddress, &results))
				{
					cout << "Unable to scan pointers for luaS_newlstr" << endl;

					goto end;
				}

				if (results.size() != 2)
				{
					cout << "Different count of pointers" << endl;

					goto end;
				}

				dwCreateTableAddress = GetFunctionAddress(Dumper::GetNextCall(results[0], Behind, 1));

				AddFunction(dwCreateTableAddress, "lua_createtable", "dwCreateTableAddress");

				dwBufAddress = GetFunctionAddress(Dumper::GetNextCall(dwCreateTableAddress, Forward, 1));

				if (Dumper::ScanPointers(dwBufAddress, &results))
				{
					dwNewThreadAddress = Dumper::GetPrologue(results[3]);

					AddFunction(dwNewThreadAddress, "lua_newthread", "dwNewThreadAddress");

					dwNewUserDataAddress = Dumper::GetPrologue(results[4]);

					AddFunction(dwNewUserDataAddress, "lua_newuserdata", "dwNewUserDataAddress");

					dwNextAddressFunc = Dumper::GetNextFunction(dwNewUserDataAddress, Forward, 1);

					AddFunction(dwNextAddressFunc, "lua_next", "dwNextAddress");

					dwBufAddress = Dumper::GetPrologue(results[5]);

					if (Dumper::FindOperands(dwBufAddress, { "jz", "jnz", "movups" }))
					{
						dwPushCClosureAddress = dwBufAddress;
						AddFunction(dwPushCClosureAddress, "lua_pushcclosure", "dwPushCClosureAddress");
					}
					else
					{
						cout << "Unable to find lua_pushcclosure" << endl;
					}
				}
				else
				{
					cout << "Unable to scan pointers to LuaC_ChecGC" << endl;
				}
			}
		}
		else
		{
			cout << "Different count of pointers to \"" << sigrmetatablestring << "\"" << endl;
		}
	}
	else
	{
		cout << "Unable to find \"" << sigrmetatablestring << "\" string" << endl;
	}

	dwPushValueAddress = GetFunctionAddress(Dumper::GetNextCall(dwPrologueAddress, Forward, 5));

	AddFunction(dwPushValueAddress, "lua_pushvalue", "dwPushValueAddress");

	dwPushNumberAddress = Dumper::GetNextFunction(dwPushValueAddress, Behind, 4);

	AddFunction(dwPushNumberAddress, "lua_pushnumber", "dwPushNumberAddress");

	dwPushNilAddress = Dumper::GetNextFunction(dwPushNumberAddress, Behind, 1);

	AddFunction(dwPushNilAddress, "lua_pushnil", "dwPushNilAddress");

	dwPushIntegerAddress = Dumper::GetNextFunction(dwPushNilAddress, Behind, 3);

	AddFunction(dwPushIntegerAddress, "lua_pushinteger", "dwPushIntegerAddress");

	dwPushBooleanAddress = Dumper::GetNextFunction(dwPushIntegerAddress, Behind, 3);

	AddFunction(dwPushBooleanAddress, "lua_pushboolean", "dwPushBooleanAddress");

	dwCallAddress = GetFunctionAddress(Dumper::GetNextCall(dwPrologueAddress, Forward, 7));

	AddFunction(dwCallAddress, "lua_call", "dwCallAddress");

	dwDCallAddress = GetFunctionAddress(Dumper::GetNextCall(dwCallAddress, Forward, 1));

	AddFunction(dwDCallAddress, "luaD_call", "dwDCallAddress");

	dwDPreCallAddress = GetFunctionAddress(Dumper::GetNextCall(dwDCallAddress, Forward, 1));

	AddFunction(dwDPreCallAddress, "luaD_precall", "dwDPreCallAddress");

	dwVExecuteAddress = GetFunctionAddress(Dumper::GetNextCall(dwDCallAddress, Forward, 2));

	AddFunction(dwVExecuteAddress, "luaV_execute", "dwVExecuteAddress");

	if (Dumper::ScanPointers(dwDCallAddress, &results))
		if (Dumper::ScanPointers(Dumper::GetPrologue(results[0]), &results))
		{
			dwPCallAddress = Dumper::GetPrologue(results[0]);

			AddFunction(dwPCallAddress, "lua_pcall", "dwPCallAddress");
		}

	dwToStringAddress = GetFunctionAddress(Dumper::GetNextCall(dwPrologueAddress, Forward, 8));

	AddFunction(dwToStringAddress, "lua_tostring", "dwToStringAddress");

	if (Dumper::GetFunctionSize(dwVGetTableAddress, &dwBufSize))
	{
		dwHGetAddress = GetFunctionAddress(Dumper::GetNextCall(dwVGetTableAddress, Forward, 1));

		if (dwBufSize < 0x40)
			dwHGetAddress = GetFunctionAddress(Dumper::GetNextCall(dwHGetAddress, Forward, 1));

		AddFunction(dwHGetAddress, "luaH_get", "dwHGetAddress");

		if (Dumper::ScanPointers(dwHGetAddress, &results))
		{
			if (results.size() != 2)
			{
				if (results.size() < 2)
					cout << "lua_rawget gone" << endl;
				else
					cout << "too much of pointers to luaH_get" << endl;
			}
			else
			{
				dwRawGetAddress = Dumper::GetPrologue(results[0]);

				AddFunction(dwRawGetAddress, "lua_rawget", "dwRawGetAddress");

				dwRawGetIAddress = Dumper::GetNextFunction(dwRawGetAddress, Forward, 2);

				AddFunction(dwRawGetIAddress, "lua_rawgeti", "dwRawGetIAddress");
			}
		}
		else
		{
			cout << "Unable to scan pointers for luaH_get" << endl;
		}
	}

	if (!Dumper::ScanPointers(dwVGetTableAddress, &results))
	{
		cout << "Unable to scan pointers for luaS_newlstr" << endl;

		goto end;
	}

	dwGetTableAddress = Dumper::GetPrologue(results[1]);

	if (dwGetTableAddress == dwGetFieldAddress)
	{
		cout << "lua_gettable address equal lua_getfield" << endl;

		goto end;
	}

	AddFunction(dwGetTableAddress, "lua_gettable", "dwGetTableAddress");

	if (!Dumper::ScanPointers(dwNewLStrAddress, &results))
	{
		cout << "Unable to scan pointers for luaS_newlstr" << endl;

		goto end;
	}

	dwPushLStringAddress = Dumper::GetPrologue(results[2]);

	AddFunction(dwPushLStringAddress, "lua_pushlstring", "dwPushLStringAddress");

	dwPushLightUserDataAddress = Dumper::GetNextFunction(dwPushLStringAddress, Behind, 1);

	AddFunction(dwPushLightUserDataAddress, "lua_pushlightuserdata", "dwPushLightUserDataAddress");

	if (!Dumper::ScanPointers(dwIndex2AdrAddress, &results))
	{
		cout << "Unable to scan pointers for luaS_newlstr" << endl;

		goto end;
	}

	dwRemoveAddress = Dumper::GetPrologue(results[24]);

	AddFunction(dwRemoveAddress, "lua_remove", "dwRemoveAddress");

	SortRobloxFunctions(&rFunctions);

	PrintFunctions();

	GetRobloxLuaTypes();

	GetPseudoIndices();

	cout << endl;

	cout << "LUA_GLOBALSINDEX: " << hex << uppercase << dwGlobalsIndex << endl;
	cout << "LUA_ENVIRONINDEX: " << hex << uppercase << dwEnvironIndex << endl;
	cout << "LUA_REGISTRYINDEX: " << hex << uppercase << dwRegistryIndex << endl;

	cout << endl;

	cout << endl;

	if (!ParseGetTop())
	{
		cout << "Unable to parse lua_gettop" << endl;

		goto end;
	}

	cout << "Base - RLua+0x" << hex << uppercase << (int)uchLuaBase << endl;
	cout << "Top - RLua+0x" << hex << uppercase << (int)uchLuaTop << endl;

	PrintFiles();

	/*cout << "Nil: " << iNilID << endl;
	cout << "Boolean: " << iBooleanID << endl;
	cout << "Number: " << iNumberID << endl;
	cout << "LightUserData: " << iLightUserDataID << endl;
	cout << "Table: " << iTableID << endl;
	cout << "UserData: " << iUserDataID << endl;
	cout << "Function: " << iFunctionID << endl;
	cout << "Thread: " << iThreadID << endl;
	cout << "UpValue: " << iUpValueID << endl;*/

end:
	if (hProcess) CloseHandle(hProcess);
	system("PAUSE");
	return NULL;
}