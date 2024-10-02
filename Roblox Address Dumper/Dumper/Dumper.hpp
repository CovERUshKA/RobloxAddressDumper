#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <Zydis/Zydis.h>

#include "../Log/Log.hpp"

#define RESULTS std::vector<DWORD>

typedef
enum tagCallConvention
{
	CC_None,
	CC_fastcall,
	CC_cdecl,
	CC_stdcall
} CallConvention;

enum Direction
{
	Behind,
	Forward
};

struct SectionData { // Mnemonics

	char chName[8];

	DWORD dwPhysicalAddress;
	DWORD dwRegionSize;
};

struct Operand
{
	BYTE code;
	short shCountBytes;

};

struct Instruction : ZydisDecodedInstruction
{
	DWORD dwAddress;

	CHAR chOpcode[256];
	CHAR chData[256];
};

namespace Dumper
{
	BOOL Init(HANDLE hProcess);

	HANDLE GetHandle();

	DWORD GetBaseAddress();
	DWORD GetBeginAddress();
	DWORD GetEndAddress();

	BOOL ReadByte(DWORD dwAddress, LPVOID lpBuffer);
	BOOL ReadByte(DWORD dwAddress, LPVOID lpBuffer, DWORD cbCount);

	BOOL IsPrologue(DWORD dwAddress);
	BOOL IsEpilogue(DWORD dwAddress);

	DWORD GetPrologue(DWORD dwAddress);
	DWORD GetEpilogue(DWORD dwAddress);

	DWORD GetNextPrologue(DWORD dwAddress, Direction dir);
	DWORD GetNextEpilogue(DWORD dwAddress, Direction dir);

	BOOL GetSectionData(DWORD dwAddress, SectionData* lpBuffer);
	BOOL GetSectionData(const char* chSectionName, SectionData* lpBuffer);

	DWORD FindPattern(string pattern, const char* chMask, const char* chSectionName, int offset);
	DWORD FindPattern(const char* chPattern, DWORD cbPattern, const char* chMask, const char* chSectionName, int offset);
	DWORD FindPattern(DWORD dwBeginAddress, DWORD dwEndAddress, const char* chPattern, DWORD cbLength, const char* chMask, int offset);

	BOOL FindEqualPatterns(DWORD dwBeginAddress, DWORD dwEndAddress, RESULTS* lpResults);

	DWORD GetNextCall(DWORD dwAddress, Direction dir);
	DWORD GetNextCall(DWORD dwAddress, Direction dir, DWORD dwNumber);

	DWORD GetNextFunction(DWORD dwAddress, Direction dir);
	DWORD GetNextFunction(DWORD dwAddress, Direction dir, DWORD dwNumber);

	BOOL GetFunctionSize(DWORD dwAddress, DWORD* lpBuf);

	BOOL GetFunctionReturn(DWORD dwFunctionAddress, USHORT* lpBuffer);

	BOOL IsValidAddress(DWORD dwPointerAddress);

	DWORD GetNextOP(DWORD dwAddress, BYTE bOPCode);

	BOOL FindOperand(DWORD dwFunctionAddress, const char* chOperand, Instruction* lpInstruction);
	BOOL FindOperands(DWORD dwFunctionAddress, vector<const char*> chOperands);

	CallConvention GetCallConvention(DWORD dwAddress);

	BOOL ScanPointers(DWORD dwAddress, RESULTS* lpResults);

	BOOL Disassemble(DWORD addr, Instruction* x);
};