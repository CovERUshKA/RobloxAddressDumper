# RobloxAddressDumper
Dumps Roblox Lua C function addresses and some other stuff. NOT WORKING

It has been written when I worked on Roblox-Exploit.

# Example Output
## Addresses.hpp
```C++
#pragma once

#define RLUA_TNIL 0
#define RLUA_TBOOLEAN 0
#define RLUA_TNUMBER 0
#define RLUA_TSTRING 0
#define RLUA_TLIGHTUSERDATA 0

#define RLUA_GLOBALSINDEX 0x00000180
#define RLUA_ENVIRONINDEX 0x00001000
#define RLUA_REGISTRYINDEX 0x00001000

#define RLUA_TOP 0x00
#define RLUA_TOP 0x00
#define RLUA_TOP 0x00
#define RLUA_BASE 0x00

#define pushlightuserdatacc __cdecl
static DWORD dwPushLightUserDataAddress = 0x004016B0;

#define gettablecc __cdecl
static DWORD dwGetTableAddress = 0x00401860;

#define pushlstringcc __cdecl
static DWORD dwPushLStringAddress = 0x00401860;

#define pcallcc __cdecl
static DWORD dwPCallAddress = 0x00470820;

#define removecc __cdecl
static DWORD dwRemoveAddress = 0x00497B60;

#define callcc __fastcall
static DWORD dwCallAddress = 0x005C40A0;

#define tostringcc __fastcall
static DWORD dwToStringAddress = 0x005DA1D0;

#define snewlstrcc __fastcall
static DWORD dwSNewLStrAddress = 0x005DA940;

#define vgettablecc __fastcall
static DWORD dwVGetTableAddress = 0x005DA940;

#define pushbooleancc __cdecl
static DWORD dwPushBooleanAddress = 0x00792860;

#define pushintegercc __fastcall
static DWORD dwPushIntegerAddress = 0x00792ED0;

#define pushnilcc __fastcall
static DWORD dwPushNilAddress = 0x00793190;

#define pushnumbercc __fastcall
static DWORD dwPushNumberAddress = 0x00793200;

#define pushvaluecc __cdecl
static DWORD dwPushValueAddress = 0x00793BA0;

#define gettopcc __cdecl
static DWORD dwGetTopAddress = 0x00799AA0;

#define settopcc __cdecl
static DWORD dwSetTopAddress = 0x0079ECD0;

#define getfieldcc __cdecl
static DWORD dwGetFieldAddress = 0x0079ECD0;

#define index2adrcc __cdecl
static DWORD dwIndex2AdrAddress = 0x00C3A2E0;

#define dcallcc __cdecl
static DWORD dwDCallAddress = 0x017C4F60;

#define hgetcc __stdcall
static DWORD dwHGetAddress = 0x01BCD690;

#define vexecutecc __cdecl
static DWORD dwVExecuteAddress = 0x01BD7159;

#define dprecallcc __cdecl
static DWORD dwDPreCallAddress = 0x01BF0272;
```
