#pragma once

// 55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 18 8D 45 10 50 FF
// print(2, "Lost connection to %s\n", "128.116.14.216|51889")
constexpr const char* sigrprint = "\x55\x8B\xEC\x6A\xFF\x68????\x64\xA1????\x50\x64\x89\x25????\x83\xEC\x18\x8D\x45\x10\x50\xFF";
constexpr const char* sigrprintmask = "xxxxxx????xx????xxxx????xxxxxxxx";

constexpr const char* sigrmetatablestring = "The metatable is locked";
constexpr const char* sigrmetatablestringmask = "xxxxxxxxxxxxxxxxxxxxxxx";