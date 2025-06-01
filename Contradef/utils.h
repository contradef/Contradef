#pragma once
#ifndef UTILS_H
#define UTILS_H

#include "pin.H"

namespace WindowsAPI
{
#include <Windows.h>
#include <unistd.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <Winternl.h>
}

#include <iostream>
#include <fstream>
#include <clocale>
#include "CallContext.h"
#include <string>
#include <cctype>
#include <deque>
#include "NtStructures.h"

bool IsPointer(ADDRINT value);
std::string GetNumericValue(ADDRINT ea, UINT32 size);
std::string GetNumericHexValue(ADDRINT ea, UINT32 size);
std::string GetNumericValueFromRef(VOID* ea, UINT32 size);
bool IsStringPointer(UINT64 addr);
bool IsValidWideString(const std::wstring& str);
bool IsValidString(const std::string& str);
std::string InterpretAddrIntAsASCII(ADDRINT value);
std::wstring CopyLPCWSTR(ADDRINT addr);
std::string CopyLPCSTR(ADDRINT addr);
std::string GetStringValueFromRegister(UINT64 value, UINT32 size);
size_t GetSafeWStringLength(ADDRINT addr, size_t maxLen = 1024);
std::wstring ConvertAddrToWideStringSafe(ADDRINT addr, size_t maxLen = 1024);
std::wstring ConvertAddrToWideString(ADDRINT addr);
std::string ConvertAddrToAnsiString(ADDRINT addr);
void LogWString(const std::wstring& wstr);
std::string WStringToString(const std::wstring& wstr);
const wchar_t* StringToWString(const std::string& str);
std::string ExtractModuleName(const std::string& fullPath);
std::string toUpperCase(const std::string& str);
VOID PrintTrace(std::deque<std::string>& rtnTrace);
void PrintCallContextMap(std::map<CallContextKey, CallContext*>& callContextMap);
void GetParentProcessName();
DWORD GetProcessIdByName(std::string processName);
std::string getFileName(const std::string& filePath);
#endif // UTILS_H
