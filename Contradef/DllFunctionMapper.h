#pragma once
#ifndef DLL_FUNCTION_MAPPER_H
#define DLL_FUNCTION_MAPPER_H

#include "Utils.h"
#include <vector>
#include <algorithm>


struct FunctionRange {
    WindowsAPI::DWORD64 start;
    WindowsAPI::DWORD64 end;
    std::string name;
};

struct FunctionData {
    std::string fullModuleName; // Nome completo do módulo (caminho)
    std::string moduleName;     // Nome base do módulo (apenas o nome do arquivo)
    std::string functionName;   // Nome da função
};

struct ModuleRange {
    unsigned long long start;
    unsigned long long end;
    std::string name;
};

// Lista global de módulos
extern std::vector<ModuleRange> moduleRanges;

FunctionData GetFunctionFromAddress(unsigned long long address, unsigned int pid);
FunctionData GetFunctionFromAddressManualPE(unsigned long long address, unsigned int pid);

#endif // DLL_FUNCTION_MAPPER_H