#pragma once
#ifndef MODULES_DETECTION_H
#define MODULES_DETECTION_H

#include <string>

// Lista de M�dulos Evasivos para Detec��o
extern const char* EvasiveModules[];
extern const size_t EvasiveModulesSize;

// Fun��o para verificar se um m�dulo � parte da lista
bool isModulePartInList(const std::string& moduleName);

#endif // MODULES_DETECTION_H
