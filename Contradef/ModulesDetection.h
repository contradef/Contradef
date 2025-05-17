#pragma once
#ifndef MODULES_DETECTION_H
#define MODULES_DETECTION_H

#include <string>

// Lista de Módulos Evasivos para Detecção
extern const char* EvasiveModules[];
extern const size_t EvasiveModulesSize;

// Função para verificar se um módulo é parte da lista
bool isModulePartInList(const std::string& moduleName);

#endif // MODULES_DETECTION_H
