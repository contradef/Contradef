#pragma once
#ifndef REGISTRY_KEYS_H
#define REGISTRY_KEYS_H

#include <string>

// Detec��o de M�quinas Virtuais
extern const char* VMwareKeys[];
extern const char* VirtualBoxKeys[];
extern const size_t VMwareKeysSize;
extern const size_t VirtualBoxKeysSize;

// Detec��o de Antiv�rus
extern const char* AntivirusKeys[];
extern const size_t AntivirusKeysSize;

// Detec��o de Sandboxes
extern const char* SandboxieKeys[];
extern const size_t SandboxieKeysSize;

// Detec��o de Instrumentadores e Depuradores
extern const char* DebuggerKeys[];
extern const size_t DebuggerKeysSize;

// Detec��o de Ferramentas de An�lise e Monitoramento
extern const char* AnalysisToolsKeys[];
extern const size_t AnalysisToolsKeysSize;

// Detec��o de Outros Ambientes e Ferramentas
extern const char* OtherToolsKeys[];
extern const size_t OtherToolsKeysSize;

// Declara��o da fun��o
bool isRegistryKeyPartInList(const std::string& key);

#endif // REGISTRY_KEYS_H
