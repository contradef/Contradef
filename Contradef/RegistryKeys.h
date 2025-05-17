#pragma once
#ifndef REGISTRY_KEYS_H
#define REGISTRY_KEYS_H

#include <string>

// Detecção de Máquinas Virtuais
extern const char* VMwareKeys[];
extern const char* VirtualBoxKeys[];
extern const size_t VMwareKeysSize;
extern const size_t VirtualBoxKeysSize;

// Detecção de Antivírus
extern const char* AntivirusKeys[];
extern const size_t AntivirusKeysSize;

// Detecção de Sandboxes
extern const char* SandboxieKeys[];
extern const size_t SandboxieKeysSize;

// Detecção de Instrumentadores e Depuradores
extern const char* DebuggerKeys[];
extern const size_t DebuggerKeysSize;

// Detecção de Ferramentas de Análise e Monitoramento
extern const char* AnalysisToolsKeys[];
extern const size_t AnalysisToolsKeysSize;

// Detecção de Outros Ambientes e Ferramentas
extern const char* OtherToolsKeys[];
extern const size_t OtherToolsKeysSize;

// Declaração da função
bool isRegistryKeyPartInList(const std::string& key);

#endif // REGISTRY_KEYS_H
