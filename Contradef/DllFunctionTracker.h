#pragma once
#ifndef DLL_FUNCTION_TRACKER_H
#define DLL_FUNCTION_TRACKER_H

#include <deque>
#include <string>
#include <iostream>
#include <vector>
#include <fstream>

// Estrutura para armazenar informações sobre a função chamada na DLL
struct DllFunctionInfo {
    int threadId;
    std::string dllName;     // Nome da DLL
    std::string functionName;// Nome da função chamada
    unsigned long long address; // Endereço da função

    // Construtor para inicializar os dados
    DllFunctionInfo(int trdId, const std::string& dll, const std::string& func, unsigned long long addr)
        : threadId(trdId), dllName(dll), functionName(func), address(addr) {
    }
};

// Classe para rastrear funções chamadas em DLLs
class DllFunctionTracker {
private:
    std::deque<DllFunctionInfo> functionList; // Lista de funções chamadas
    size_t maxSize;                           // Tamanho máximo da lista

public:
    // Construtor para inicializar o rastreador com um tamanho máximo
    DllFunctionTracker(size_t maxListSize);

    // Adiciona uma nova função chamada
    void addFunctionCall(int threadId, const std::string& dllName, const std::string& functionName, unsigned long long address);

    // Obtém as últimas N funções chamadas
    std::vector<DllFunctionInfo> getLastNCalls(size_t n) const;

    // Imprime todas as funções chamadas
    void printAllCalls() const;

    void DllFunctionTracker::saveAllExternalCalls(std::ofstream& ExternalCallTraceOutFile);
    void DllFunctionTracker::saveLastExternalCall(std::ofstream& ExternalCallTraceOutFile);

    // Verifica se uma função específica foi chamada
    bool wasFunctionCalled(const std::string& dllName, const std::string& functionName) const;

    bool DllFunctionTracker::wasFunctionCalledInLastN(const std::string& dllName, const std::string& functionName, size_t n) const;
};

#endif // DLL_FUNCTION_TRACKER_H

// Example
//int main() {
//    DllFunctionTracker tracker(10); // Máximo de 10 funções rastreadas
//
//    // Adiciona algumas funções chamadas
//    tracker.addFunctionCall("kernel32.dll", "CreateFileA", 0x7ff123456);
//    tracker.addFunctionCall("user32.dll", "MessageBoxA", 0x7ff123789);
//    tracker.addFunctionCall("ntdll.dll", "NtCreateThread", 0x7ff123abc);
//
//    // Imprime todas as funções chamadas
//    tracker.printAllCalls();
//
//    // Verifica se uma função específica foi chamada
//    if (tracker.wasFunctionCalled("kernel32.dll", "CreateFileA")) {
//        std::cout << "A função CreateFileA foi chamada na DLL kernel32.dll\n";
//    }
//
//    // Obtém as últimas 2 chamadas
//    auto lastCalls = tracker.getLastNCalls(2);
//    std::cout << "Últimas 2 chamadas:\n";
//    for (const auto& call : lastCalls) {
//        std::cout << "DLL: " << call.dllName << ", Função: " << call.functionName << "\n";
//    }
//
//    return 0;
//}