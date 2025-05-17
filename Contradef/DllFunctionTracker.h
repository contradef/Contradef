#pragma once
#ifndef DLL_FUNCTION_TRACKER_H
#define DLL_FUNCTION_TRACKER_H

#include <deque>
#include <string>
#include <iostream>
#include <vector>
#include <fstream>

// Estrutura para armazenar informa��es sobre a fun��o chamada na DLL
struct DllFunctionInfo {
    int threadId;
    std::string dllName;     // Nome da DLL
    std::string functionName;// Nome da fun��o chamada
    unsigned long long address; // Endere�o da fun��o

    // Construtor para inicializar os dados
    DllFunctionInfo(int trdId, const std::string& dll, const std::string& func, unsigned long long addr)
        : threadId(trdId), dllName(dll), functionName(func), address(addr) {
    }
};

// Classe para rastrear fun��es chamadas em DLLs
class DllFunctionTracker {
private:
    std::deque<DllFunctionInfo> functionList; // Lista de fun��es chamadas
    size_t maxSize;                           // Tamanho m�ximo da lista

public:
    // Construtor para inicializar o rastreador com um tamanho m�ximo
    DllFunctionTracker(size_t maxListSize);

    // Adiciona uma nova fun��o chamada
    void addFunctionCall(int threadId, const std::string& dllName, const std::string& functionName, unsigned long long address);

    // Obt�m as �ltimas N fun��es chamadas
    std::vector<DllFunctionInfo> getLastNCalls(size_t n) const;

    // Imprime todas as fun��es chamadas
    void printAllCalls() const;

    void DllFunctionTracker::saveAllExternalCalls(std::ofstream& ExternalCallTraceOutFile);
    void DllFunctionTracker::saveLastExternalCall(std::ofstream& ExternalCallTraceOutFile);

    // Verifica se uma fun��o espec�fica foi chamada
    bool wasFunctionCalled(const std::string& dllName, const std::string& functionName) const;

    bool DllFunctionTracker::wasFunctionCalledInLastN(const std::string& dllName, const std::string& functionName, size_t n) const;
};

#endif // DLL_FUNCTION_TRACKER_H

// Example
//int main() {
//    DllFunctionTracker tracker(10); // M�ximo de 10 fun��es rastreadas
//
//    // Adiciona algumas fun��es chamadas
//    tracker.addFunctionCall("kernel32.dll", "CreateFileA", 0x7ff123456);
//    tracker.addFunctionCall("user32.dll", "MessageBoxA", 0x7ff123789);
//    tracker.addFunctionCall("ntdll.dll", "NtCreateThread", 0x7ff123abc);
//
//    // Imprime todas as fun��es chamadas
//    tracker.printAllCalls();
//
//    // Verifica se uma fun��o espec�fica foi chamada
//    if (tracker.wasFunctionCalled("kernel32.dll", "CreateFileA")) {
//        std::cout << "A fun��o CreateFileA foi chamada na DLL kernel32.dll\n";
//    }
//
//    // Obt�m as �ltimas 2 chamadas
//    auto lastCalls = tracker.getLastNCalls(2);
//    std::cout << "�ltimas 2 chamadas:\n";
//    for (const auto& call : lastCalls) {
//        std::cout << "DLL: " << call.dllName << ", Fun��o: " << call.functionName << "\n";
//    }
//
//    return 0;
//}