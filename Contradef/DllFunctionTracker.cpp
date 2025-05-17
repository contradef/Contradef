#include "DllFunctionTracker.h"

// Construtor: inicializa com o tamanho máximo da lista
DllFunctionTracker::DllFunctionTracker(size_t maxListSize)
    : maxSize(maxListSize) {
}

// Adiciona uma nova função chamada
void DllFunctionTracker::addFunctionCall(int threadId, const std::string& dllName, const std::string& functionName, unsigned long long address) {
    // Se a lista atingiu o tamanho máximo, remove o mais antigo
    if (functionList.size() >= maxSize) {
        functionList.pop_front();
    }

    // Adiciona a nova chamada à lista
    functionList.push_back(DllFunctionInfo(threadId, dllName, functionName, address));
}

// Obtém as últimas N funções chamadas
std::vector<DllFunctionInfo> DllFunctionTracker::getLastNCalls(size_t n) const {
    std::vector<DllFunctionInfo> result;
    size_t count = std::min(n, functionList.size());

    for (auto it = functionList.rbegin(); count > 0; ++it, --count) {
        result.push_back(*it);
    }
    return result;
}

// Imprime todas as funções chamadas
void DllFunctionTracker::printAllCalls() const {
    std::cout << "Funções chamadas em DLLs:\n";
    for (const auto& func : functionList) {
        std::cout << "DLL: " << func.dllName
            << ", Função: " << func.functionName
            << ", Endereço: 0x" << std::hex << func.address << std::dec << "\n";
    }
}

// Imprime todas as funções chamadas
void DllFunctionTracker::saveAllExternalCalls(std::ofstream& ExternalCallTraceOutFile) {

    if (!ExternalCallTraceOutFile.is_open()) {
        std::cerr << "Erro: Arquivo de saída não está aberto!\n";
        return;
    }

    for (const auto& func : functionList) {
        ExternalCallTraceOutFile << std::hex << func.address << std::dec << "   T[" << func.threadId << "]  " << func.dllName << ":" << func.functionName << std::endl;
    }
}

void DllFunctionTracker::saveLastExternalCall(std::ofstream& ExternalCallTraceOutFile) {

    if (!ExternalCallTraceOutFile.is_open()) {
        std::cerr << "Erro: Arquivo de saída não está aberto!\n";
        return;
    }

    const auto& func = functionList.back();
    ExternalCallTraceOutFile << std::hex << func.address << std::dec << "   T[" << func.threadId << "]  " << func.dllName << ":" << func.functionName << std::endl;
    ExternalCallTraceOutFile << std::flush;
}

// Verifica se uma função específica foi chamada
bool DllFunctionTracker::wasFunctionCalled(const std::string& dllName, const std::string& functionName) const {
    for (const auto& func : functionList) {
        if (func.dllName == dllName && func.functionName == functionName) {
            return true;
        }
    }
    return false;
}

// Verifica se uma função foi chamada nas últimas N chamadas
bool DllFunctionTracker::wasFunctionCalledInLastN(const std::string& dllName, const std::string& functionName, size_t n) const {
    size_t count = std::min(n, functionList.size());

    for (auto it = functionList.rbegin(); count > 0; ++it, --count) {
        if (it->dllName == dllName && it->functionName == functionName) {
            return true;
        }
    }
    return false;
}