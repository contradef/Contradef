#pragma once
#ifndef CALL_STACK_MANAGER_H
#define CALL_STACK_MANAGER_H

#include "pin.H"
#include <stack>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>

// Estrutura para armazenar informações de uma função na pilha de chamadas
struct FunctionInfo {
    unsigned long long address;           // Endereço da função
    unsigned long long returnAddress;     // Endereço de retorno da função
    unsigned long long stackReturnAddress;// Endereço de retorno na pilha
    std::string name;                     // Nome da função
    bool fromTailCall;                    // Indica se é de uma chamada otimizada (tail call)

    // Construtor para inicializar a estrutura
    FunctionInfo(unsigned long long addr, unsigned long long retAddr, unsigned long long stackRetAddr, bool fTailCall, const std::string& funcName)
        : address(addr), returnAddress(retAddr), stackReturnAddress(stackRetAddr), fromTailCall(fTailCall), name(funcName) {
    }
};

// Classe para gerenciar a pilha de chamadas
class CallStackManager {
private:
    std::stack<FunctionInfo> callStack; // Pilha para armazenar informações das funções

public:
    // Adiciona uma função à pilha
    void pushFunction(unsigned long long address, unsigned long long returnAddress, unsigned long long stackReturnAddress, bool fTailCall, const std::string& functionName);

    // Remove a função do topo da pilha
    void popFunction();

    // Exibe a função no topo da pilha
    void peekTopFunction() const;

    // Remove funções até encontrar o endereço de retorno especificado
    void popUntilAddress(unsigned long long targetAddress);

    // Verifica se a pilha está vazia
    bool isEmpty() const;

    // Retorna o tamanho atual da pilha
    size_t size() const;

    // Exibe todas as funções na pilha
    void printAllFunctions() const;

    // Exibe as últimas N funções da pilha
    void printLastNFunctions(size_t n) const;

    // Imprime a pilha de chamadas com formatação
    void PrintCallStack();

    // Verifica se uma função com o endereço de retorno especificado está na pilha
    bool fcnInCallStack(unsigned long long fcnRetAddr);
};

#endif // CALL_STACK_MANAGER_H
