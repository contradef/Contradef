#pragma once
#ifndef CALL_STACK_MANAGER_H
#define CALL_STACK_MANAGER_H

#include "pin.H"
#include <stack>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>

// Estrutura para armazenar informa��es de uma fun��o na pilha de chamadas
struct FunctionInfo {
    unsigned long long address;           // Endere�o da fun��o
    unsigned long long returnAddress;     // Endere�o de retorno da fun��o
    unsigned long long stackReturnAddress;// Endere�o de retorno na pilha
    std::string name;                     // Nome da fun��o
    bool fromTailCall;                    // Indica se � de uma chamada otimizada (tail call)

    // Construtor para inicializar a estrutura
    FunctionInfo(unsigned long long addr, unsigned long long retAddr, unsigned long long stackRetAddr, bool fTailCall, const std::string& funcName)
        : address(addr), returnAddress(retAddr), stackReturnAddress(stackRetAddr), fromTailCall(fTailCall), name(funcName) {
    }
};

// Classe para gerenciar a pilha de chamadas
class CallStackManager {
private:
    std::stack<FunctionInfo> callStack; // Pilha para armazenar informa��es das fun��es

public:
    // Adiciona uma fun��o � pilha
    void pushFunction(unsigned long long address, unsigned long long returnAddress, unsigned long long stackReturnAddress, bool fTailCall, const std::string& functionName);

    // Remove a fun��o do topo da pilha
    void popFunction();

    // Exibe a fun��o no topo da pilha
    void peekTopFunction() const;

    // Remove fun��es at� encontrar o endere�o de retorno especificado
    void popUntilAddress(unsigned long long targetAddress);

    // Verifica se a pilha est� vazia
    bool isEmpty() const;

    // Retorna o tamanho atual da pilha
    size_t size() const;

    // Exibe todas as fun��es na pilha
    void printAllFunctions() const;

    // Exibe as �ltimas N fun��es da pilha
    void printLastNFunctions(size_t n) const;

    // Imprime a pilha de chamadas com formata��o
    void PrintCallStack();

    // Verifica se uma fun��o com o endere�o de retorno especificado est� na pilha
    bool fcnInCallStack(unsigned long long fcnRetAddr);
};

#endif // CALL_STACK_MANAGER_H
