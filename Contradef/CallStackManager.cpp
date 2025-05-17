#include "CallStackManager.h"
#include <iomanip>

// Empilhar uma fun��o na pilha de chamadas
void CallStackManager::pushFunction(unsigned long long address, unsigned long long returnAddress, unsigned long long stackReturnAddress, bool fTailCall, const std::string& functionName) {
    callStack.push(FunctionInfo(address, returnAddress, stackReturnAddress, fTailCall, functionName));
    //std::cout << "Fun��o empilhada: " << functionName << " no endere�o: " << std::hex << address << std::dec << std::endl;
}

// Desempilhar a fun��o do topo da pilha
void CallStackManager::popFunction() {
    if (!callStack.empty()) {
        FunctionInfo topFunction = callStack.top();
        callStack.pop();
        //std::cout << "Fun��o desempilhada: " << topFunction.name << " no endere�o: " << std::hex << topFunction.address << std::dec << std::endl;
    }
    else {
        std::cerr << "Erro: Tentativa de desempilhar de uma pilha vazia.\n";
    }
}

// Exibe a fun��o no topo da pilha
void CallStackManager::peekTopFunction() const {
    if (!callStack.empty()) {
        const FunctionInfo& topFunction = callStack.top();
        std::cout << "Topo da pilha: Fun��o " << topFunction.name
            << " no endere�o: " << std::hex << topFunction.address
            << ", endere�o de retorno: " << topFunction.returnAddress << std::dec << std::endl;
    }
    else {
        std::cout << "A pilha est� vazia.\n";
    }
}

// Desempilha at� encontrar o endere�o de retorno especificado
//void CallStackManager::popUntilAddress(unsigned long long targetAddress) {
//    while (!callStack.empty()) {
//        const FunctionInfo& topFunction = callStack.top();
//
//        if (topFunction.returnAddress == targetAddress || topFunction.stackReturnAddress == targetAddress) {
//            std::cout << "Fun��o correspondente encontrada: " << topFunction.name
//                << " no endere�o de retorno: " << std::hex << targetAddress << std::dec << std::endl;
//            callStack.pop();
//            return;
//        }
//
//        std::cout << "Desempilhando fun��o: " << topFunction.name
//            << " no endere�o: " << std::hex << topFunction.address << std::dec << std::endl;
//        callStack.pop();
//    }
//    std::cerr << "Aviso: Endere�o de retorno n�o encontrado na pilha.\n";
//}

// Desempilhar at� um endere�o espec�fico
void CallStackManager::popUntilAddress(unsigned long long targetAddress) {
    while (!callStack.empty()) {
        FunctionInfo topFunction = callStack.top();

        // Verifica se o endere�o corresponde ao alvo
        if (topFunction.returnAddress == targetAddress || topFunction.stackReturnAddress == targetAddress) {
            callStack.pop();
            return;
        }

        PIN_LockClient();
        RTN targetRtn = RTN_FindByAddress(targetAddress);
        if (RTN_Valid(targetRtn)) {
            RTN stackRTN = RTN_FindByAddress(topFunction.address);
            if (RTN_Valid(stackRTN)) {
                if (RTN_Address(stackRTN) == RTN_Address(targetRtn)) {
                    callStack.pop();
                    PIN_UnlockClient();
                    return;
                }
            }
            //std::cout << "[ROP] retorno de fun��o (" << std::hex << topFunction.fromTailCall << ") n�o empilhada. Nome da fucao de retorno: " << RTN_Name(targetRtn) << ", endereco: " << targetAddress << ". Nome da funcao esperada: " << topFunction.name << " (" << topFunction.returnAddress << ") (" << topFunction.stackReturnAddress << ")" << std::dec << std::endl;
            //std::cout << "Retorno incorreto para o endereco: " << std::hex << targetAddress << std::dec << ", Funcao: " << RTN_Name(targetRtn) << std::endl;
        }
        else {
            //std::cout << "[ROP] Funcao nao e valida. Retorno incorreto para o endereco: " << std::hex << targetAddress << std::dec << std::endl;
        }
        PIN_UnlockClient();
        if (!fcnInCallStack(targetAddress)) {
            std::cout << "Funcao nao esta na pilha\n";
            return; // Encerra a fun��o sem desempilhar o elemento
        }
        callStack.pop();
    }
}


// Verifica se a pilha est� vazia
bool CallStackManager::isEmpty() const {
    return callStack.empty();
}

// Retorna o tamanho da pilha
size_t CallStackManager::size() const {
    return callStack.size();
}

// Imprime todas as fun��es na pilha
void CallStackManager::printAllFunctions() const {
    std::stack<FunctionInfo> tempStack = callStack; // C�pia tempor�ria da pilha
    std::cout << "Fun��es na pilha (de topo para base):\n";
    while (!tempStack.empty()) {
        const FunctionInfo& func = tempStack.top();
        std::cout << "  Fun��o: " << func.name << " no endere�o: " << std::hex << func.address
            << ", endere�o de retorno: " << func.returnAddress << std::dec << std::endl;
        tempStack.pop();
    }
}

// Imprime as �ltimas N fun��es na pilha
void CallStackManager::printLastNFunctions(size_t n) const {
    if (n > callStack.size()) {
        std::cout << "A pilha cont�m menos de " << n << " fun��es. Exibindo todas:\n";
        printAllFunctions();
        return;
    }

    std::vector<FunctionInfo> tempVector;
    std::stack<FunctionInfo> tempStack = callStack;

    while (!tempStack.empty()) {
        tempVector.push_back(tempStack.top());
        tempStack.pop();
    }

    std::cout << "�ltimas " << n << " fun��es na pilha:\n";
    for (size_t i = tempVector.size() - n; i < tempVector.size(); ++i) {
        const FunctionInfo& func = tempVector[i];
        std::cout << "  Fun��o: " << func.name << " no endere�o: " << std::hex << func.address
            << ", endere�o de retorno: " << func.returnAddress << std::dec << std::endl;
    }
}

// Imprime toda a pilha de chamadas
void CallStackManager::PrintCallStack() {
    std::stack<FunctionInfo> tempStack = callStack; // C�pia tempor�ria
    size_t depth = tempStack.size();

    std::cout << "Pilha de chamadas (de topo para base):\n";
    while (!tempStack.empty()) {
        const FunctionInfo& funcInfo = tempStack.top();
        std::cout << std::setw((depth - tempStack.size() + 1) * 4) << "" // Indenta��o
            << "Fun��o: " << funcInfo.name << ", Endere�o: " << std::hex << funcInfo.address
            << ", Retorno: " << funcInfo.returnAddress << std::dec << std::endl;
        tempStack.pop();
    }
}

// Verifica se uma fun��o com o endere�o de retorno especificado est� na pilha
bool CallStackManager::fcnInCallStack(unsigned long long fcnRetAddr) {
    std::stack<FunctionInfo> tempStack = callStack; // C�pia tempor�ria
    while (!tempStack.empty()) {
        const FunctionInfo& funcInfo = tempStack.top();
        tempStack.pop();
        if (funcInfo.returnAddress == fcnRetAddr || funcInfo.stackReturnAddress == fcnRetAddr) {
            return true;
        }
    }
    return false;
}
