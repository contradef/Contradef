#include "InstGetCommandLineA.h"

std::map<CallContextKey, CallContext*> InstGetCommandLineA::callContextMap;
UINT32 InstGetCommandLineA::imgCallId = 0;
UINT32 InstGetCommandLineA::fcnCallId = 0;
Notifier* InstGetCommandLineA::globalNotifierPtr;

VOID InstGetCommandLineA::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress) {

    // Verifica��o para instrumentar apenas o execut�vel principal, se aplic�vel
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    UINT32 callCtxId = callId * 100 + fcnCallId;
    auto* callContext = new CallContext(callCtxId, tid, instAddress, nullptr);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] GetCommandLineA..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endere�o da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Par�metros: (nenhum)" << std::endl;
    stringStream << "    Endere�o da fun��o chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] In�cio da chamada GetCommandLineA" << std::endl;

}

VOID InstGetCommandLineA::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retValAddr) {

    // Verifica��o para instrumentar apenas o execut�vel principal, se aplic�vel
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;

        // Valor de retorno � um LPSTR (char*), se n�o for NULL, podemos tentar ler a string
        char* cmdLine = reinterpret_cast<char*>(retValAddr);
        if (cmdLine != nullptr) {
            // Tenta ler a string at� um limite para evitar logs excessivos
            std::string cmdLineStr;
            cmdLineStr.resize(256);
            SIZE_T charsRead = PIN_SafeCopy(&cmdLineStr[0], cmdLine, 255);
            // Garante termina��o
            cmdLineStr[charsRead] = '\0';

            stringStream << "    Retorno GetCommandLineA: 0x" << std::hex << retValAddr << std::dec << " ("
                << cmdLineStr << ")" << std::endl;
        }
        else {
            stringStream << "    Retorno GetCommandLineA: NULL" << std::endl;
        }

        // N�o h� erro diretamente associado a esta fun��o, mas se desejado pode-se consultar GetLastError().
        // Se n�o houver sentido, apenas indica conclus�o.
        stringStream << "    Opera��o conclu�da." << std::endl;
        stringStream << "  [-] Chamada GetCommandLineA conclu�da" << std::endl;
        stringStream << "[*] Conclu�do" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        callContextMap.erase(it);
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstGetCommandLineA::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetCommandLineA") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // LPSTR GetCommandLineA(void);
        //
        // Retorna um LPSTR (char* para a linha de comando atual do processo).

        // Inser��o do CallbackBefore antes da chamada da fun��o
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_END);

        // Inser��o do CallbackAfter ap�s a chamada da fun��o
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,    // valor de retorno (LPSTR)
            IARG_END);

        RTN_Close(rtn);
    }
}
