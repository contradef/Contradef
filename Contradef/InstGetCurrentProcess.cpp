#include "InstGetCurrentProcess.h"

std::map<CallContextKey, CallContext*> InstGetCurrentProcess::callContextMap;
UINT32 InstGetCurrentProcess::imgCallId = 0;
UINT32 InstGetCurrentProcess::fcnCallId = 0;
Notifier* InstGetCurrentProcess::globalNotifierPtr;

VOID InstGetCurrentProcess::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, nullptr);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando a chamada
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] GetCurrentProcess..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da obtenção do handle do processo atual" << std::endl;

}

VOID InstGetCurrentProcess::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT retVal, ADDRINT returnAddress) {

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

        stringStream << "    Handle do processo atual: " << std::hex << retVal << std::dec << std::endl;
        stringStream << "  [-] Obtenção do handle do processo atual concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        callContextMap.erase(it);
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstGetCurrentProcess::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetCurrentProcess") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,          // Endereço da função chamante
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_FUNCRET_EXITPOINT_VALUE,  // Valor de retorno da função
            IARG_RETURN_IP,                // Endereço da função chamante
            IARG_END);

        RTN_Close(rtn);
    }
}
