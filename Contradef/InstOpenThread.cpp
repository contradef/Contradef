#include "InstOpenThread.h"

std::map<CallContextKey, CallContext*> InstOpenThread::callContextMap;
UINT32 InstOpenThread::imgCallId = 0;
UINT32 InstOpenThread::fcnCallId = 0;
Notifier* InstOpenThread::globalNotifierPtr;

VOID InstOpenThread::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT dwDesiredAccess, ADDRINT bInheritHandle, ADDRINT dwThreadId) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    OpenThreadArgs args;
    args.dwDesiredAccess = dwDesiredAccess;
    args.bInheritHandle = bInheritHandle;
    args.dwThreadId = dwThreadId;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os parâmetros e o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] OpenThread..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        dwDesiredAccess: " << dwDesiredAccess << std::endl;
    stringStream << "        bInheritHandle: " << bInheritHandle << std::endl;
    stringStream << "        dwThreadId: " << dwThreadId << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada OpenThread" << std::endl;

}

VOID InstOpenThread::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal) {

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

        stringStream << "    Valor de retorno (Handle da Thread): " << std::hex << retVal << std::dec << std::endl;
        stringStream << "  [-] Chamada OpenThread concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        callContextMap.erase(it);
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstOpenThread::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "OpenThread") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // dwDesiredAccess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // bInheritHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // dwThreadId
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCRET_EXITPOINT_VALUE,          // Valor de retorno (HANDLE)
            IARG_END);

        RTN_Close(rtn);
    }
}
