#include "InstWaitForSingleObject.h"


std::map<CallContextKey, CallContext*> InstWaitForSingleObject::callContextMap;
UINT32 InstWaitForSingleObject::imgCallId = 0;
UINT32 InstWaitForSingleObject::fcnCallId = 0;
Notifier* InstWaitForSingleObject::globalNotifierPtr;

VOID InstWaitForSingleObject::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hHandle, ADDRINT dwMilliseconds) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    WaitForSingleObjectArgs args;
    args.hHandle = hHandle;
    args.dwMilliseconds = dwMilliseconds;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;
    // Registrando os parâmetros e o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] WaitForSingleObject..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        hHandle: " << std::hex << hHandle << std::dec << std::endl;
    stringStream << "        dwMilliseconds: ";
    if (dwMilliseconds == INFINITE) {
        stringStream << "INFINITE";
    }
    else {
        stringStream << dwMilliseconds << " ms";
    }
    stringStream << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "[*] Concluído (AGUARDANDO RETORNO)" << std::endl << std::endl;

    ExecutionInformation executionCompletedInfo = { stringStream.str() };
    ExecutionEventData executionEvent(executionCompletedInfo);
    globalNotifierPtr->NotifyAll(&executionEvent);
}

VOID InstWaitForSingleObject::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal) {
    if (instrumentOnlyMain && !IsMainExecutable(ADDRINT(returnAddress))) {
        return;
    }
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;
        stringStream << std::endl << "[+] [RETORNO] WaitForSingleObject..." << std::endl;
        stringStream << "    Valor de retorno: ";
        switch (retVal) {
        case WAIT_OBJECT_0:
            stringStream << "WAIT_OBJECT_0";
            break;
        case WAIT_TIMEOUT:
            stringStream << "WAIT_TIMEOUT";
            break;
        case WAIT_FAILED:
            stringStream << "WAIT_FAILED";
            break;
        case WAIT_ABANDONED:
            stringStream << "WAIT_ABANDONED";
            break;
        default:
            stringStream << std::hex << retVal << std::dec;
        }
        stringStream << std::endl;
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

VOID InstWaitForSingleObject::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "WaitForSingleObject") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // hHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // dwMilliseconds
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCRET_EXITPOINT_VALUE,          // Valor de retorno
            IARG_END);

        RTN_Close(rtn);
    }
}
