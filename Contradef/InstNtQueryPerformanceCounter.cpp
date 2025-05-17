#include "InstNtQueryPerformanceCounter.h"

std::map<CallContextKey, CallContext*> InstNtQueryPerformanceCounter::callContextMap;
UINT32 InstNtQueryPerformanceCounter::imgCallId = 0;
UINT32 InstNtQueryPerformanceCounter::fcnCallId = 0;
Notifier* InstNtQueryPerformanceCounter::globalNotifierPtr;

VOID InstNtQueryPerformanceCounter::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstNtQueryPerformanceCounterArgs args;
    args.PerformanceCounter = PerformanceCounter;
    args.PerformanceFrequency = PerformanceFrequency;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;
}

VOID InstNtQueryPerformanceCounter::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar fun��o
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        // Registrar par�metros
        const InstNtQueryPerformanceCounterArgs* args = reinterpret_cast<InstNtQueryPerformanceCounterArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do m�dulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endere�o da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Par�metros: " << std::endl;
        stringStream << "        PerformanceCounter: " << args->PerformanceCounter << std::endl;
        stringStream << "        PerformanceFrequency: " << args->PerformanceFrequency << std::endl;
        stringStream << "    Valor de retorno: " << *retValAddr << std::endl;
        stringStream << "[*] Conclu�do" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        // Cria evento
        ExecutionEventData executionEvent(executionCompletedInfo);
        // Notifica os observers
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstNtQueryPerformanceCounter::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {
    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtQueryPerformanceCounter" || rtnName == "ZwQueryPerformanceCounter") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endere�o da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // PerformanceCounter
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // PerformanceFrequency
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endere�o da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // PerformanceCounter
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // PerformanceFrequency
            IARG_END);

        RTN_Close(rtn);
    }
}