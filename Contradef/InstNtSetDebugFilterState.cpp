#include "InstNtSetDebugFilterState.h"

std::map<CallContextKey, CallContext*> InstNtSetDebugFilterState::callContextMap;
UINT32 InstNtSetDebugFilterState::imgCallId = 0;
UINT32 InstNtSetDebugFilterState::fcnCallId = 0;
Notifier* InstNtSetDebugFilterState::globalNotifierPtr;


VOID InstNtSetDebugFilterState::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT ComponentId, ADDRINT Level, ADDRINT State) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstNtSetDebugFilterStateArgs args;
    args.ComponentId = ComponentId;
    args.Level = Level;
    args.State = State;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstNtSetDebugFilterState::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT ComponentId, ADDRINT Level, ADDRINT State) {

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
        // Registrar Parámetros
        const InstNtSetDebugFilterStateArgs* args = reinterpret_cast<InstNtSetDebugFilterStateArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        ComponentId: " << args->ComponentId << std::endl;
        stringStream << "        Level: " << args->Level << std::endl;
        stringStream << "        State: " << args->State << std::endl;
        stringStream << "    Valor de retorno: " << *retValAddr << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

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

VOID InstNtSetDebugFilterState::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

   std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtSetDebugFilterState" || rtnName == "ZwSetDebugFilterState") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ComponentId
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Level
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // State
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ComponentId
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Level
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // State
            IARG_END);

        RTN_Close(rtn);
    }
}
