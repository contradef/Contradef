#include "InstRtlRemoveVectoredExceptionHandler.h"

std::map<CallContextKey, CallContext*> InstRtlRemoveVectoredExceptionHandler::callContextMap;
UINT32 InstRtlRemoveVectoredExceptionHandler::imgCallId = 0;
UINT32 InstRtlRemoveVectoredExceptionHandler::fcnCallId = 0;
Notifier* InstRtlRemoveVectoredExceptionHandler::globalNotifierPtr;

VOID InstRtlRemoveVectoredExceptionHandler::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT Handle) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    RtlRemoveVectoredExceptionHandlerArgs args;
    args.Handle = Handle;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] RtlRemoveVectoredExceptionHandler..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        Handle: 0x" << std::hex << Handle << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada RtlRemoveVectoredExceptionHandler" << std::endl;

}

VOID InstRtlRemoveVectoredExceptionHandler::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT Handle) {

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

        ULONG result = static_cast<ULONG>(retValAddr);
        stringStream << "    Retorno RtlRemoveVectoredExceptionHandler: " << result << std::endl;

        if (result != 0) {
            stringStream << "    Manipulador de exceção removido com sucesso." << std::endl;
        }
        else {
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao remover o manipulador de exceção. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada RtlRemoveVectoredExceptionHandler concluída" << std::endl;
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

VOID InstRtlRemoveVectoredExceptionHandler::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "RtlRemoveVectoredExceptionHandler") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // ULONG RtlRemoveVectoredExceptionHandler(PVOID Handle);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // Handle
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,     // valor de retorno (ULONG)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // Handle
            IARG_END);

        RTN_Close(rtn);
    }
}
