#include "InstRtlAddVectoredExceptionHandler.h"

std::map<CallContextKey, CallContext*> InstRtlAddVectoredExceptionHandler::callContextMap;
UINT32 InstRtlAddVectoredExceptionHandler::imgCallId = 0;
UINT32 InstRtlAddVectoredExceptionHandler::fcnCallId = 0;
Notifier* InstRtlAddVectoredExceptionHandler::globalNotifierPtr;

VOID InstRtlAddVectoredExceptionHandler::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT First, ADDRINT Handler) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    RtlAddVectoredExceptionHandlerArgs args;
    args.First = First;
    args.Handler = Handler;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] RtlAddVectoredExceptionHandler..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        First: " << First << std::endl; // Exibe o valor numericamente
    stringStream << "        Handler: 0x" << std::hex << Handler << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada RtlAddVectoredExceptionHandler" << std::endl;

}

VOID InstRtlAddVectoredExceptionHandler::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT First, ADDRINT Handler) {

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

        PVOID result = reinterpret_cast<PVOID>(retValAddr);
        stringStream << "    Retorno RtlAddVectoredExceptionHandler: 0x" << std::hex << retValAddr << std::dec << std::endl;

        if (result != NULL) {
            stringStream << "    Manipulador de exceção adicionado com sucesso." << std::endl;
        }
        else {
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao adicionar o manipulador de exceção. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada RtlAddVectoredExceptionHandler concluída" << std::endl;
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

VOID InstRtlAddVectoredExceptionHandler::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "RtlAddVectoredExceptionHandler") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // PVOID RtlAddVectoredExceptionHandler(
        //   ULONG First,
        //   PVECTORED_EXCEPTION_HANDLER Handler
        // );

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // First
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Handler
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,     // valor de retorno (PVOID)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // First
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Handler
            IARG_END);

        RTN_Close(rtn);
    }
}
