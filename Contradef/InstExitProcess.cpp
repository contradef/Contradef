#include "InstExitProcess.h"

std::map<CallContextKey, CallContext*> InstExitProcess::callContextMap;
UINT32 InstExitProcess::imgCallId = 0;
UINT32 InstExitProcess::fcnCallId = 0;
Notifier* InstExitProcess::globalNotifierPtr;

VOID InstExitProcess::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT uExitCode) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ExitProcessArgs args;
    args.uExitCode = uExitCode;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Preparando a saída de informações relevantes para o ExitProcess
    std::stringstream stringStream;
    stringStream << std::endl << "[+] ExitProcess..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        uExitCode: " << args.uExitCode << std::endl;
    stringStream << "  [-] Processo sendo finalizado" << std::endl;
    stringStream << "[*] Concluído" << std::endl;
    
    ExecutionInformation executionCompletedInfo = { stringStream.str() };
    ExecutionEventData executionEvent(executionCompletedInfo);
    globalNotifierPtr->NotifyAll(&executionEvent);

    delete callContext;
    fcnCallId++;
}

VOID InstExitProcess::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "ExitProcess") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(CallbackBefore),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // uExitCode
            IARG_END);

        RTN_Close(rtn);
    }
}
