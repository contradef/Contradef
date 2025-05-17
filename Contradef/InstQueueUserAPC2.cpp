#include "InstQueueUserAPC2.h"

std::map<CallContextKey, CallContext*> InstQueueUserAPC2::callContextMap;
UINT32 InstQueueUserAPC2::imgCallId = 0;
UINT32 InstQueueUserAPC2::fcnCallId = 0;
Notifier* InstQueueUserAPC2::globalNotifierPtr;

VOID InstQueueUserAPC2::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT pfnAPC, ADDRINT hThread, ADDRINT dwData) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    QueueUserAPC2Args args;
    args.pfnAPC = pfnAPC;
    args.hThread = hThread;
    args.dwData = dwData;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] QueueUserAPC2..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        pfnAPC: 0x" << std::hex << pfnAPC << std::dec << std::endl;
    stringStream << "        hThread: 0x" << std::hex << hThread << std::dec << std::endl;
    stringStream << "        dwData: " << dwData << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada QueueUserAPC2" << std::endl;

}

VOID InstQueueUserAPC2::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT pfnAPC, ADDRINT hThread, ADDRINT dwData) {

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

        BOOL result = static_cast<BOOL>(retValAddr);
        stringStream << "    Retorno QueueUserAPC2: " << result << std::endl;

        if (result != 0) {
            stringStream << "    APC enfileirada com sucesso." << std::endl;
        }
        else {
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao enfileirar APC. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada QueueUserAPC2 concluída" << std::endl;
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

VOID InstQueueUserAPC2::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "QueueUserAPC2") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura de QueueUserAPC2 (assumida):
        // BOOL QueueUserAPC2(
        //   PAPCFUNC pfnAPC,
        //   HANDLE hThread,
        //   ULONG_PTR dwData
        // );

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // pfnAPC
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // hThread
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwData
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,     // valor de retorno (BOOL)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // pfnAPC
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // hThread
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwData
            IARG_END);

        RTN_Close(rtn);
    }
}
