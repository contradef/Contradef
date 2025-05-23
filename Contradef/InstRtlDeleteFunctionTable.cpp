#include "InstRtlDeleteFunctionTable.h"

std::map<CallContextKey, CallContext*> InstRtlDeleteFunctionTable::callContextMap;
UINT32 InstRtlDeleteFunctionTable::imgCallId = 0;
UINT32 InstRtlDeleteFunctionTable::fcnCallId = 0;
Notifier* InstRtlDeleteFunctionTable::globalNotifierPtr;

VOID InstRtlDeleteFunctionTable::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT FunctionTable) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    RtlDeleteFunctionTableArgs args;
    args.FunctionTable = FunctionTable;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os par�metros e o endere�o da fun��o chamante
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] RtlDeleteFunctionTable..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endere�o da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Par�metros: " << std::endl;
    stringStream << "        FunctionTable: " << std::hex << FunctionTable << std::dec << std::endl;
    stringStream << "    Endere�o da fun��o chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] In�cio da chamada RtlDeleteFunctionTable" << std::endl;

}

VOID InstRtlDeleteFunctionTable::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal) {

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

        if (retVal != 0) {
            stringStream << "    Tabela de fun��es deletada com sucesso." << std::endl;
        }
        else {
            stringStream << "    Falha ao deletar a tabela de fun��es." << std::endl;
        }
        stringStream << "  [-] Chamada RtlDeleteFunctionTable conclu�da" << std::endl;
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

VOID InstRtlDeleteFunctionTable::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "RtlDeleteFunctionTable") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endere�o da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // FunctionTable
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endere�o da fun��o chamante
            IARG_FUNCRET_EXITPOINT_VALUE,          // Valor de retorno
            IARG_END);

        RTN_Close(rtn);
    }
}
