#include "InstNtSetInformationThread.h"

std::map<CallContextKey, CallContext*> InstNtSetInformationThread::callContextMap;
UINT32 InstNtSetInformationThread::imgCallId = 0;
UINT32 InstNtSetInformationThread::fcnCallId = 0;
Notifier* InstNtSetInformationThread::globalNotifierPtr;

VOID InstNtSetInformationThread::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT ThreadHandle, ADDRINT ThreadInformationClass, ADDRINT ThreadInformation, ADDRINT ThreadInformationLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    NtSetInformationThreadArgs args;
    args.ThreadHandle = ThreadHandle;
    args.ThreadInformationClass = ThreadInformationClass;
    args.ThreadInformation = ThreadInformation;
    args.ThreadInformationLength = ThreadInformationLength;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os parâmetros e o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] NtSetInformationThread..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        ThreadHandle: " << std::hex << ThreadHandle << std::dec << std::endl;
    stringStream << "        ThreadInformationClass: " << ThreadInformationClass << std::endl;
    stringStream << "        ThreadInformation: " << std::hex << ThreadInformation << std::dec << std::endl;
    stringStream << "        ThreadInformationLength: " << ThreadInformationLength << " bytes" << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada NtSetInformationThread" << std::endl;

}

VOID InstNtSetInformationThread::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal) {

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
        const NtSetInformationThreadArgs* args = reinterpret_cast<NtSetInformationThreadArgs*>(callContext->functionArgs);

        stringStream << "    Valor de retorno: " << std::hex << retVal << std::dec << std::endl;
        stringStream << "  [-] Chamada NtSetInformationThread concluída" << std::endl;
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

VOID InstNtSetInformationThread::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtSetInformationThread") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // ThreadHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // ThreadInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // ThreadInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // ThreadInformationLength
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
