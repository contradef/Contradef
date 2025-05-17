#include "InstNtQuerySystemInformationEx.h"

std::map<CallContextKey, CallContext*> InstNtQuerySystemInformationEx::callContextMap;
UINT32 InstNtQuerySystemInformationEx::imgCallId = 0;
UINT32 InstNtQuerySystemInformationEx::fcnCallId = 0;
Notifier* InstNtQuerySystemInformationEx::globalNotifierPtr;

VOID InstNtQuerySystemInformationEx::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT SystemInformationClass, ADDRINT InputBuffer, ULONG InputBufferLength,
    ADDRINT SystemInformation, ULONG SystemInformationLength, ADDRINT ReturnLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    NtQuerySystemInformationExArgs args;
    args.SystemInformationClass = SystemInformationClass;
    args.InputBuffer = InputBuffer;
    args.InputBufferLength = InputBufferLength;
    args.SystemInformation = SystemInformation;
    args.SystemInformationLength = SystemInformationLength;
    args.ReturnLength = ReturnLength;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os parâmetros e o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;

    stringStream << std::endl << "[+] NtQuerySystemInformationEx..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        SystemInformationClass: " << SystemInformationClass << std::endl;
    stringStream << "        InputBuffer: " << std::hex << InputBuffer << std::dec << std::endl;
    stringStream << "        InputBufferLength: " << InputBufferLength << std::endl;
    stringStream << "        SystemInformation: " << std::hex << SystemInformation << std::dec << std::endl;
    stringStream << "        SystemInformationLength: " << SystemInformationLength << std::endl;
    stringStream << "        ReturnLength: " << std::hex << ReturnLength << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada NtQuerySystemInformationEx" << std::endl;

}

VOID InstNtQuerySystemInformationEx::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal) {

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

        stringStream << "    Valor de retorno: 0x" << std::hex << retVal << std::dec << std::endl;
        stringStream << "  [-] Chamada NtQuerySystemInformationEx concluída" << std::endl;
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

VOID InstNtQuerySystemInformationEx::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtQuerySystemInformationEx" || rtnName == "ZwQuerySystemInformationEx") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // SystemInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // InputBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // InputBufferLength
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // SystemInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,      // SystemInformationLength
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5,      // ReturnLength
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
