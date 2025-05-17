#include "InstRtlInstallFunctionTableCallback.h"

std::map<CallContextKey, CallContext*> InstRtlInstallFunctionTableCallback::callContextMap;
UINT32 InstRtlInstallFunctionTableCallback::imgCallId = 0;
UINT32 InstRtlInstallFunctionTableCallback::fcnCallId = 0;
Notifier* InstRtlInstallFunctionTableCallback::globalNotifierPtr;

VOID InstRtlInstallFunctionTableCallback::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT TableIdentifier, ADDRINT BaseAddress, ADDRINT Length, ADDRINT Callback, ADDRINT Context, ADDRINT OutOfProcessCallback) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    RtlInstallFunctionTableCallbackArgs args;
    args.TableIdentifier = TableIdentifier;
    args.BaseAddress = BaseAddress;
    args.Length = Length;
    args.Callback = Callback;
    args.Context = Context;
    args.OutOfProcessCallback = OutOfProcessCallback;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os parâmetros e o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] RtlInstallFunctionTableCallback..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        TableIdentifier: " << std::hex << TableIdentifier << std::dec << std::endl;
    stringStream << "        BaseAddress: " << std::hex << BaseAddress << std::dec << std::endl;
    stringStream << "        Length: " << Length << std::endl;
    stringStream << "        Callback: " << std::hex << Callback << std::dec << std::endl;
    stringStream << "        Context: " << std::hex << Context << std::dec << std::endl;
    stringStream << "        OutOfProcessCallback: " << std::hex << OutOfProcessCallback << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada RtlInstallFunctionTableCallback" << std::endl;

}

VOID InstRtlInstallFunctionTableCallback::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal) {

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

        stringStream << "    Valor de retorno: " << std::hex << retVal << std::dec << std::endl;
        stringStream << "  [-] Chamada RtlInstallFunctionTableCallback concluída" << std::endl;
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

VOID InstRtlInstallFunctionTableCallback::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "RtlInstallFunctionTableCallback") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // TableIdentifier
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // BaseAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // Length
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // Callback
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,      // Context
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5,      // OutOfProcessCallback
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
